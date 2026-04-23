use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use base64::prelude::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::crypto::{EncryptedPayload, TunnelCipher};

pub const FRAME_VERSION: u8 = 1;
const BATCH_MAGIC: &[u8; 4] = b"GTB1";
const BATCH_HEADER_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    ClientToExit,
    ExitToClient,
}

impl Direction {
    pub fn as_path(self) -> &'static str {
        match self {
            Self::ClientToExit => "c2e",
            Self::ExitToClient => "e2c",
        }
    }

    pub fn opposite(self) -> Self {
        match self {
            Self::ClientToExit => Self::ExitToClient,
            Self::ExitToClient => Self::ClientToExit,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FrameFlag {
    Open,
    Data,
    HalfClose,
    Close,
    Reset,
    Ack,
    Control,
}

impl FrameFlag {
    pub fn as_path(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Data => "data",
            Self::HalfClose => "half-close",
            Self::Close => "close",
            Self::Reset => "reset",
            Self::Ack => "ack",
            Self::Control => "control",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameHeader {
    pub version: u8,
    pub session_id: String,
    pub stream_id: u64,
    pub direction: Direction,
    pub seq: u64,
    pub ack: u64,
    pub flag: FrameFlag,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub header: FrameHeader,
    pub payload: FramePayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FramePayload {
    Open {
        host: String,
        port: u16,
    },
    Data {
        data_b64: String,
    },
    HalfClose,
    Close,
    Reset {
        reason: String,
    },
    Ack {
        acked_direction: Direction,
        ack: u64,
    },
    Control(ControlPayload),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ControlPayload {
    SessionHello {
        version: u8,
    },
    StreamOpen {
        sid: u64,
        #[serde(default)]
        lease_id: u64,
        host: String,
        port: u16,
    },
    StreamClose {
        sid: u64,
        #[serde(default)]
        lease_id: u64,
        final_seq_c2e: u64,
        final_seq_e2c: u64,
    },
    StreamReset {
        sid: u64,
        #[serde(default)]
        lease_id: u64,
        reason: String,
    },
    SessionBye {
        reason: String,
    },
}

impl FramePayload {
    pub fn data(bytes: &[u8]) -> Self {
        Self::Data {
            data_b64: BASE64_STANDARD.encode(bytes),
        }
    }

    pub fn data_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::Data { data_b64 } => BASE64_STANDARD
                .decode(data_b64)
                .context("failed to decode data payload"),
            _ => bail!("payload is not data"),
        }
    }

    pub fn flag(&self) -> FrameFlag {
        match self {
            Self::Open { .. } => FrameFlag::Open,
            Self::Data { .. } => FrameFlag::Data,
            Self::HalfClose => FrameFlag::HalfClose,
            Self::Close => FrameFlag::Close,
            Self::Reset { .. } => FrameFlag::Reset,
            Self::Ack { .. } => FrameFlag::Ack,
            Self::Control(_) => FrameFlag::Control,
        }
    }
}

impl Serialize for FramePayload {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;

        let len = match self {
            Self::Open { .. } | Self::Ack { .. } => 3,
            Self::Data { .. } | Self::Reset { .. } | Self::Control(_) => 2,
            Self::HalfClose | Self::Close => 1,
        };
        let mut map = serializer.serialize_map(Some(len))?;
        map.serialize_entry("type", self.flag().as_path())?;
        match self {
            Self::Open { host, port } => {
                map.serialize_entry("host", host)?;
                map.serialize_entry("port", port)?;
            }
            Self::Data { data_b64 } => {
                map.serialize_entry("data_b64", data_b64)?;
            }
            Self::HalfClose | Self::Close => {}
            Self::Reset { reason } => {
                map.serialize_entry("reason", reason)?;
            }
            Self::Ack {
                acked_direction,
                ack,
            } => {
                map.serialize_entry("acked_direction", acked_direction)?;
                map.serialize_entry("ack", ack)?;
            }
            Self::Control(payload) => {
                map.serialize_entry("payload", payload)?;
            }
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for FramePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error as _;

        let value = serde_json::Value::deserialize(deserializer)?;
        let object = value
            .as_object()
            .ok_or_else(|| D::Error::custom("frame payload must be an object"))?;
        let payload_type = object
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| D::Error::custom("frame payload missing type"))?;

        match payload_type {
            "open" => Ok(Self::Open {
                host: json_string::<D::Error>(object, "host")?,
                port: json_u16::<D::Error>(object, "port")?,
            }),
            "data" => Ok(Self::Data {
                data_b64: json_string::<D::Error>(object, "data_b64")?,
            }),
            "half-close" => Ok(Self::HalfClose),
            "close" => Ok(Self::Close),
            "reset" => Ok(Self::Reset {
                reason: json_string::<D::Error>(object, "reason")?,
            }),
            "ack" => {
                let acked_direction = serde_json::from_value(
                    json_value::<D::Error>(object, "acked_direction")?.clone(),
                )
                .map_err(D::Error::custom)?;
                Ok(Self::Ack {
                    acked_direction,
                    ack: json_u64::<D::Error>(object, "ack")?,
                })
            }
            "control" => {
                let payload =
                    serde_json::from_value(json_value::<D::Error>(object, "payload")?.clone())
                        .map_err(D::Error::custom)?;
                Ok(Self::Control(payload))
            }
            other => Err(D::Error::custom(format!(
                "unknown frame payload type {other}"
            ))),
        }
    }
}

fn json_value<'a, E>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> std::result::Result<&'a serde_json::Value, E>
where
    E: serde::de::Error,
{
    object
        .get(key)
        .ok_or_else(|| E::custom(format!("frame payload missing {key}")))
}

fn json_string<E>(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> std::result::Result<String, E>
where
    E: serde::de::Error,
{
    json_value::<E>(object, key)?
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| E::custom(format!("frame payload {key} must be a string")))
}

fn json_u64<E>(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> std::result::Result<u64, E>
where
    E: serde::de::Error,
{
    json_value::<E>(object, key)?
        .as_u64()
        .ok_or_else(|| E::custom(format!("frame payload {key} must be an integer")))
}

fn json_u16<E>(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> std::result::Result<u16, E>
where
    E: serde::de::Error,
{
    let value = json_u64::<E>(object, key)?;
    u16::try_from(value).map_err(|_| E::custom(format!("frame payload {key} is out of u16 range")))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameEnvelope {
    pub header: FrameHeader,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

impl Frame {
    pub fn new(
        session_id: impl Into<String>,
        stream_id: u64,
        direction: Direction,
        seq: u64,
        ack: u64,
        payload: FramePayload,
    ) -> Self {
        Self {
            header: FrameHeader {
                version: FRAME_VERSION,
                session_id: session_id.into(),
                stream_id,
                direction,
                seq,
                ack,
                flag: payload.flag(),
                timestamp_ms: now_ms(),
            },
            payload,
        }
    }

    pub fn encode(&self, cipher: &TunnelCipher) -> Result<Vec<u8>> {
        FrameBatch::encode(std::slice::from_ref(self), cipher)
    }

    pub fn decode(cipher: &TunnelCipher, bytes: &[u8]) -> Result<Self> {
        let frames = FrameBatch::decode(cipher, bytes)?;
        if frames.len() != 1 {
            bail!("expected one frame, decoded {}", frames.len());
        }
        Ok(frames.into_iter().next().expect("checked frame count"))
    }

    pub fn relative_path(&self) -> PathBuf {
        FrameBatch::relative_path(std::slice::from_ref(self))
            .expect("single frame batch path should be valid")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchHeader {
    pub session_id: String,
    pub direction: Direction,
    pub first_seq: u64,
    pub last_seq: u64,
    pub ack_watermark: u64,
    pub timestamp_ms: u64,
    pub frame_count: u32,
}

pub struct FrameBatch;

impl FrameBatch {
    pub fn encode(frames: &[Frame], cipher: &TunnelCipher) -> Result<Vec<u8>> {
        let header = validate_batch(frames)?;
        let aad = encode_batch_header(&header)?;
        let plaintext = encode_batch_plaintext(frames)?;
        let encrypted = cipher.encrypt(&aad, &plaintext)?;

        let mut encoded = aad;
        encoded.extend_from_slice(&encrypted.nonce);
        put_u32(&mut encoded, encrypted.ciphertext.len() as u32);
        encoded.extend_from_slice(&encrypted.ciphertext);
        Ok(encoded)
    }

    pub fn decode(cipher: &TunnelCipher, bytes: &[u8]) -> Result<Vec<Frame>> {
        if bytes.starts_with(BATCH_MAGIC) {
            return decode_binary_batch(cipher, bytes);
        }
        decode_legacy_json_frame(cipher, bytes).map(|frame| vec![frame])
    }

    pub fn relative_path(frames: &[Frame]) -> Result<PathBuf> {
        let header = validate_batch(frames)?;
        let stream = frames[0].header.stream_id;
        let stream_component = if frames.iter().all(|frame| frame.header.stream_id == stream) {
            format!("{stream:016x}")
        } else {
            "mixed".to_string()
        };

        Ok(PathBuf::from("frames")
            .join(header.direction.as_path())
            .join(safe_component(&header.session_id))
            .join(stream_component)
            .join(format!(
                "{:020}-{:020}-{:04}.gtb",
                header.first_seq, header.last_seq, header.frame_count
            )))
    }

    pub fn payload_bytes(frames: &[Frame]) -> Result<usize> {
        frames.iter().try_fold(0usize, |total, frame| {
            let bytes = match &frame.payload {
                FramePayload::Data { .. } => frame.payload.data_bytes()?.len(),
                FramePayload::Open { host, .. } => host.len() + 2,
                FramePayload::Reset { reason } => reason.len(),
                FramePayload::Ack { .. } => 9,
                FramePayload::Control(payload) => serde_json::to_vec(payload)
                    .context("failed to encode control payload")?
                    .len(),
                FramePayload::HalfClose | FramePayload::Close => 0,
            };
            Ok(total + bytes)
        })
    }
}

fn validate_batch(frames: &[Frame]) -> Result<BatchHeader> {
    let first = frames
        .first()
        .ok_or_else(|| anyhow::anyhow!("frame batch must not be empty"))?;
    let mut first_seq = u64::MAX;
    let mut last_seq = 0u64;
    let mut ack_watermark = 0u64;

    for frame in frames {
        if frame.header.version != FRAME_VERSION {
            bail!("unsupported frame version {}", frame.header.version);
        }
        if frame.header.flag != frame.payload.flag() {
            bail!("frame flag does not match payload");
        }
        if frame.header.session_id != first.header.session_id {
            bail!("frame batch cannot mix sessions");
        }
        if frame.header.direction != first.header.direction {
            bail!("frame batch cannot mix directions");
        }
        first_seq = first_seq.min(frame.header.seq);
        last_seq = last_seq.max(frame.header.seq);
        ack_watermark = ack_watermark.max(frame.header.ack);
        if let FramePayload::Ack { ack, .. } = &frame.payload {
            ack_watermark = ack_watermark.max(*ack);
        }
    }

    Ok(BatchHeader {
        session_id: first.header.session_id.clone(),
        direction: first.header.direction,
        first_seq,
        last_seq,
        ack_watermark,
        timestamp_ms: now_ms(),
        frame_count: frames.len() as u32,
    })
}

fn encode_batch_header(header: &BatchHeader) -> Result<Vec<u8>> {
    let session = header.session_id.as_bytes();
    if session.len() > u16::MAX as usize {
        bail!("session id is too long");
    }
    let mut out = Vec::with_capacity(64 + session.len());
    out.extend_from_slice(BATCH_MAGIC);
    put_u8(&mut out, BATCH_HEADER_VERSION);
    put_u8(&mut out, direction_to_u8(header.direction));
    put_u16(&mut out, session.len() as u16);
    out.extend_from_slice(session);
    put_u64(&mut out, header.first_seq);
    put_u64(&mut out, header.last_seq);
    put_u64(&mut out, header.ack_watermark);
    put_u64(&mut out, header.timestamp_ms);
    put_u32(&mut out, header.frame_count);
    Ok(out)
}

fn encode_batch_plaintext(frames: &[Frame]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for frame in frames {
        put_u64(&mut out, frame.header.stream_id);
        put_u64(&mut out, frame.header.seq);
        put_u64(&mut out, frame.header.ack);
        put_u8(&mut out, flag_to_u8(frame.header.flag));
        put_u64(&mut out, frame.header.timestamp_ms);
        encode_payload(&mut out, &frame.payload)?;
    }
    Ok(out)
}

fn encode_payload(out: &mut Vec<u8>, payload: &FramePayload) -> Result<()> {
    match payload {
        FramePayload::Open { host, port } => {
            let host = host.as_bytes();
            if host.len() > u16::MAX as usize {
                bail!("open host is too long");
            }
            put_u16(out, host.len() as u16);
            out.extend_from_slice(host);
            put_u16(out, *port);
        }
        FramePayload::Data { .. } => {
            let data = payload.data_bytes()?;
            if data.len() > u32::MAX as usize {
                bail!("data frame is too large");
            }
            put_u32(out, data.len() as u32);
            out.extend_from_slice(&data);
        }
        FramePayload::HalfClose | FramePayload::Close => {}
        FramePayload::Reset { reason } => {
            let reason = reason.as_bytes();
            if reason.len() > u16::MAX as usize {
                bail!("reset reason is too long");
            }
            put_u16(out, reason.len() as u16);
            out.extend_from_slice(reason);
        }
        FramePayload::Ack {
            acked_direction,
            ack,
        } => {
            put_u8(out, direction_to_u8(*acked_direction));
            put_u64(out, *ack);
        }
        FramePayload::Control(payload) => {
            let encoded =
                serde_json::to_vec(payload).context("failed to encode control payload")?;
            if encoded.len() > u32::MAX as usize {
                bail!("control payload is too large");
            }
            put_u32(out, encoded.len() as u32);
            out.extend_from_slice(&encoded);
        }
    }
    Ok(())
}

fn decode_binary_batch(cipher: &TunnelCipher, bytes: &[u8]) -> Result<Vec<Frame>> {
    let mut cursor = Cursor::new(bytes);
    cursor.expect_magic(BATCH_MAGIC)?;
    let version = cursor.take_u8()?;
    if version != BATCH_HEADER_VERSION {
        bail!("unsupported batch version {}", version);
    }
    let direction = u8_to_direction(cursor.take_u8()?)?;
    let session_len = cursor.take_u16()? as usize;
    let session_id = String::from_utf8(cursor.take_bytes(session_len)?.to_vec())
        .context("batch session id is not utf-8")?;
    let first_seq = cursor.take_u64()?;
    let last_seq = cursor.take_u64()?;
    let ack_watermark = cursor.take_u64()?;
    let timestamp_ms = cursor.take_u64()?;
    let frame_count = cursor.take_u32()?;
    let aad_end = cursor.position();

    let nonce: [u8; 24] = cursor
        .take_bytes(24)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("batch nonce must be 24 bytes"))?;
    let ciphertext_len = cursor.take_u32()? as usize;
    let ciphertext = cursor.take_bytes(ciphertext_len)?.to_vec();
    if cursor.remaining() != 0 {
        bail!("batch has trailing bytes");
    }

    let plaintext = cipher.decrypt(&bytes[..aad_end], &EncryptedPayload { nonce, ciphertext })?;
    let header = BatchHeader {
        session_id,
        direction,
        first_seq,
        last_seq,
        ack_watermark,
        timestamp_ms,
        frame_count,
    };
    decode_batch_plaintext(&header, &plaintext)
}

fn decode_batch_plaintext(header: &BatchHeader, plaintext: &[u8]) -> Result<Vec<Frame>> {
    let mut cursor = Cursor::new(plaintext);
    let mut frames = Vec::with_capacity(header.frame_count as usize);
    for _ in 0..header.frame_count {
        let stream_id = cursor.take_u64()?;
        let seq = cursor.take_u64()?;
        let ack = cursor.take_u64()?;
        let flag = u8_to_flag(cursor.take_u8()?)?;
        let timestamp_ms = cursor.take_u64()?;
        let payload = decode_payload(&mut cursor, flag)?;
        frames.push(Frame {
            header: FrameHeader {
                version: FRAME_VERSION,
                session_id: header.session_id.clone(),
                stream_id,
                direction: header.direction,
                seq,
                ack,
                flag,
                timestamp_ms,
            },
            payload,
        });
    }
    if cursor.remaining() != 0 {
        bail!("batch plaintext has trailing bytes");
    }
    Ok(frames)
}

fn decode_payload(cursor: &mut Cursor<'_>, flag: FrameFlag) -> Result<FramePayload> {
    match flag {
        FrameFlag::Open => {
            let host_len = cursor.take_u16()? as usize;
            let host = String::from_utf8(cursor.take_bytes(host_len)?.to_vec())
                .context("open host is not utf-8")?;
            let port = cursor.take_u16()?;
            Ok(FramePayload::Open { host, port })
        }
        FrameFlag::Data => {
            let len = cursor.take_u32()? as usize;
            Ok(FramePayload::data(cursor.take_bytes(len)?))
        }
        FrameFlag::HalfClose => Ok(FramePayload::HalfClose),
        FrameFlag::Close => Ok(FramePayload::Close),
        FrameFlag::Reset => {
            let len = cursor.take_u16()? as usize;
            let reason = String::from_utf8(cursor.take_bytes(len)?.to_vec())
                .context("reset reason is not utf-8")?;
            Ok(FramePayload::Reset { reason })
        }
        FrameFlag::Ack => {
            let acked_direction = u8_to_direction(cursor.take_u8()?)?;
            let ack = cursor.take_u64()?;
            Ok(FramePayload::Ack {
                acked_direction,
                ack,
            })
        }
        FrameFlag::Control => {
            let len = cursor.take_u32()? as usize;
            let payload = serde_json::from_slice(cursor.take_bytes(len)?)
                .context("failed to decode control payload")?;
            Ok(FramePayload::Control(payload))
        }
    }
}

fn decode_legacy_json_frame(cipher: &TunnelCipher, bytes: &[u8]) -> Result<Frame> {
    let envelope: FrameEnvelope =
        serde_json::from_slice(bytes).context("failed to decode frame envelope")?;
    if envelope.header.version != FRAME_VERSION {
        bail!("unsupported frame version {}", envelope.header.version);
    }
    let nonce_vec = BASE64_STANDARD
        .decode(envelope.nonce_b64)
        .context("failed to decode frame nonce")?;
    let nonce: [u8; 24] = nonce_vec
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("frame nonce must be 24 bytes"))?;
    let ciphertext = BASE64_STANDARD
        .decode(envelope.ciphertext_b64)
        .context("failed to decode frame ciphertext")?;
    let aad = serde_json::to_vec(&envelope.header).context("failed to encode frame aad")?;
    let plaintext = cipher.decrypt(&aad, &EncryptedPayload { nonce, ciphertext })?;
    let payload: FramePayload =
        serde_json::from_slice(&plaintext).context("failed to decode frame payload")?;
    if payload.flag() != envelope.header.flag {
        bail!("frame flag does not match decrypted payload");
    }
    Ok(Frame {
        header: envelope.header,
        payload,
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn position(&self) -> usize {
        self.offset
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn expect_magic(&mut self, magic: &[u8]) -> Result<()> {
        let bytes = self.take_bytes(magic.len())?;
        if bytes != magic {
            bail!("invalid batch magic");
        }
        Ok(())
    }

    fn take_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| anyhow::anyhow!("batch cursor overflow"))?;
        if end > self.bytes.len() {
            bail!("truncated batch");
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn take_u8(&mut self) -> Result<u8> {
        Ok(self.take_bytes(1)?[0])
    }

    fn take_u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take_bytes(2)?.try_into()?))
    }

    fn take_u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take_bytes(4)?.try_into()?))
    }

    fn take_u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take_bytes(8)?.try_into()?))
    }
}

fn put_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn direction_to_u8(direction: Direction) -> u8 {
    match direction {
        Direction::ClientToExit => 1,
        Direction::ExitToClient => 2,
    }
}

fn u8_to_direction(value: u8) -> Result<Direction> {
    match value {
        1 => Ok(Direction::ClientToExit),
        2 => Ok(Direction::ExitToClient),
        _ => bail!("invalid direction {}", value),
    }
}

fn flag_to_u8(flag: FrameFlag) -> u8 {
    match flag {
        FrameFlag::Open => 1,
        FrameFlag::Data => 2,
        FrameFlag::HalfClose => 3,
        FrameFlag::Close => 4,
        FrameFlag::Reset => 5,
        FrameFlag::Ack => 6,
        FrameFlag::Control => 7,
    }
}

fn u8_to_flag(value: u8) -> Result<FrameFlag> {
    match value {
        1 => Ok(FrameFlag::Open),
        2 => Ok(FrameFlag::Data),
        3 => Ok(FrameFlag::HalfClose),
        4 => Ok(FrameFlag::Close),
        5 => Ok(FrameFlag::Reset),
        6 => Ok(FrameFlag::Ack),
        7 => Ok(FrameFlag::Control),
        _ => bail!("invalid frame flag {}", value),
    }
}

impl Frame {
    pub fn legacy_relative_path(&self) -> PathBuf {
        PathBuf::from("frames")
            .join(self.header.direction.as_path())
            .join(safe_component(&self.header.session_id))
            .join(format!("{:016x}", self.header.stream_id))
            .join(format!(
                "{:020}-{}.json",
                self.header.seq,
                self.header.flag.as_path()
            ))
    }
}

#[derive(Debug, Clone)]
pub struct StoredFrame {
    pub frame: Frame,
    pub relative_path: PathBuf,
}

impl StoredFrame {
    pub fn is_for(&self, session_id: &str, direction: Direction) -> bool {
        self.frame.header.session_id == session_id && self.frame.header.direction == direction
    }
}

#[derive(Default, Debug)]
pub struct ReplayWindow {
    seen: HashSet<(Direction, u64, u64)>,
}

impl ReplayWindow {
    pub fn mark_seen(&mut self, frame: &Frame) -> Result<()> {
        let key = (
            frame.header.direction,
            frame.header.stream_id,
            frame.header.seq,
        );
        if !self.seen.insert(key) {
            bail!("replayed frame seq {}", frame.header.seq);
        }
        Ok(())
    }
}

pub fn acked_frame_paths(frames: &[StoredFrame]) -> Vec<PathBuf> {
    let mut ack_max = HashMap::<(String, u64, Direction), u64>::new();

    for stored in frames {
        if let FramePayload::Ack {
            acked_direction,
            ack,
        } = &stored.frame.payload
        {
            let key = (
                stored.frame.header.session_id.clone(),
                stored.frame.header.stream_id,
                *acked_direction,
            );
            let entry = ack_max.entry(key).or_insert(0);
            *entry = (*entry).max(*ack);
        }
    }

    let mut by_path = HashMap::<PathBuf, Vec<&StoredFrame>>::new();
    for stored in frames {
        by_path
            .entry(stored.relative_path.clone())
            .or_default()
            .push(stored);
    }

    let mut acked = by_path
        .into_iter()
        .filter_map(|(path, stored_frames)| {
            let non_ack_frames = stored_frames
                .iter()
                .copied()
                .filter(|stored| stored.frame.header.flag != FrameFlag::Ack);

            let mut saw_non_ack = false;
            for stored in non_ack_frames {
                saw_non_ack = true;
                let key = (
                    stored.frame.header.session_id.clone(),
                    stored.frame.header.stream_id,
                    stored.frame.header.direction,
                );
                if ack_max
                    .get(&key)
                    .is_none_or(|ack| stored.frame.header.seq > *ack)
                {
                    return None;
                }
            }

            if saw_non_ack
                || stored_frames
                    .iter()
                    .any(|stored| matches!(stored.frame.payload, FramePayload::Ack { .. }))
            {
                Some(path)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    acked.sort();
    acked.dedup();
    acked
}

pub fn safe_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

pub fn frame_path_to_stream(path: &Path) -> Option<u64> {
    path.components()
        .nth(3)
        .and_then(|component| component.as_os_str().to_str())
        .and_then(|name| u64::from_str_radix(name, 16).ok())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip_preserves_metadata() {
        let cipher = TunnelCipher::from_key_bytes([3; 32]);
        let frame = Frame::new(
            "session",
            42,
            Direction::ClientToExit,
            7,
            6,
            FramePayload::Open {
                host: "example.com".to_string(),
                port: 80,
            },
        );

        let encoded = frame.encode(&cipher).unwrap();
        let decoded = Frame::decode(&cipher, &encoded).unwrap();

        assert_eq!(decoded.header.session_id, "session");
        assert_eq!(decoded.header.stream_id, 42);
        assert_eq!(decoded.header.direction, Direction::ClientToExit);
        assert_eq!(decoded.header.seq, 7);
        assert_eq!(decoded.header.ack, 6);
        assert_eq!(decoded.payload, frame.payload);
    }

    #[test]
    fn binary_batch_roundtrip_preserves_order_and_payloads() {
        let cipher = TunnelCipher::from_key_bytes([4; 32]);
        let frames = vec![
            Frame::new(
                "session",
                9,
                Direction::ClientToExit,
                1,
                0,
                FramePayload::data(b"hello"),
            ),
            Frame::new(
                "session",
                9,
                Direction::ClientToExit,
                2,
                0,
                FramePayload::data(b"world"),
            ),
        ];

        let encoded = FrameBatch::encode(&frames, &cipher).unwrap();
        assert_eq!(&encoded[..4], BATCH_MAGIC);
        let decoded = FrameBatch::decode(&cipher, &encoded).unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].header.seq, 1);
        assert_eq!(decoded[1].header.seq, 2);
        assert_eq!(decoded[0].payload.data_bytes().unwrap(), b"hello");
        assert_eq!(decoded[1].payload.data_bytes().unwrap(), b"world");
    }

    #[test]
    fn control_payload_roundtrip_preserves_lease_id() {
        let payload = ControlPayload::StreamOpen {
            sid: 7,
            lease_id: 99,
            host: "example.com".to_string(),
            port: 80,
        };

        let encoded = serde_json::to_string(&payload).unwrap();
        let decoded: ControlPayload = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded, payload);
    }

    #[test]
    fn binary_batch_rejects_tampering() {
        let cipher = TunnelCipher::from_key_bytes([5; 32]);
        let frames = vec![Frame::new(
            "session",
            1,
            Direction::ClientToExit,
            1,
            0,
            FramePayload::data(b"secret"),
        )];
        let mut encoded = FrameBatch::encode(&frames, &cipher).unwrap();
        let last = encoded.len() - 1;
        encoded[last] ^= 1;

        assert!(FrameBatch::decode(&cipher, &encoded).is_err());
    }

    #[test]
    fn replay_window_rejects_duplicate_seq() {
        let frame = Frame::new(
            "session",
            1,
            Direction::ClientToExit,
            1,
            0,
            FramePayload::HalfClose,
        );
        let mut window = ReplayWindow::default();
        window.mark_seen(&frame).unwrap();
        assert!(window.mark_seen(&frame).is_err());
    }

    #[test]
    fn ack_cleanup_removes_only_acknowledged_direction_and_stream() {
        let ack = StoredFrame {
            frame: Frame::new(
                "s",
                1,
                Direction::ExitToClient,
                9,
                0,
                FramePayload::Ack {
                    acked_direction: Direction::ClientToExit,
                    ack: 2,
                },
            ),
            relative_path: PathBuf::from("ack.json"),
        };
        let old = StoredFrame {
            frame: Frame::new(
                "s",
                1,
                Direction::ClientToExit,
                2,
                0,
                FramePayload::HalfClose,
            ),
            relative_path: PathBuf::from("old.json"),
        };
        let other_direction = StoredFrame {
            frame: Frame::new(
                "s",
                1,
                Direction::ExitToClient,
                2,
                0,
                FramePayload::HalfClose,
            ),
            relative_path: PathBuf::from("other-direction.json"),
        };
        let newer = StoredFrame {
            frame: Frame::new(
                "s",
                1,
                Direction::ClientToExit,
                3,
                0,
                FramePayload::HalfClose,
            ),
            relative_path: PathBuf::from("newer.json"),
        };

        let paths = acked_frame_paths(&[ack, old, other_direction, newer]);
        assert!(paths.contains(&PathBuf::from("ack.json")));
        assert!(paths.contains(&PathBuf::from("old.json")));
        assert!(!paths.contains(&PathBuf::from("other-direction.json")));
        assert!(!paths.contains(&PathBuf::from("newer.json")));
    }

    #[test]
    fn ack_cleanup_keeps_partially_acknowledged_batch() {
        let ack = StoredFrame {
            frame: Frame::new(
                "s",
                1,
                Direction::ExitToClient,
                9,
                0,
                FramePayload::Ack {
                    acked_direction: Direction::ClientToExit,
                    ack: 2,
                },
            ),
            relative_path: PathBuf::from("ack.gtb"),
        };
        let old = StoredFrame {
            frame: Frame::new(
                "s",
                1,
                Direction::ClientToExit,
                2,
                0,
                FramePayload::data(b"old"),
            ),
            relative_path: PathBuf::from("batch.gtb"),
        };
        let newer_same_batch = StoredFrame {
            frame: Frame::new(
                "s",
                1,
                Direction::ClientToExit,
                3,
                0,
                FramePayload::data(b"new"),
            ),
            relative_path: PathBuf::from("batch.gtb"),
        };

        let paths = acked_frame_paths(&[ack, old, newer_same_batch]);
        assert!(paths.contains(&PathBuf::from("ack.gtb")));
        assert!(!paths.contains(&PathBuf::from("batch.gtb")));
    }
}
