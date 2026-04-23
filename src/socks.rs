use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NO_ACCEPTABLE: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TargetAddr {
    pub host: String,
    pub port: u16,
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyCode {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

pub async fn accept_connect(stream: &mut TcpStream) -> Result<TargetAddr> {
    negotiate_no_auth(stream).await?;

    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .context("failed to read SOCKS5 request header")?;
    if header[0] != SOCKS_VERSION {
        bail!("unsupported SOCKS version {}", header[0]);
    }
    if header[1] != CMD_CONNECT {
        send_reply(stream, ReplyCode::CommandNotSupported).await?;
        bail!("only SOCKS5 CONNECT is supported");
    }
    if header[2] != 0x00 {
        send_reply(stream, ReplyCode::GeneralFailure).await?;
        bail!("invalid SOCKS5 reserved byte");
    }

    let target = match header[3] {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            TargetAddr {
                host: Ipv4Addr::from(addr).to_string(),
                port: read_port(stream).await?,
            }
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            if len[0] == 0 {
                send_reply(stream, ReplyCode::GeneralFailure).await?;
                bail!("empty SOCKS5 domain name");
            }
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            TargetAddr {
                host: String::from_utf8(domain).context("SOCKS5 domain is not valid UTF-8")?,
                port: read_port(stream).await?,
            }
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            TargetAddr {
                host: Ipv6Addr::from(addr).to_string(),
                port: read_port(stream).await?,
            }
        }
        _ => {
            send_reply(stream, ReplyCode::AddressTypeNotSupported).await?;
            bail!("unsupported SOCKS5 address type {}", header[3]);
        }
    };

    Ok(target)
}

pub async fn send_reply(stream: &mut TcpStream, code: ReplyCode) -> Result<()> {
    stream
        .write_all(&[SOCKS_VERSION, code as u8, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await
        .context("failed to send SOCKS5 reply")
}

async fn negotiate_no_auth(stream: &mut TcpStream) -> Result<()> {
    let mut header = [0u8; 2];
    stream
        .read_exact(&mut header)
        .await
        .context("failed to read SOCKS5 greeting")?;
    if header[0] != SOCKS_VERSION {
        bail!("unsupported SOCKS version {}", header[0]);
    }
    let mut methods = vec![0u8; header[1] as usize];
    stream
        .read_exact(&mut methods)
        .await
        .context("failed to read SOCKS5 auth methods")?;
    let selected = if methods.contains(&METHOD_NO_AUTH) {
        METHOD_NO_AUTH
    } else {
        METHOD_NO_ACCEPTABLE
    };
    stream
        .write_all(&[SOCKS_VERSION, selected])
        .await
        .context("failed to send SOCKS5 auth selection")?;
    if selected == METHOD_NO_ACCEPTABLE {
        bail!("SOCKS5 client did not offer no-auth mode");
    }
    Ok(())
}

async fn read_port(stream: &mut TcpStream) -> Result<u16> {
    let mut port = [0u8; 2];
    stream
        .read_exact(&mut port)
        .await
        .context("failed to read SOCKS5 port")?;
    Ok(u16::from_be_bytes(port))
}

pub fn parse_connect_request_for_test(bytes: &[u8]) -> Result<TargetAddr> {
    if bytes.len() < 4 {
        bail!("short request");
    }
    if bytes[0] != SOCKS_VERSION {
        bail!("unsupported version");
    }
    if bytes[1] != CMD_CONNECT {
        bail!("unsupported command");
    }
    if bytes[2] != 0 {
        bail!("invalid reserved byte");
    }
    let mut index = 4;
    let host = match bytes[3] {
        ATYP_IPV4 => {
            if bytes.len() < index + 4 + 2 {
                bail!("short IPv4 request");
            }
            let addr = Ipv4Addr::new(
                bytes[index],
                bytes[index + 1],
                bytes[index + 2],
                bytes[index + 3],
            );
            index += 4;
            addr.to_string()
        }
        ATYP_DOMAIN => {
            if bytes.len() < index + 1 {
                bail!("short domain request");
            }
            let len = bytes[index] as usize;
            index += 1;
            if len == 0 || bytes.len() < index + len + 2 {
                bail!("invalid domain request");
            }
            let domain = String::from_utf8(bytes[index..index + len].to_vec())?;
            index += len;
            domain
        }
        ATYP_IPV6 => {
            if bytes.len() < index + 16 + 2 {
                bail!("short IPv6 request");
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&bytes[index..index + 16]);
            index += 16;
            Ipv6Addr::from(addr).to_string()
        }
        _ => bail!("unsupported address type"),
    };
    let port = u16::from_be_bytes([bytes[index], bytes[index + 1]]);
    Ok(TargetAddr { host, port })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_domain_connect_request() {
        let mut bytes = vec![0x05, 0x01, 0x00, 0x03, 11];
        bytes.extend_from_slice(b"example.com");
        bytes.extend_from_slice(&80u16.to_be_bytes());
        let parsed = parse_connect_request_for_test(&bytes).unwrap();
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, 80);
    }

    #[test]
    fn rejects_unsupported_command() {
        let bytes = [0x05, 0x03, 0x00, 0x03, 0x00, 0x00, 0x50];
        assert!(parse_connect_request_for_test(&bytes).is_err());
    }
}
