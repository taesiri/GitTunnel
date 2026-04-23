use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use tokio::time::sleep;
use tracing::info;

use crate::crypto::TunnelCipher;
use crate::frame::{Direction, Frame, FramePayload};
use crate::git_relay::{GitRelay, RelayTuning};

pub struct BenchOptions {
    pub repo: String,
    pub branch: String,
    pub session_id: String,
    pub workdir: Option<PathBuf>,
    pub cipher: TunnelCipher,
    pub trace_frames: bool,
    pub push_interval: Duration,
    pub poll_interval: Duration,
    pub target_kib_s: f64,
    pub latency_target: Duration,
    pub total_bytes: usize,
    pub chunk_size: usize,
    pub batch_size: usize,
    pub max_blob_bytes: usize,
}

pub async fn run_bench(options: BenchOptions) -> Result<()> {
    if options.total_bytes == 0 {
        bail!("benchmark bytes must be greater than zero");
    }
    if options.chunk_size == 0 || options.batch_size == 0 {
        bail!("benchmark chunk and batch sizes must be greater than zero");
    }
    if options.chunk_size > options.batch_size {
        bail!("benchmark chunk size must not exceed batch size");
    }

    let writer_workdir = options
        .workdir
        .as_ref()
        .map(|path| path.join("bench-writer"));
    let reader_workdir = options
        .workdir
        .as_ref()
        .map(|path| path.join("bench-reader"));
    let tuning = RelayTuning::new(
        options.push_interval,
        options.poll_interval,
        options.trace_frames,
        true,
        options.max_blob_bytes,
    );
    let writer = GitRelay::new_split(
        options.repo.clone(),
        options.branch.clone(),
        Direction::ClientToExit,
        options.session_id.clone(),
        writer_workdir,
        options.cipher.clone(),
        tuning,
    )?;
    let reader = GitRelay::new_split(
        options.repo.clone(),
        options.branch.clone(),
        Direction::ExitToClient,
        options.session_id.clone(),
        reader_workdir,
        options.cipher,
        tuning,
    )?;
    writer.ensure_ready().await?;
    reader.ensure_ready().await?;

    info!(
        branch = %options.branch,
        target_kib_s = options.target_kib_s,
        latency_target_ms = options.latency_target.as_millis(),
        total_bytes = options.total_bytes,
        batch_size = options.batch_size,
        push_interval_ms = options.push_interval.as_millis(),
        poll_interval_ms = options.poll_interval.as_millis(),
        "starting one-way GitHub relay benchmark"
    );

    let mut sent_bytes = 0usize;
    let mut received_bytes = 0usize;
    let mut seq = 1u64;
    let mut push_count = 0usize;
    let mut fetch_count = 0usize;
    let mut encoded_sizes = Vec::<usize>::new();
    let mut observe_latencies = Vec::<Duration>::new();
    let mut seen = HashSet::<u64>::new();
    let mut first_byte_latency = None;
    let bench_start = Instant::now();
    let stream_id = fresh_stream_id();

    while sent_bytes < options.total_bytes {
        let batch_remaining = options.total_bytes - sent_bytes;
        let batch_payload = batch_remaining.min(options.batch_size);
        let mut frames = Vec::new();
        let mut built = 0usize;
        while built < batch_payload {
            let n = (batch_payload - built).min(options.chunk_size);
            let data = synthetic_payload(sent_bytes + built, n);
            frames.push(Frame::new(
                options.session_id.clone(),
                stream_id,
                Direction::ClientToExit,
                seq,
                0,
                FramePayload::data(&data),
            ));
            seq += 1;
            built += n;
        }

        let wanted = frames
            .iter()
            .map(|frame| frame.header.seq)
            .collect::<HashSet<_>>();
        let pushed_at = Instant::now();
        let stats = writer
            .write_frames(frames)
            .await
            .context("failed to push benchmark batch")?;
        let push_done = Instant::now();
        push_count += 1;
        encoded_sizes.push(stats.encoded_bytes);
        sent_bytes += stats.payload_bytes;

        loop {
            fetch_count += 1;
            let frames = reader
                .read_frames(Some(Direction::ClientToExit))
                .await
                .context("failed to fetch benchmark frames")?;
            let mut observed_this_batch = true;
            for stored in frames {
                if stored.frame.header.session_id != options.session_id
                    || stored.frame.header.stream_id != stream_id
                {
                    continue;
                }
                let frame_seq = stored.frame.header.seq;
                if seen.insert(frame_seq) {
                    if let FramePayload::Data { .. } = stored.frame.payload {
                        let bytes = stored.frame.payload.data_bytes()?.len();
                        received_bytes += bytes;
                        first_byte_latency.get_or_insert_with(|| bench_start.elapsed());
                    }
                }
            }
            for wanted_seq in &wanted {
                if !seen.contains(wanted_seq) {
                    observed_this_batch = false;
                    break;
                }
            }
            if observed_this_batch {
                observe_latencies.push(push_done.elapsed());
                break;
            }
            sleep(options.poll_interval).await;
        }

        info!(
            push = push_count,
            pushed_ms = pushed_at.elapsed().as_millis(),
            sent_bytes,
            received_bytes,
            "benchmark batch observed by reader"
        );
    }

    let elapsed = bench_start.elapsed();
    let kib_s = received_bytes as f64 / 1024.0 / elapsed.as_secs_f64();
    let p50 = percentile_duration(&observe_latencies, 50.0).unwrap_or_default();
    let p95 = percentile_duration(&observe_latencies, 95.0).unwrap_or_default();
    let p99 = percentile_duration(&observe_latencies, 99.0).unwrap_or_default();
    let first_byte = first_byte_latency.unwrap_or_default();
    let max_object = encoded_sizes.iter().copied().max().unwrap_or_default();
    let latency_status = if first_byte <= options.latency_target && p95 <= options.latency_target {
        "met"
    } else {
        "unmet"
    };
    let throughput_status = if kib_s >= options.target_kib_s {
        "met"
    } else {
        "unmet"
    };

    println!("GitTunnel github-bulk one-way benchmark");
    println!("payload_bytes_sent={sent_bytes}");
    println!("payload_bytes_observed={received_bytes}");
    println!("elapsed_ms={}", elapsed.as_millis());
    println!("payload_kib_s={kib_s:.2}");
    println!("target_kib_s={:.2}", options.target_kib_s);
    println!("throughput_target={throughput_status}");
    println!("pushes={push_count}");
    println!("fetches={fetch_count}");
    println!("push_interval_ms={}", options.push_interval.as_millis());
    println!("poll_interval_ms={}", options.poll_interval.as_millis());
    println!("first_byte_latency_ms={}", first_byte.as_millis());
    println!("commit_to_observe_p50_ms={}", p50.as_millis());
    println!("commit_to_observe_p95_ms={}", p95.as_millis());
    println!("commit_to_observe_p99_ms={}", p99.as_millis());
    println!("latency_target_ms={}", options.latency_target.as_millis());
    println!("latency_target={latency_status}");
    println!("max_encoded_object_bytes={max_object}");
    println!("cleanup_result=not_requested_run_gittunnel_clean");

    Ok(())
}

fn synthetic_payload(offset: usize, len: usize) -> Vec<u8> {
    (0..len).map(|idx| ((offset + idx) % 251) as u8).collect()
}

fn fresh_stream_id() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
        .min(u64::MAX as u128) as u64
}

fn percentile_duration(values: &[Duration], percentile: f64) -> Option<Duration> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = ((percentile / 100.0) * ((sorted.len() - 1) as f64)).round() as usize;
    sorted.get(rank).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_duration_picks_expected_rank() {
        let values = [10_u64, 20, 30, 40, 50]
            .into_iter()
            .map(Duration::from_millis)
            .collect::<Vec<_>>();
        assert_eq!(
            percentile_duration(&values, 50.0),
            Some(Duration::from_millis(30))
        );
        assert_eq!(
            percentile_duration(&values, 95.0),
            Some(Duration::from_millis(50))
        );
    }
}
