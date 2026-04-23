# Stage 4 GitHub Live Test Report

Date: 2026-04-22

## Verdict

Stage 4 warm pooling works functionally, but it does not make GitHub relay latency interactive.

- Warm pool startup created 4 reusable stream branch pairs in 3.7 seconds.
- Every measured stream used a warm lease: 11 warm-pool hits, 0 misses.
- Lease acquisition on the client path was effectively 0 ms.
- Sequential small-request first-byte latency was still about 10 seconds p50.
- Parallel small-request first-byte latency was worse, about 18 seconds p50 for three simultaneous curls.
- Best sustained payload result was the 1 MiB file: 12.97 KiB/s end-to-end, or 15.46 KiB/s after subtracting first-byte delay.
- The 50 KiB/s target was not met. The 300 ms target remains out of reach for GitHub push/fetch transport.

The bottleneck has moved away from cold branch creation, but the remaining GitHub control/data push and fetch observation path is still measured in seconds.

## Environment

- Local machine: macOS arm64.
- VPS: Linux x86_64.
- Relay repo: private GitHub repository.
- GitHub key paths: omitted.
- VPS binary path: `/opt/gittunnel-demo/gittunnel`.
- Local client binary: `target/release/gittunnel`.
- Linux build method:

```sh
docker run --rm --platform linux/amd64 \
  -v "$PWD":/work \
  -w /work \
  -e CARGO_TARGET_DIR=/work/target-linux-amd64 \
  rust:1.92 \
  sh -lc 'export PATH=/usr/local/cargo/bin:$PATH; cargo build --release'
```

Linux binary observed by `file`:

```text
ELF 64-bit LSB pie executable, x86-64, dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2
```

## Local Verification

Before the live run:

```sh
cargo fmt -- --check
cargo test --quiet
cargo clippy --all-targets -- -D warnings
cargo build --release
```

Results:

- Formatting: pass.
- Tests: 31 passed.
- Clippy: pass with warnings denied.
- Local release build: pass.
- Linux x86_64 Docker release build: pass.

## Live Session Setup

Fresh report session:

```text
stage4-report-session
```

VPS exit command shape:

```sh
GIT_SSH_COMMAND='ssh -i /path/to/vps-github-key -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new' \
/opt/gittunnel-demo/gittunnel --log debug exit \
  --repo git@github.com:OWNER/REPO.git \
  --branch git-tunnel/stage4-report \
  --session stage4-report-session \
  --key /opt/gittunnel-demo/tunnel.key \
  --profile github-multi \
  --trace-frames \
  --allow-host example.com:80 \
  --allow-host example.com:443 \
  --allow-host 127.0.0.1:18080 \
  --max-runtime-secs 1800
```

Local client command shape:

```sh
GIT_SSH_COMMAND='ssh -i ~/.ssh/your-github-key -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new' \
target/release/gittunnel --log debug client \
  --repo git@github.com:OWNER/REPO.git \
  --branch git-tunnel/stage4-report \
  --session stage4-report-session \
  --key /tmp/gittunnel-report/tunnel.key \
  --profile github-multi \
  --trace-frames \
  --listen 127.0.0.1:1080 \
  --warm-pool-size 4 \
  --max-runtime-secs 1800
```

VPS bandwidth target server:

```sh
cd /opt/gittunnel-demo/www
dd if=/dev/urandom of=64k.bin bs=1024 count=64
dd if=/dev/urandom of=256k.bin bs=1024 count=256
dd if=/dev/urandom of=1m.bin bs=1024 count=1024
sha256sum 64k.bin 256k.bin 1m.bin > SHA256SUMS
python3 -m http.server 18080 --bind 127.0.0.1
```

Warm-pool startup:

```text
warm_pool_ready=4
warm_pool_hit=11
warm_pool_miss=0
warm_pool_recycle_done=11
```

Initial relay refs after prewarm:

```text
9 refs: gt/<session>/ctl plus 4 c2e/e2c stream branch pairs.
```

## Small Request Latency

Command shape:

```sh
curl --silent --show-error --fail \
  --socks5-hostname 127.0.0.1:1080 \
  -o example.html \
  -w 'http_code=%{http_code} bytes=%{size_download} time_starttransfer=%{time_starttransfer} time_total=%{time_total}\n' \
  http://example.com/
```

Sequential `example.com` results:

| Run | HTTP | Bytes | First byte (s) | Total (s) |
|---:|---:|---:|---:|---:|
| 1 | 200 | 528 | 9.161145 | 10.126672 |
| 2 | 200 | 528 | 9.985669 | 9.985775 |
| 3 | 200 | 528 | 9.307322 | 9.307436 |
| 4 | 200 | 528 | 13.425796 | 13.425908 |
| 5 | 200 | 528 | 13.025667 | 13.025759 |

Sequential latency summary:

| Metric | First byte (s) |
|---|---:|
| min | 9.161145 |
| p50 | 9.985669 |
| avg | 10.981120 |
| max | 13.425796 |

Parallel 3-curl results:

| Run | HTTP | Bytes | First byte (s) | Total (s) |
|---:|---:|---:|---:|---:|
| 1 | 200 | 528 | 13.200801 | 15.231518 |
| 3 | 200 | 528 | 18.161921 | 18.162028 |
| 2 | 200 | 528 | 19.425892 | 19.425977 |

Parallel wall time: 19 seconds.

## Payload Bandwidth

All payloads were served from the VPS on loopback at `http://127.0.0.1:18080/` and fetched through local SOCKS via GitHub.

| File | Bytes | SHA256 | First byte (s) | Total (s) | Overall KiB/s | Post-first-byte KiB/s |
|---|---:|---|---:|---:|---:|---:|
| `64k.bin` | 65,536 | matched | 12.851656 | 16.704256 | 3.83 | 16.61 |
| `256k.bin` | 262,144 | matched | 12.735223 | 28.041811 | 9.13 | 16.72 |
| `1m.bin` | 1,048,576 | matched | 12.707387 | 78.944502 | 12.97 | 15.46 |

Remote SHA256 values:

```text
bccd04b55b217faeedc8fcca3c23253dc0ca3ce5c6d400d40aca148c19d705e7  64k.bin
151ded1500fa5d83be2cde799f5b6957a1ef287dfd1750901956d918cb7663f6  256k.bin
e1c9ec8da53f3c470dcd9e5ce1e20e0054819b368e27b5396d7fae43640a9106  1m.bin
```

The downloaded files matched those hashes locally.

## Relay Safety Checks

Log scan:

```text
client error/rejection/failure lines: 0
exit error/rejection/failure lines: 0
```

Branch count after all transfers:

```text
9 refs: gt/<session>/ctl plus 4 c2e/e2c stream branch pairs.
```

Plaintext scan across the live session branch heads:

```text
patterns searched: GET /, HTTP/, Example Domain
result: no matches
```

This confirms that accessible branch heads did not expose the HTTP request, response headers, or body as plaintext.

## Cleanup

Stopped:

- Local `gittunnel client`.
- VPS `gittunnel exit`.
- VPS Python loopback HTTP server.

Deleted relay refs:

```text
gt/stage4-report-session/ctl
gt/stage4-report-session/s/0000000000000001/c2e
gt/stage4-report-session/s/0000000000000001/e2c
gt/stage4-report-session/s/0000000000000002/c2e
gt/stage4-report-session/s/0000000000000002/e2c
gt/stage4-report-session/s/0000000000000003/c2e
gt/stage4-report-session/s/0000000000000003/e2c
gt/stage4-report-session/s/0000000000000004/c2e
gt/stage4-report-session/s/0000000000000004/e2c
```

Remaining matching refs after cleanup:

```text
0
```

## Interpretation

Warm pooling is valuable, but only for removing cold branch creation from the connection path. In this run, it reduced lease acquisition to 0 ms, but the connection still had to:

1. Push `StreamOpen` to the control branch.
2. Have the exit side fetch and observe that control frame.
3. Push the client request frame.
4. Have the exit side fetch the request frame.
5. Open the target TCP connection.
6. Push response frames back.
7. Have the client fetch and observe the response frames.

That GitHub transaction chain dominates latency.

For throughput, the current `github-multi` SOCKS data path pushes each TCP read as a Git frame batch. Larger transfers amortize the 12 to 13 second first-byte delay, but sustained throughput still lands around 15 to 17 KiB/s after first byte, and about 13 KiB/s end-to-end for a 1 MiB object.

## Next Engineering Verdict

The next work should not chase more branch warmup. The branch warmup part is now working.

Highest-impact next steps:

1. Add real data batching for `github-multi` stream writes so multiple TCP reads can share one Git push.
2. Add `bench --streams N` for repeatable multi-stream throughput measurement.
3. Reduce repeated close-control log churn by compacting or checkpointing the control branch.
4. Consider compression before encryption for text payloads, but do not expect it to help random/binary payloads.

Current measured ceiling for this implementation is about 13 KiB/s end-to-end on a 1 MiB transfer, with p50 first-byte latency around 10 seconds for sequential small HTTP requests.
