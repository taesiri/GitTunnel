# GitTunnel

GitTunnel is a deliberately absurd Rust CLI demo: SOCKS5 TCP traffic tunneled
through a GitHub repository using ordinary `git push` and `git fetch` operations
as the relay transport.

Every TCP payload frame is encrypted before it lands in Git. GitHub only sees
opaque frame blobs and enough metadata to route stream branches.

This is a toy and a measurement project. It is not a practical proxy, not a
stealth tool, not a bypass tool, and not production infrastructure. Use a
private repository that you own.

## Current Verdict

The fun version: it works.

The engineering version: GitHub is a hilarious relay and a terrible transport.
Warm pooling fixed the cold branch creation problem, but true first-byte latency
is still measured in seconds because every stream crosses multiple GitHub
push/fetch observation cycles.

Latest live test report: [docs/stage4-github-live-report.md](docs/stage4-github-live-report.md)

| Measurement | Result |
|---|---:|
| Warm branch pairs pre-created | 4 |
| Warm-pool startup time | 3.7 s |
| Warm-pool hits / misses | 11 / 0 |
| Sequential small-request first-byte p50 | 9.99 s |
| Sequential small-request first-byte average | 10.98 s |
| 3 parallel small curls | all HTTP 200 |
| 3 parallel curl wall time | 19 s |
| Best 1 MiB end-to-end throughput | 12.97 KiB/s |
| Best 1 MiB post-first-byte throughput | 15.46 KiB/s |
| 50 KiB/s target | not met |
| 300 ms latency target | not met |
| Plaintext scan of relay branch heads | no matches |

## What It Supports

- SOCKS5 TCP `CONNECT`.
- Domain-name SOCKS requests, so DNS resolution can happen on the exit side.
- Encrypted frame payloads with XChaCha20-Poly1305.
- GitHub relay through the installed `git` CLI.
- A local client process that listens on loopback.
- A remote exit process that opens allowed outbound TCP connections.
- `github-multi` branch-per-stream mode with a warm pool of reusable stream
  branch pairs.

Out of scope:

- UDP ASSOCIATE.
- BIND.
- Stealth, persistence, evasion, or production performance claims.
- Interactive SSH latency. The measured path is far too slow for that.

## Profiles

| Profile | Model | Current use |
|---|---|---|
| `conservative` | Single branch, JSON-era reference path | Baseline/reference behavior |
| `github-bulk` | Split `c2e`/`e2c` branches, binary batches, deferred cleanup | Bulk benchmark experiments |
| `github-multi` | Control branch plus branch pair per stream | Current SOCKS demo path |

`github-multi` is the current focus. It uses:

- `gt/<session>/ctl` for control frames.
- `gt/<session>/s/<sid>/c2e` for client-to-exit stream data.
- `gt/<session>/s/<sid>/e2c` for exit-to-client stream data.
- `(sid, lease_id)` stream identity so branch IDs can be recycled safely.

## Latest Live Results

All results below were measured on 2026-04-22 using:

- Local client: macOS arm64.
- Exit: Linux x86_64 VPS.
- Relay: private GitHub repository.
- Local and VPS GitHub keys: explicit paths omitted.
- Runtime profile: `github-multi`.
- Warm pool size: 4.

The live test used explicit `GIT_SSH_COMMAND` values on both sides so Git picked
the intended GitHub identity without editing SSH config.

### Small HTTP Latency

Five sequential requests:

```sh
curl --socks5-hostname 127.0.0.1:1080 http://example.com/
```

| Run | HTTP | Bytes | First byte (s) | Total (s) |
|---:|---:|---:|---:|---:|
| 1 | 200 | 528 | 9.161145 | 10.126672 |
| 2 | 200 | 528 | 9.985669 | 9.985775 |
| 3 | 200 | 528 | 9.307322 | 9.307436 |
| 4 | 200 | 528 | 13.425796 | 13.425908 |
| 5 | 200 | 528 | 13.025667 | 13.025759 |

Summary:

| Metric | First byte (s) |
|---|---:|
| min | 9.161145 |
| p50 | 9.985669 |
| average | 10.981120 |
| max | 13.425796 |

Three parallel small requests:

| Run | HTTP | Bytes | First byte (s) | Total (s) |
|---:|---:|---:|---:|---:|
| 1 | 200 | 528 | 13.200801 | 15.231518 |
| 3 | 200 | 528 | 18.161921 | 18.162028 |
| 2 | 200 | 528 | 19.425892 | 19.425977 |

Parallel wall time: 19 seconds.

### Payload Throughput

Payload files were served on the VPS from `127.0.0.1:18080` and fetched through
the local SOCKS listener.

| File | Bytes | SHA256 | First byte (s) | Total (s) | Overall KiB/s | Post-first-byte KiB/s |
|---|---:|---|---:|---:|---:|---:|
| `64k.bin` | 65,536 | matched | 12.851656 | 16.704256 | 3.83 | 16.61 |
| `256k.bin` | 262,144 | matched | 12.735223 | 28.041811 | 9.13 | 16.72 |
| `1m.bin` | 1,048,576 | matched | 12.707387 | 78.944502 | 12.97 | 15.46 |

Remote SHA256 values from the VPS:

```text
bccd04b55b217faeedc8fcca3c23253dc0ca3ce5c6d400d40aca148c19d705e7  64k.bin
151ded1500fa5d83be2cde799f5b6957a1ef287dfd1750901956d918cb7663f6  256k.bin
e1c9ec8da53f3c470dcd9e5ce1e20e0054819b368e27b5396d7fae43640a9106  1m.bin
```

## Development History

These phases are not all directly comparable. Early throughput numbers came
from `github-bulk`; the current latency/bandwidth verdict comes from
`github-multi` SOCKS mode.

| Phase | Change | Result |
|---|---|---|
| Baseline | Original `github-bulk` path | About 64 KiB/s in one-way bulk mode |
| Phase 0 | SSH ControlMaster | Reduced commit-observe latency by about 22% in earlier tests |
| Phase 1 | `GitBranch` per worktree | Removed `.git/index.lock` races |
| Phase 2 | Control branch `gt/<session>/ctl` | Decoupled open/close/reset from data branches |
| Phase 3 | Branch-per-stream | Proved real multi-stream concurrency, but cold branch creation caused about 14 s first byte |
| Phase 4 | Warm pool and `(sid, lease_id)` lifecycle | Warm lease acquisition is 0 ms; p50 small-request first byte is still about 10 s |

## Architecture

```text
SOCKS client
    |
    | CONNECT host:port
    v
local gittunnel client
    |
    | borrow warm (sid, lease_id)
    | push StreamOpen to gt/<session>/ctl
    | push client bytes to gt/<session>/s/<sid>/c2e
    v
GitHub repository
    |
    | exit fetches control/data branches
    v
remote gittunnel exit
    |
    | TCP connect to allowed host:port
    | push response bytes to gt/<session>/s/<sid>/e2c
    v
GitHub repository
    |
    | client fetches response branch
    v
local SOCKS socket
```

### Warm Pool

`github-multi` pre-creates stream branch pairs before accepting SOCKS
connections. The default client pool size is 4:

```sh
gittunnel client \
  --profile github-multi \
  --repo git@github.com:OWNER/REPO.git \
  --branch git-tunnel/demo \
  --session demo-session \
  --listen 127.0.0.1:1080 \
  --key tunnel.key \
  --warm-pool-size 4
```

Each SOCKS connection borrows an idle `(sid, lease_id)` slot. After normal close,
the client resets both stream branches to an empty checkpoint, assigns a new
`lease_id`, and returns the slot to the pool.

Set `--warm-pool-size 0` to keep the old cold branch-per-stream behavior.

### Encryption

Frame payloads are encrypted with XChaCha20-Poly1305 using a shared 32-byte key.
The relay repository should only contain opaque batch blobs plus routing/order
metadata. The live report includes a plaintext scan for `GET /`, `HTTP/`, and
`Example Domain`; no matches were found in the live session branch heads.

### Why Latency Is Still Bad

Warm pooling removes cold branch creation from the connection path, but a small
HTTP request still requires a chain like this:

1. Client pushes `StreamOpen`.
2. Exit fetches and observes control.
3. Client pushes request bytes.
4. Exit fetches request bytes.
5. Exit opens the TCP target connection.
6. Exit pushes response bytes.
7. Client fetches response bytes.

That is why first byte is still around 10 seconds, even when lease acquisition is
0 ms.

## Build

Local build:

```sh
cargo build --release
```

Linux x86_64 build from macOS using Docker:

```sh
docker run --rm --platform linux/amd64 \
  -v "$PWD":/work \
  -w /work \
  -e CARGO_TARGET_DIR=/work/target-linux-amd64 \
  rust:1.92 \
  sh -lc 'export PATH=/usr/local/cargo/bin:$PATH; cargo build --release'
```

Copy the Linux binary to the VPS:

```sh
scp target-linux-amd64/release/gittunnel user@YOUR_VPS_HOST:/opt/gittunnel-demo/gittunnel
ssh user@YOUR_VPS_HOST 'chmod 755 /opt/gittunnel-demo/gittunnel'
```

## Key File

Create one shared key and copy the same file to both sides:

```sh
openssl rand -hex 32 > tunnel.key
scp tunnel.key user@YOUR_VPS_HOST:/opt/gittunnel-demo/tunnel.key
```

## Quickstart

Use a private empty GitHub repository you own.

Exit side on the VPS:

```sh
GIT_SSH_COMMAND='ssh -i /path/to/vps-github-key -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new' \
/opt/gittunnel-demo/gittunnel --log debug exit \
  --profile github-multi \
  --repo git@github.com:OWNER/REPO.git \
  --branch git-tunnel/demo \
  --session demo-session \
  --key /opt/gittunnel-demo/tunnel.key \
  --allow-host example.com:80 \
  --allow-host example.com:443
```

Client side locally:

```sh
GIT_SSH_COMMAND='ssh -i ~/.ssh/your-github-key -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new' \
target/release/gittunnel --log debug client \
  --profile github-multi \
  --repo git@github.com:OWNER/REPO.git \
  --branch git-tunnel/demo \
  --session demo-session \
  --listen 127.0.0.1:1080 \
  --key tunnel.key \
  --warm-pool-size 4
```

Test:

```sh
curl --socks5-hostname 127.0.0.1:1080 http://example.com/
```

## Test Commands

Latest local verification:

| Check | Result |
|---|---|
| `cargo fmt -- --check` | pass |
| `cargo test --quiet` | 31 passed |
| `cargo clippy --all-targets -- -D warnings` | pass |
| macOS release build | pass |
| Linux x86_64 Docker release build | pass |
| GitHub/VPS live test | pass, with measurements above |

Local verification:

```sh
cargo fmt -- --check
cargo test --quiet
cargo clippy --all-targets -- -D warnings
```

Live latency test:

```sh
curl --silent --show-error --fail \
  --socks5-hostname 127.0.0.1:1080 \
  -o example.html \
  -w 'http_code=%{http_code} bytes=%{size_download} time_starttransfer=%{time_starttransfer} time_total=%{time_total}\n' \
  http://example.com/
```

VPS-local bandwidth target:

```sh
ssh user@YOUR_VPS_HOST '
  mkdir -p /opt/gittunnel-demo/www
  cd /opt/gittunnel-demo/www
  dd if=/dev/urandom of=1m.bin bs=1024 count=1024
  sha256sum 1m.bin
  python3 -m http.server 18080 --bind 127.0.0.1
'
```

Bandwidth test through the tunnel:

```sh
curl --fail --max-time 1200 \
  --socks5-hostname 127.0.0.1:1080 \
  -o 1m-via-tunnel.bin \
  -w 'bytes=%{size_download} speed_Bps=%{speed_download} first_byte=%{time_starttransfer} total=%{time_total}\n' \
  http://127.0.0.1:18080/1m.bin

shasum -a 256 1m-via-tunnel.bin
```

## Cleanup

Stop local and VPS processes, then delete the session refs. For `github-multi`,
the active refs are under `gt/<session>/`.

```sh
GIT_SSH_COMMAND='ssh -i ~/.ssh/your-github-key -o IdentitiesOnly=yes' \
git ls-remote --heads git@github.com:OWNER/REPO.git 'refs/heads/gt/demo-session/*'
```

Delete each branch:

```sh
GIT_SSH_COMMAND='ssh -i ~/.ssh/your-github-key -o IdentitiesOnly=yes' \
git push git@github.com:OWNER/REPO.git --delete gt/demo-session/ctl

GIT_SSH_COMMAND='ssh -i ~/.ssh/your-github-key -o IdentitiesOnly=yes' \
git push git@github.com:OWNER/REPO.git --delete gt/demo-session/s/0000000000000001/c2e
```

The live report run deleted all 9 temporary refs and verified 0 matching refs
remaining.

## Repository Safety Notes

- Use a private relay repository.
- Keep payloads small.
- Do not use Git LFS for the tunnel data path.
- The demo intentionally avoids append-only history for stream branches; it
  resets branch heads back to empty checkpoints after lease reuse.
- GitHub's [repository limits](https://docs.github.com/en/repositories/creating-and-managing-repositories/repository-limits)
  guidance currently recommends keeping a single Git object at or below 1 MB,
  keeping Git read operations around 15 per second per repository, and keeping
  push rate around 6 pushes per minute per repository.
- GitHub's [large file guidance](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github)
  and [Git LFS billing docs](https://docs.github.com/en/billing/concepts/product-billing/git-lfs)
  are part of why this project avoids LFS for relay data.

## Module Map

```text
src/
  main.rs         CLI and profile routing
  ssh.rs          SSH ControlMaster helpers
  git_branch.rs   single-branch Git primitive
  git_relay.rs    conservative/github-bulk relay wrapper
  control.rs      gt/<session>/ctl control channel
  stream.rs       per-stream c2e/e2c branch pair
  session.rs      github-multi client/exit orchestration
  tunnel.rs       legacy conservative/github-bulk SOCKS path
  frame.rs        GTB1 frame format and ControlPayload
  bench.rs        one-way github-bulk benchmark harness
  socks.rs        SOCKS5 CONNECT parser
  crypto.rs       XChaCha20-Poly1305 key handling
```

## Next Work

The next meaningful speed work is not more branch warmup. Stage 4 proved warm
lease acquisition is no longer the problem.

Most useful next steps:

1. Add real data batching for `github-multi` stream writes.
2. Add `bench --streams N` for repeatable multi-stream measurement.
3. Compact or checkpoint the control branch to reduce repeated close replay.
4. Add compression before encryption for text-like payloads.

Expected impact: data batching is the best candidate for moving throughput
toward the original 50 KiB/s goal. It will not make GitHub push/fetch a 300 ms
interactive transport.
