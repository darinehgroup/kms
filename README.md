# kms

A minimal, self-hosted key-management service for envelope encryption, built
for a 1 vCPU / 1 GiB host. It does exactly four things: generate + wrap
per-company DEKs, unwrap them on demand, rotate the root KEK, and keep an
append-only hash-chained audit log. Full specification: [DESIGN.md](DESIGN.md)
(Persian).

## Architecture in one paragraph

The App server stores each company's `wrapped_dek` (AES-256-GCM, wrapped under
the KMS-held KEK, with `company_id|kek_version` bound as AAD). The KMS holds
only KEK versions — encrypted at rest under an Argon2id key derived from a
2-of-2 founder passphrase — plus the audit log and two encrypted founder TOTP
seeds, all in a local SQLite file. There is no company registry: a wrong
`company_id` simply fails GCM authentication. Two planes are strictly
separated: the network **data-plane** (mTLS + certificate pinning, TLS 1.3)
exposes only `generate`/`unwrap`/`health`; every administrative command runs
on a **control-plane** Unix socket reachable only via SSH on the KMS host.

## Build

```sh
make build          # bin/kms (host platform)
make linux          # static linux/amd64 binary for the server
make test
```

Go ≥ 1.26.4 (per `go.mod`). Pure Go (modernc.org/sqlite) — no cgo, single
static binary, so it runs on any distro with no runtime dependencies.

`make linux` produces `bin/kms-linux-amd64`, but `deploy/kms.service` expects
`/usr/local/bin/kms` — **rename on install**. `make linux` is amd64-only; for
an arm64 host, set `GOARCH=arm64`. Build on an admin workstation and ship the
binary: keeping a compiler and toolchain off the KMS host is part of the design.
`bin/` is gitignored — never commit a build (a stale macOS binary is an easy way
to ship something unrunnable to a Linux server).

## First-time setup (runbook)

```sh
# 0. On an OFFLINE admin machine: generate the PKI, deploy leaves + ca.crt
scripts/gen-pki.sh ./pki 10.0.0.3       # prints both pins

# 1. On the KMS server, install config + the systemd unit first:
#    /var/lib/kms must be pre-created — `kms init` runs as the kms user, and
#    /var/lib is root-owned 0755, so the unit's StateDirectory= is too late.
install -d -o kms -g kms -m 0700 /var/lib/kms
install -d -o root -g kms -m 0750 /etc/kms
cp deploy/kms.env.example /etc/kms/kms.env    # fill in LISTEN_ADDR + CLIENT_PINS
cp deploy/kms.service /etc/systemd/system/ && systemctl daemon-reload
install -m 0755 deploy/kmsctl /usr/local/bin/kmsctl

# 2. Initialize — both founders type their own share
sudo kmsctl init

# 3. Start the service (comes up SEALED)
systemctl enable --now kms

# 4. Unseal — both founders again
sudo kmsctl unseal

# 5. Enroll break-glass TOTP for both founders (shown ONCE; scan immediately)
sudo kmsctl set-totp --label founder_a
sudo kmsctl set-totp --label founder_b

# 6. Confirm
sudo kmsctl status         # sealed: false, totp seeds: 2
sudo kmsctl verify-audit
```

Every admin command goes through `kmsctl`: the admin socket is `0600 kms:kms`,
so commands must run **as the kms user**, and config is parsed before command
dispatch, so they need the service's environment too. `kmsctl` supplies both.

> `systemctl is-active kms` is **not** a health check. `Type=simple` reports
> `active` the moment the process starts — while it is still sealed and
> answering 503 to everything. Check `/v1/health` for real status.

After every restart the service is sealed and the data-plane answers
`503 SEALED` until step 3 is repeated. **The 2-of-2 passphrase has no
recovery path — losing either share loses every key. Back both shares up,
separately and securely, before going to production.**

## Commands

| Command | Where it runs | Notes |
|---|---|---|
| `kms serve` | server process | data-plane mTLS + admin socket |
| `kms init` | direct DB access | creates KEK v1 + audit genesis; refuses if initialized |
| `kms unseal` / `kms seal` | admin socket | 2-of-2 shares / zeroize keyring |
| `kms status` | admin socket | seal state, KEK/TOTP counts |
| `kms rotate-kek` | admin socket | needs both shares again; rewraps TOTP seeds; old versions stay unwrap-capable |
| `kms rekey-passphrase` | admin socket | new shares, same KEKs (all versions re-encrypted) |
| `kms set-totp --label X` | admin socket | founder TOTP enrollment, seed stored encrypted under KEK |
| `kms break-glass --company C --wrapped-dek B64 --kek-version N` | admin socket | requires both founders' current TOTP codes; anti-replay; loudly audited |
| `kms verify-audit` | direct DB (read-only) | walks the whole hash chain |

## Data-plane API (mTLS only)

- `POST /v1/dek/generate` `{"company_id"}` → `{"wrapped_dek","kek_version","plaintext_dek"}`
- `POST /v1/dek/unwrap` `{"company_id","wrapped_dek","kek_version"}` → `{"plaintext_dek"}`
- `GET /v1/health` → `200 {"status":"ok"}` or `503 {"status":"sealed"}`

Errors: `{"error":CODE,"message":...}` with `SEALED`(503),
`INVALID_REQUEST`(400), `UNWRAP_FAILED`(400), `KEK_VERSION_UNKNOWN`(400),
`RATE_LIMITED`(429), `INTERNAL`(500). All cryptographic unwrap failures are
the single generic `UNWRAP_FAILED` — no oracle. `company_id` must match
`^[A-Za-z0-9_-]{1,64}$`. Per-company rate limit (default 120/min) applies to
both generate and unwrap; denials are audited.

## Environment variables

| KMS server | default | |
|---|---|---|
| `KMS_LISTEN_ADDR` | — (required) | e.g. `10.0.0.3:8443` |
| `KMS_ADMIN_SOCKET` | `/run/kms/admin.sock` | control-plane |
| `KMS_DB_PATH` | `/var/lib/kms/kms.db` | SQLite |
| `KMS_TLS_SERVER_CERT` / `KMS_TLS_SERVER_KEY` | — | server leaf |
| `KMS_TLS_CLIENT_CA` | — | CA for client verification |
| `KMS_TLS_CLIENT_PINS` | — | comma-separated SHA-256 fingerprints of allowed client certs |
| `KMS_RATE_LIMIT_UNWRAP_PER_MIN` | `120` | per company_id |
| `KMS_MLOCK` | off | `1` = mlockall (needs `LimitMEMLOCK=infinity`) |

App-side, as actually read by the consuming app server
(`internal/platform/config/config.go`) — note there is **no `APP_` prefix**:

| App server | | |
|---|---|---|
| `KMS_URL` | required in production | must be the private **IP** — the server leaf has an IP SAN and no DNS SAN |
| `KMS_CLIENT_CERT` | **file path** | read with `tls.LoadX509KeyPair` |
| `KMS_CLIENT_KEY` | **file path** | same |
| `KMS_SERVER_CA` | **file path** | read with `os.ReadFile` |
| `KMS_SERVER_PIN` | **inline value** | 64-hex sha256; `sha256:` prefix and colons are tolerated |

The three path variables are filenames, not PEM content — pasting a certificate
body in gives `file name too long`. In Docker they must be bind-mounted and
readable by uid 10001 (the `finomix` user inside the app image).

> **Not implemented:** earlier drafts of this README described an
> `APP_DEK_CACHE_TTL=5m` plaintext-DEK cache. **There is no such cache in
> `app-server`** — no `APP_*` variable is read anywhere, and
> `internal/platform/kmsclient` holds no state. Every DEK operation is a live
> round trip to the KMS, which matters against the per-company
> `KMS_RATE_LIMIT_UNWRAP_PER_MIN` ceiling. Treat a client-side cache as
> outstanding work, not as existing behaviour.

Cache invalidation after a KEK rotation would happen by TTL expiry — the KMS
makes no outbound connections. After `rotate-kek`, run the App's gradual rewrap
job (unwrap with the old version, generate/wrap with the new, update
`wrapped_dek`+`kek_version`).

## Operational notes

- **Firewall**: only the data-plane port, only from the App server's private
  IP (`deny-all-except`). SSH via admin IP / WireGuard only. No outbound
  connections except NTP (audit timestamps depend on it).
- **Backups**: back up the SQLite file encrypted and off-host. It contains
  only ciphertext + metadata; it is useless without the passphrase shares.
- **Monitoring**: watch `result='denied'` rates in the audit log
  (`SELECT operation, COUNT(*) FROM audit_log WHERE result='denied' GROUP BY 1`)
  and the `/v1/health` endpoint.
- **Practice** the unseal and break-glass procedures before you need them.

## License

[MIT](LICENSE) © Darineh Group
