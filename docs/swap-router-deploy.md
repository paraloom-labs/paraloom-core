# Swap router deployment

The `swap-router` bin serves the non-custodial private-swap routing endpoint
(`src/relayer/swap_router.rs`). It holds **no keys** — it only builds unsigned
Jupiter swap transactions for a caller-supplied fresh address. It is safe to run
next to the anchor/validator on the same host.

## What it exposes

- `POST /swap/route` — `{ input_mint, output_mint, amount, user_public_key }`
  returns `{ out_amount, swap_transaction }` (unsigned base64 versioned tx).
- `GET /swap/health` — `200 "ok"`.

CORS is permissive (public, read-only, no credentials).

## Build

On the server (`/opt/paraloom-core`, current stable toolchain):

```sh
cargo build --release --bin swap-router
```

## systemd unit

`/etc/systemd/system/paraloom-swap-router.service`:

```ini
[Unit]
Description=Paraloom non-custodial swap routing service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/paraloom-core
ExecStart=/opt/paraloom-core/target/release/swap-router
Restart=on-failure
RestartSec=3
# Bind to loopback; Caddy terminates TLS and proxies.
Environment=SWAP_ROUTER_ADDR=127.0.0.1:8788
Environment=JUPITER_BASE_URL=https://lite-api.jup.ag/swap/v1
Environment=SLIPPAGE_BPS=50
Environment=RUST_LOG=info
# Protocol fee (optional). Needs a Paraloom-owned fee token account for each
# out mint; leave unset until those accounts exist.
# Environment=PLATFORM_FEE_BPS=25
# Environment=FEE_ACCOUNT=<paraloom_usdc_fee_account_pubkey>

[Install]
WantedBy=multi-user.target
```

Enable and start (note: `enable` so it survives a reboot — a validator once
stayed down after a reboot because it was started but not enabled):

```sh
systemctl daemon-reload
systemctl enable --now paraloom-swap-router
systemctl status paraloom-swap-router
curl -s http://127.0.0.1:8788/swap/health   # -> ok
```

## Caddy route

Serve it under the existing `node.paraloom.io` host so the app can call
`https://node.paraloom.io/swap/route`. Add to the `node.paraloom.io` block:

```caddy
node.paraloom.io {
    # ... existing /rpc and /transact/* routes ...
    reverse_proxy /swap/* 127.0.0.1:8788
}
```

```sh
caddy validate --config /etc/caddy/Caddyfile
systemctl reload caddy
curl -s https://node.paraloom.io/swap/health   # -> ok
```

## Smoke test (mainnet routing, no on-chain action)

`/swap/route` only asks Jupiter to build a tx; it signs and submits nothing, so
this is safe to run against real mainnet:

```sh
curl -s https://node.paraloom.io/swap/route \
  -H 'content-type: application/json' \
  -d '{"input_mint":"SOL","output_mint":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","amount":20000000,"user_public_key":"<any_pubkey>"}'
```

A `200` with an `out_amount` and a base64 `swap_transaction` confirms routing is
live. `422` means Jupiter found no route; `502` means the aggregator failed.
