# mtp-gateway

Rust gateway for authenticated TCP, UDP and server-side DNS relay.

Client: [mtp-splitter](https://github.com/itinfra7/mtp-splitter).

Author: **itinfra7 from GitHub**  
License: **AGPL-3.0-only**; third-party notices are in [NOTICE](NOTICE).

The transport uses Fake-TLS ee, Obfuscated2, explicit padded chunks, TLS 1.3 mutual authentication and multiplexing. UDP uses UDP-over-TCP.

## Build

Linux x86_64, Rust 1.98.1. Built and tested on **AlmaLinux 10.2** and **Ubuntu 24.04**.

```sh
cargo build --release --locked -p mtp-gateway
cargo test --workspace --locked
```

## Install

The systemd installer requires Python 3 and iproute2. For a release archive, use `./mtp-gateway` instead of `target/release/mtp-gateway`. Replace the example IP and names with your endpoint values. TCP 8443 must be reachable through the host and cloud firewalls.

```sh
sudo target/release/mtp-gateway init \
  --root /var/lib/mtp-gateway-admin \
  --host 203.0.113.10 --port 8443 \
  --outer-sni www.example.com --server-name gateway.example.com \
  --dns-server 9.9.9.9:53
sudo python3 deploy/install-systemd.py \
  --root /var/lib/mtp-gateway-admin --binary target/release/mtp-gateway
```

The installer creates a dedicated unprivileged service account. CA private keys remain inaccessible to the service. It does not alter your firewall.

## Manage

```sh
sudo mtp-gateway client issue --root /var/lib/mtp-gateway-admin --id desktop --owner alice
sudo mtp-gateway client list --root /var/lib/mtp-gateway-admin
sudo mtp-gateway client export --root /var/lib/mtp-gateway-admin --id desktop --out /root/client-exports
sudo mtp-gateway user show --root /var/lib/mtp-gateway-admin --owner alice > alice-policy.json
sudo mtp-gateway user set --root /var/lib/mtp-gateway-admin --owner alice --policy alice-policy.json
sudo mtp-gateway client revoke --root /var/lib/mtp-gateway-admin --id desktop
sudo mtp-gateway doctor --config /etc/mtp-gateway/gateway.toml
sudo systemctl restart mtp-gateway
```

Keep exported credentials private. [Deployment](docs/DEPLOYMENT.ko.md), [protocol](docs/PROTOCOL.ko.md), [client integration](docs/CLIENT_INTEGRATION.ko.md), [verification](docs/VERIFICATION.ko.md).
