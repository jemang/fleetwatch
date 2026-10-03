# FleetWatch

FleetWatch is a self-hosted monitor for Linux servers and Proxmox nodes. A single **Hub** binary holds the database and dashboard; a small **agent** on each host pushes CPU, memory, disk and network metrics to it over HTTPS. The agent opens no port and runs no commands. Live dashboard, alert webhooks, signed agent installs, passkey login, Docker deploy.


## Start the Hub

Requirements: Docker with Compose.

```bash
make release-key                       # once: makes the key that signs the agent files
cp deploy/.env.example deploy/.env     # then edit: password and public URL
docker compose -f deploy/docker-compose.yml up -d --build
```

Open the public URL and log in with the password. Data lives in the Docker volume `fleetwatch_hub-data` (mounted at `/data`). After a change to `deploy/.env`, run the same `up -d` line again; the container is recreated with the new values and the data stays. The variables can also be set in the shell instead of the file.

| Variable | Meaning | Default |
|---|---|---|
| `FLEETWATCH_ADMIN_PASSWORD` | dashboard password (required) | – |
| `FLEETWATCH_PUBLIC_URL` | address of the Hub as agents see it (required for real use) | `http://localhost:8080` |
| `FLEETWATCH_PORT` | port on the Docker host | `8080` |
| `FLEETWATCH_VERSION` | version stamped into the Hub and the agent files | `0.1.0` |
| `FLEETWATCH_TLS_CERT`, `FLEETWATCH_TLS_KEY` | serve HTTPS directly (otherwise put a reverse proxy in front) | – |
| `FLEETWATCH_TRUSTED_PROXIES` | addresses or networks of a reverse proxy, comma-separated; `X-Forwarded-For` is believed only from them | – |
| `FLEETWATCH_RETENTION_RAW`, `_1M`, `_5M`, `_1H` | how long history is kept, as hours (for example `168h`) | 24 hours, 7 days, 30 days, 365 days |

Use HTTPS for anything outside a trusted network: over plain HTTP the agent credential travels unencrypted.

### The signing key

`make release-key` writes the private key to `release/signing-key.pem` and the public key to `internal/release/pubkey/pubkey.pem`. The image build signs the agent files with the private key (passed as a build secret; it is stored in no image). The public key is compiled into the Hub and the agent.

- Keep `release/signing-key.pem` secret and keep a copy. It is in `.gitignore`.
- If it is lost, make a new pair: installed agents then refuse `upgrade` until they are installed again.

## Add a server

In the dashboard choose **+ Add Server** and run the line it shows on the server:

```bash
curl -fsSL https://monitor.example.com/install/<token> | sudo bash
```

The token works once and expires after 15 minutes. The script checks the signature and the checksum of the agent, installs it as the service `fleetwatch-agent` (user `fleetwatch`, locked down with systemd protections, limited to 64 MB of memory and 10% of one processor), registers the server and waits until the Hub has received a report.

Requirements on the server: Linux with systemd, amd64 or arm64, and the programs `curl`, `openssl` and `sha256sum`.

To read the script first, open **Read the script before it runs** in the same dialog.

Options, set on the same line after `sudo`:

```bash
curl -fsSL https://monitor.example.com/install/<token> | sudo FLEETWATCH_SERVICES=nginx,docker bash
```

| Variable | Meaning |
|---|---|
| `FLEETWATCH_SERVICES` | systemd units to watch, separated by commas |
| `FLEETWATCH_PVE_TOKEN_ID`, `FLEETWATCH_PVE_TOKEN_SECRET` | read-only Proxmox API token, to report VMs, containers and storage |

### Proxmox

Create a read-only token on the node, then pass it to the installer:

```bash
pveum user add fleetwatch@pve
pveum acl modify / --users fleetwatch@pve --roles PVEAuditor
pveum user token add fleetwatch@pve agent --privsep 0
```

For an agent that is already installed, add this to `/etc/fleetwatch/agent.yaml` and restart the service:

```yaml
proxmox:
  token_id: fleetwatch@pve!agent
  token_secret: <the value pveum printed>
  ca_file: /etc/fleetwatch/pve-root-ca.pem   # a copy of /etc/pve/pve-root-ca.pem, readable by user fleetwatch
```

The Proxmox part has been tested against a stand-in API only, not against a real node.

## On the server

```bash
sudo fleetwatch-agent status      # how the Hub sees this server
sudo fleetwatch-agent upgrade     # install the version the Hub offers (signature checked with the built-in key)
sudo fleetwatch-agent uninstall   # remove service, config, credential and program
journalctl -u fleetwatch-agent    # the agent's log
```

`uninstall` leaves the system user in place; remove it with `sudo userdel fleetwatch`.

## Passkeys

In **Settings → Passkeys** the administrator can add a passkey (Touch ID, Windows Hello, a hardware key, a password manager) and then log in with **Use passkey** on the login page. The password stays as the second way in. Browsers allow passkeys only over HTTPS with a host name (`localhost` over plain HTTP works for development), so `FLEETWATCH_PUBLIC_URL` must be an `https://` address with a name; otherwise the section explains why passkeys are off.

## In the dashboard

- **Hosts** – all servers; a host name opens its page with disks, network, services, Proxmox guests and history.
- **Alerts** – what is wrong now and what was. **Settings** holds the webhook and Telegram targets and the waiting times.
- Host page, section **Agent**: *Replace credential* issues a new credential (the old one stops working when the new one is issued); *Disable agent* makes the Hub refuse a server's reports.

## Upgrade

Hub: build and start again with a higher `FLEETWATCH_VERSION`; the data volume is kept. Agents: run `sudo fleetwatch-agent upgrade` on each server.

## Development

Go runs only inside Docker; nothing is needed on the machine but Docker and `make`.

```bash
make test                      # all tests, with the race detector
make test PKG=./internal/hub/web/
make vet
deploy/e2e.sh                  # end-to-end check with a test agent container
```

Simulation servers (two test agents, one a stand-in Proxmox node, and a webhook receiver) are in `deploy/docker-compose.test.yml`, kept apart from the Hub so they are easy to drop:

```bash
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.test.yml up -d   # Hub + simulation
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.test.yml stop agent-test agent-pve-test hook-test
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.test.yml rm agent-test agent-pve-test hook-test   # drop them
```
