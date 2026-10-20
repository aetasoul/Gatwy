<div align="center">

# Gatwy
### ![alt text](https://github.com/kotoxie/Gatwy/blob/master/packages/client/public/favicon.png?raw=true) 


### Self-host your entire remote access stack in one Docker container — 10 protocols, one interface: RDP, SSH, VNC, Telnet, SMB, SFTP, FTP, MySQL & PostgreSQL (Optional - Moonlight).


[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Image Size](https://img.shields.io/endpoint?url=https://gatwy-image-size.gatwy.dev)
[![Latest Release](https://img.shields.io/github/v/release/kotoxie/gatwy?label=release)](https://github.com/kotoxie/gatwy/releases/latest)
[![Docker Image](https://img.shields.io/badge/ghcr.io-kotoxie%2Fgatwy-blue?logo=docker)](https://ghcr.io/kotoxie/gatwy)

**No middleware. No Java. No server relay. WebAssembly-native RDP running directly in your browser — zero overhead across all protocols.**

[Website](https://gatwy.dev) · [Documentation](https://docs.gatwy.dev) · [Gatwy vs Guacamole](https://docs.gatwy.dev/comparison)

[Quick Start](#-quick-start) · [Configuration](#️-configuration)
</div>

---

## 🚀 Why Gatwy?

Most browser-based remote access tools relay your display through a server-side engine, adding latency and complexity. Gatwy's RDP client runs **entirely in your browser** using WebAssembly — pixel-perfect, low-latency RDP with no middleware, no Java, and no extra containers.

> **One container. Zero dependencies.** Open your browser and connect.

---

## ✨ Highlights

| | Feature | What you get |
|:-:|---|---|
|| **10 protocols** | RDP (WebAssembly), SSH, VNC, Telnet, SMB, SFTP, FTP, PostgreSQL, MySQL — plus optional Moonlight |
|| **Split-pane workspace** | Unlimited sessions side by side with drag-and-drop tabs |
|| **Session recording & audit** | Encrypted RDP video, SSH asciinema, command-level audit log with auto-redacted passwords, file activity tracking |
|| **Credential library** | Reusable username/password and SSH key credentials; rotate a password once and every connection follows |
|| **Granular RBAC** | 30 fine-grained permissions, custom roles, per-connection sharing, protocol-level access control |
|| **Auth flexibility** | Local accounts, LDAP/AD, OpenID Connect (SSO), MFA (TOTP), IP access rules |
|| **Alerting** | SMTP, Telegram, Slack, Webhook channels with a no-code rule builder |
|| **Encrypted backup & restore** | Single-file `.geb` backup with AES-256 encryption |

👉 **[Full feature list →](https://docs.gatwy.dev/features/overview)**

---

## 🐳 Quick Start

### Docker Compose

```yaml
# docker-compose.yml
services:
  gatwy:
    image: ghcr.io/kotoxie/gatwy:latest
    container_name: gatwy
    restart: unless-stopped
    ports:
      - '7443:7443'
    volumes:
      - ./data:/app/data
    environment:
      - GATWY_ENCRYPTION_KEY=your-64-char-hex-key  # openssl rand -hex 32
```

```bash
docker compose up -d
```

### Docker Run

```bash
docker run -d \
  --name gatwy \
  --restart unless-stopped \
  -p 7443:7443 \
  -v ./data:/app/data \
  -e GATWY_ENCRYPTION_KEY=your-64-char-hex-key \
  ghcr.io/kotoxie/gatwy:latest
```

Then open **`https://<YOUR_IP>:7443`** and create your admin account on first launch.

> [!NOTE]
> The browser will warn about the self-signed certificate. Accept the exception to proceed, or [bring your own cert](https://docs.gatwy.dev/configuration#tls).

---

## ⚙️ Configuration

### Core

| Variable | Default | Description |
|---|---|---|
| `GATWY_ENCRYPTION_KEY` | *(auto-generated file)* | 64-char hex AES-256 key. ⚠️ **Set this in production.** Generate with `openssl rand -hex 32` |
| `PORT` | `7443` | HTTPS port |
| `DATA_DIR` | `/app/data` | Database, certs, recordings, and logs |
| `TLS_CERT_PATH` / `TLS_KEY_PATH` | *(auto)* | Custom TLS certificate & key paths |
| `BASE_PATH` | `/` *(root)* | URL path prefix for serving behind a reverse proxy (e.g. `/sys/ftp`). Plain path segments only (`A-Z a-z 0-9 . _ ~ -`); leading/trailing slashes are normalized. |

### Authentication

| Variable | Default | Description |
|---|---|---|
| `OIDC_TOKEN_AUTH_METHOD` | `client_secret_basic` | OIDC token endpoint client auth: `client_secret_basic` (or `basic`) or `client_secret_post` (or `post`). |

> **Note:** If no encryption key is set, Gatwy auto-generates one at `/app/data/encryption.key` and shows a warning banner. Fine for a home lab — not recommended for production.

👉 **[Full configuration reference →](https://docs.gatwy.dev)**

---

## 🌙 Optional: Moonlight / Sunshine

Moonlight is **off by default**. The helper it uses, [moonlight-web-stream](https://github.com/MrCreativ3001/moonlight-web-stream), is GPL-3.0 and is not bundled — Gatwy itself stays MIT.

> [!TIP]
> Enable it by setting `ENABLE_MOONLIGHT` to `1`, `true`, or `yes`.

```yaml
services:
  gatwy:
    environment:
      - ENABLE_MOONLIGHT=1
```

On start, the entrypoint downloads a pinned release into `/opt/moonlight-web` and Moonlight appears in the protocol picker. PIN pairing uses the Sunshine web UI.

When the variable is unset, Moonlight is hidden; stored Moonlight connections are kept and return if you enable it later.

See [THIRD_PARTY.md](THIRD_PARTY.md) for the license note and pinned release.

---

## 🔄 Updating

```bash
docker compose pull && docker compose up -d
```

---

## 🛠️ Building from Source

```bash
git clone https://github.com/kotoxie/gatwy && cd gatwy

# With Docker
docker compose up --build -d

# Without Docker (Node.js 20+)
npm install && npm run build && npm start
```

---

## 📄 License

[MIT](LICENSE)
