# securegate

Expose local HTTP services on your own domain through SSH, like
[sish](https://github.com/antoniomika/sish) or ngrok, managed from a web
dashboard or an interactive terminal wizard.

```bash
ssh -p 2222 -R myapp:80:localhost:3000 gate.example.com
# → https://myapp.gate.example.com now serves your localhost:3000
```

- **Subdomains and SSH keys are registered in the dashboard** (or with
  `securegate config`). Each subdomain has its own authorized SSH keys: a key
  can only open tunnels on the subdomains it was added to, and unknown keys
  are rejected during the SSH handshake.
- **Sign-in without passwords:** a one-time code sent by email, then
  passkeys (fingerprint, face or device PIN). GitHub and any OpenID Connect
  provider can be added as optional sign-in methods.
- **Access control per subdomain:** *public*, *signed-in users* or *private*
  (owner only). Protected tunnels send visitors to sign in and work with any
  app behind them; the app never sees securegate's cookies.
- **Live view** of every tunnel: client address, key, requests and traffic,
  with a disconnect button. Removing a key or disabling a user closes their
  tunnels at once. The SSH session prints every request, like sish.
- **Single static binary** with SQLite storage and automatic HTTPS (Let's
  Encrypt) — or Docker, or Kubernetes with Traefik.

## How it works

```
 browser ──HTTPS──▶ securegate ──SSH channel──▶ ssh -R client ──▶ localhost:3000
                     │  myapp.gate.example.com → tunnel "myapp"
                     │  gate.example.com       → dashboard
```

The dashboard is served on the host of `public_url`; every direct subdomain
of it is a tunnel. When a client runs `ssh -R myapp:80:localhost:3000`,
securegate checks that the key is authorized for `myapp` and routes
`myapp.<domain>` to that SSH connection. Each HTTP request (WebSockets and
streaming included) opens a channel back to the client.

The `80` only tells securegate that this is an HTTP tunnel: OpenSSH requires
a port there. The subdomain can also come from the SSH user name, or be left
out when the key belongs to a single subdomain:

```bash
ssh -p 2222 -R 80:localhost:3000 myapp@gate.example.com
ssh -p 2222 -R 80:localhost:3000 gate.example.com
```

A new connection for a subdomain replaces the previous one, so reconnecting
(e.g. with `autossh -M 0`) takes over at once.

## Getting started

You need a domain where both `gate.example.com` and `*.gate.example.com`
point to the server.

```bash
go build -o securegate ./cmd/securegate     # Go 1.26+
sudo ./securegate config                     # interactive setup
sudo ./securegate service --install          # run it as a systemd service
```

Then sign in at `https://gate.example.com` with an administrator email,
register a subdomain, paste your public key (`~/.ssh/id_ed25519.pub`) and
connect with the `ssh -R` command the dashboard shows.

### Commands

| Command | |
|---|---|
| `securegate config` | Interactive wizard. Creates the configuration on first run; then manages subdomains, SSH keys, users and server settings. `--accessible` uses plain prompts (also for screen readers and scripts: it accepts piped answers). |
| `securegate start` | Run in the foreground. `--detached` runs in the background, logging to `<data_dir>/securegate.log`. |
| `securegate stop` / `status` | Stop a detached server / show whether it runs, with live counters. |
| `securegate service --install` | Install a hardened systemd service: binary in `/usr/local/bin`, a dedicated `securegate` user owning the data directory, `CAP_NET_BIND_SERVICE` for ports 80/443. `--uninstall` and `--status` too; `--dry-run` shows what would happen. |

Every command takes `--config FILE`; otherwise `$SECUREGATE_CONFIG`,
`./securegate.yaml` or `/etc/securegate/securegate.yaml` is used.

`securegate config` and `status` talk to the running server through a Unix
socket in the data directory (mode 0600: root or the service user), so changes
apply to live tunnels immediately.

## Deployment

### Binary and systemd

As above: `securegate config`, then `securegate service --install`. Secrets
can stay out of the configuration file: write `${SMTP_PASSWORD}` and put
`SMTP_PASSWORD=...` in `/etc/securegate/securegate.env`, which systemd reads
as root.

### Docker

The image keeps the configuration and all state in `/data`:

```bash
docker volume create securegate
docker run -it --rm -v securegate:/data ghcr.io/jgermade/securegate config
docker run -d --name securegate --restart unless-stopped -v securegate:/data \
  -p 80:80 -p 443:443 -p 2222:2222 ghcr.io/jgermade/securegate
docker exec -it securegate securegate config     # manage subdomains, keys and users
```

The image is published to `ghcr.io/jgermade/securegate` when a `v*` tag is
pushed; until then, build it with `docker build -t securegate .`. See
[`deploy/docker/compose.yaml`](deploy/docker/compose.yaml) for Compose.
With Docker alone, choose Let's Encrypt in the setup: securegate gets a
certificate for each registered subdomain on demand, so no DNS challenge is
needed.

### Kubernetes with Traefik

[`deploy/helm/securegate`](deploy/helm/securegate) installs securegate behind
Traefik v3:

- an `IngressRoute` for `gate.example.com` and its subdomains (TLS from a
  Traefik resolver with a DNS-01 challenge, an existing wildcard secret, or
  cert-manager);
- an `IngressRouteTCP` on a dedicated Traefik entry point for SSH, with the
  PROXY protocol so securegate sees client addresses — or a `LoadBalancer`
  Service instead.

```bash
helm install securegate deploy/helm/securegate \
  --set domain=gate.example.com \
  --set traefik.tls.certResolver=letsencrypt-dns \
  --set secretEnv.SMTP_PASSWORD=... \
  -f my-values.yaml      # config.auth.admins, SMTP settings...
kubectl exec -it deploy/securegate -- securegate config
```

Traefik needs a TCP entry point for SSH, e.g. in the Traefik chart's values:

```yaml
ports:
  ssh:
    port: 2222
    expose: {default: true}
    exposedPort: 2222
    protocol: TCP
```

securegate runs as a single replica: tunnels live in the memory of the
process that holds the SSH connections.

## Configuration

See [`securegate.example.yaml`](securegate.example.yaml) for every option.
Highlights:

- `public_url`: the dashboard URL. Tunnels live on its subdomains.
- `http.tls`: Let's Encrypt (`acme`) or a wildcard certificate
  (`cert_file`/`key_file`). Leave it out behind a TLS-terminating proxy and
  set `http.trust_proxy_headers`.
- `auth.email`: SMTP settings for sign-in codes (`log_only: true` writes them
  to the log for local development).
- `auth.providers`: optional `github` or `oidc` providers (Google, GitLab,
  Microsoft Entra ID, Keycloak, Authentik...). Their callback URL is
  `<public_url>/auth/<id>/callback`.
- `auth.admins`, `auth.allowed_emails`, `auth.allowed_domains`,
  `auth.allow_everyone`: who may sign in.
- `ssh.proxy_protocol`: expect a PROXY protocol header from a load balancer.

For local development, `*.localhost` resolves to 127.0.0.1 in browsers:

```yaml
public_url: http://localhost:8080
auth:
  admins: [you@example.com]
  email: {log_only: true}
```

## Security notes

- **SSH:** public-key authentication only; the key is checked again for every
  forward, so revoking it takes effect immediately. Local forwarding
  (`ssh -L`) and other channel types are refused.
- **Accounts** are identified by verified email. Email codes are 6 digits,
  single use, valid 10 minutes, bound to the browser that asked for them,
  burned after 5 wrong guesses and rate limited per address and IP. The
  response is the same whether or not an address may sign in, and no email is
  sent to addresses that may not.
- **Passkeys** require user verification. Tunnel subdomains may claim the same
  WebAuthn RP ID as the dashboard, so assertions are only accepted from the
  dashboard's exact origin; challenges are single use.
- **Dashboard:** server-side sessions (only a hash of the token is stored),
  `__Host-` cookies over HTTPS, CSRF tokens plus an `Origin` check on every
  state change (tunnels are same-site with the dashboard, so SameSite cookies
  alone are not enough), and a strict Content-Security-Policy.
- **Protected tunnels:** the dashboard issues a short-lived, single-use,
  host-bound token that the tunnel host exchanges for a host-only, HttpOnly
  cookie tied to the dashboard session. Signing out revokes access to every
  tunnel. securegate's cookies are stripped before requests reach the app.
- **OAuth:** authorization code flow with PKCE, state and (OIDC) nonce checks.

## Development

```bash
go test -race ./...
```

`internal/e2e` runs the whole system: SSH clients opening tunnels, browsers
signing in with email codes, a software WebAuthn authenticator and a fake
OpenID Connect provider, and the configuration wizard against a live admin
socket.

## Roadmap

- TCP tunnels on dedicated ports.
- Sharing private subdomains with specific users.
- Custom domains (CNAME to a subdomain).
- Request inspector in the dashboard.
