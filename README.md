# gate2sky

**[gate2sky.github.io](https://gate2sky.github.io/)** ·
[releases](https://github.com/gate2sky/gate2sky.github.io/releases)

```sh
curl -fsSL https://gate2sky.github.io/setup.sh | sh
```

Expose local HTTP services on your own domain through SSH, like
[sish](https://github.com/antoniomika/sish) or ngrok, managed from a web
dashboard or an interactive terminal wizard.

```bash
ssh -p 2222 -R myapp:80:localhost:3000 gate.example.com
# → https://myapp.gate.example.com now serves your localhost:3000
```

- **Subdomains and SSH keys are registered in the dashboard** (or with
  `gate2sky config`). Each subdomain has its own authorized SSH keys: a key
  can only open tunnels on the subdomains it was added to, and unknown keys
  are rejected during the SSH handshake.
- **Sign-in without passwords:** a one-time code sent by email, then
  passkeys (fingerprint, face or device PIN). GitHub and any OpenID Connect
  provider can be added as optional sign-in methods.
- **Access control per subdomain:** *public*, *signed-in users* or *private*
  (owner only). Protected tunnels send visitors to sign in and work with any
  app behind them; the app never sees gate2sky's cookies.
- **Live view** of every tunnel: client address, key, requests and traffic,
  with a disconnect button. Removing a key or disabling a user closes their
  tunnels at once. The SSH session prints every request, like sish.
- **Single static binary** with SQLite storage and automatic HTTPS (Let's
  Encrypt) — or Docker, or Kubernetes with Traefik.

## How it works

```
 browser ──HTTPS──▶ gate2sky ──SSH channel──▶ ssh -R client ──▶ localhost:3000
                     │  myapp.gate.example.com → tunnel "myapp"
                     │  gate.example.com       → dashboard
```

The dashboard is served on the host of `public_url`; every direct subdomain
of it is a tunnel. When a client runs `ssh -R myapp:80:localhost:3000`,
gate2sky checks that the key is authorized for `myapp` and routes
`myapp.<domain>` to that SSH connection. Each HTTP request (WebSockets and
streaming included) opens a channel back to the client.

The `80` only tells gate2sky that this is an HTTP tunnel: OpenSSH requires
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
point to the server. Then, on Linux or macOS:

```sh
curl -fsSL https://gate2sky.github.io/setup.sh | sh
```

Without curl, `wget -qO- https://gate2sky.github.io/setup.sh | sh` does the
same: the installer then downloads with wget too.

The installer downloads the release for your machine, checks it against the
release's `SHA256SUMS`, runs it once before it replaces anything, opens the
setup wizard and, on Linux with systemd, installs the service. Run it again to
update (the service is restarted), reconfigure or uninstall:

```sh
curl -fsSL https://gate2sky.github.io/setup.sh | sh -s -- reinstall
curl -fsSL https://gate2sky.github.io/setup.sh | sh -s -- configure
curl -fsSL https://gate2sky.github.io/setup.sh | sh -s -- uninstall --purge
```

Every release archive, the Docker image and the Helm chart also carry a
build provenance attestation signed by GitHub: it proves they were built by
this repository's release workflow, from the tagged commit. With the
[GitHub CLI](https://cli.github.com/):

```sh
gh attestation verify gate2sky-linux-amd64.tar.gz --repo gate2sky/gate2sky.github.io
gh attestation verify oci://ghcr.io/gate2sky/gate2sky:latest --repo gate2sky/gate2sky.github.io
```

| Option | |
| --- | --- |
| `--dir DIR` | Where the binary goes. Default `/usr/local/bin`, or `GATE2SKY_INSTALL_DIR`. |
| `--version TAG` | A release such as `v0.2.0`. Default the latest, or `GATE2SKY_VERSION`. |
| `--config FILE` | Default `/etc/gate2sky/gate2sky.yaml`. |
| `--no-service` | Neither install nor restart the systemd service. |
| `--purge` | With `uninstall`: also delete the configuration, data and service user. |
| `-y`, `--yes` | Do not ask; `--purge` needs it when there is no terminal. |
| `GATE2SKY_DOWNLOAD_URL` | A directory with `gate2sky-<os>-<arch>.tar.gz` and `SHA256SUMS`, used instead of GitHub. |

From source:

```bash
go build -o gate2sky ./cmd/gate2sky     # Go 1.26+
sudo ./gate2sky config                     # interactive setup
sudo ./gate2sky service --install          # run it as a systemd service
```

Then sign in at `https://gate.example.com` with an administrator email,
register a subdomain, paste your public key (`~/.ssh/id_ed25519.pub`) and
connect with the `ssh -R` command the dashboard shows.

### Commands

| Command | |
|---|---|
| `gate2sky config` | Interactive wizard. Creates the configuration on first run; then manages subdomains, SSH keys, users and server settings. `--accessible` uses plain prompts (also for screen readers and scripts: it accepts piped answers). |
| `gate2sky start` | Run in the foreground. `--detached` runs in the background, logging to `<data_dir>/gate2sky.log`. |
| `gate2sky stop` / `status` | Stop a detached server / show whether it runs, with live counters. |
| `gate2sky service --install` | Install a hardened systemd service: binary in `/usr/local/bin`, a dedicated `gate2sky` user owning the data directory, `CAP_NET_BIND_SERVICE` for ports 80/443. `--uninstall` and `--status` too; `--dry-run` shows what would happen. |

Every command takes `--config FILE`; otherwise `$GATE2SKY_CONFIG`,
`./gate2sky.yaml` or `/etc/gate2sky/gate2sky.yaml` is used.

`gate2sky config` and `status` talk to the running server through a Unix
socket in the data directory (mode 0600: root or the service user), so changes
apply to live tunnels immediately.

## Deployment

### Binary and systemd

As above: `gate2sky config`, then `gate2sky service --install`. Secrets
can stay out of the configuration file: write `${SMTP_PASSWORD}` and put
`SMTP_PASSWORD=...` in `/etc/gate2sky/gate2sky.env`, which systemd reads
as root.

### Docker

The image keeps the configuration and all state in `/data`:

```bash
docker volume create gate2sky
docker run -it --rm -v gate2sky:/data ghcr.io/gate2sky/gate2sky config
docker run -d --name gate2sky --restart unless-stopped -v gate2sky:/data \
  -p 80:80 -p 443:443 -p 2222:2222 ghcr.io/gate2sky/gate2sky
docker exec -it gate2sky gate2sky config     # manage subdomains, keys and users
```

Every release publishes the image to `ghcr.io/gate2sky/gate2sky`; before
the first one, build it with `docker build -t gate2sky .`. See
[`deploy/docker/compose.yaml`](deploy/docker/compose.yaml) for Compose.
With Docker alone, choose Let's Encrypt in the setup: gate2sky gets a
certificate for each registered subdomain on demand, so no DNS challenge is
needed.

### Kubernetes with Traefik

[`deploy/helm/gate2sky`](deploy/helm/gate2sky) installs gate2sky behind
Traefik v3. Every release publishes it to `oci://ghcr.io/gate2sky/charts`
and to the classic repository `https://gate2sky.github.io/charts` (for tools
without OCI support, such as helm-dashboard), so there is nothing to clone
(from a clone, `deploy/helm/gate2sky` works the same):

- an `IngressRoute` for `gate.example.com` and its subdomains (TLS from a
  Traefik resolver with a DNS-01 challenge, an existing wildcard secret, or
  cert-manager);
- an `IngressRouteTCP` on a dedicated Traefik entry point for SSH, with the
  PROXY protocol so gate2sky sees client addresses — or a `LoadBalancer`
  Service instead.

```bash
helm install gate2sky oci://ghcr.io/gate2sky/charts/gate2sky \
  --set domain=gate.example.com \
  --set traefik.tls.certResolver=letsencrypt-dns \
  --set secretEnv.SMTP_PASSWORD=... \
  -f my-values.yaml      # config.auth.admins, SMTP settings...
kubectl exec -it deploy/gate2sky -- gate2sky config
```

Or from the classic repository:

```bash
helm repo add gate2sky https://gate2sky.github.io/charts
helm install gate2sky gate2sky/gate2sky --set domain=gate.example.com ...
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

gate2sky runs as a single replica: tunnels live in the memory of the
process that holds the SSH connections.

## Configuration

See [`gate2sky.example.yaml`](gate2sky.example.yaml) for every option.
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
  alone are not enough), and a strict Content-Security-Policy: scripts only
  from the dashboard itself or with the page's per-response nonce, never
  `eval`, no inline styles, no connections to other hosts.
- **Protected tunnels:** the dashboard issues a short-lived, single-use,
  host-bound token that the tunnel host exchanges for a host-only, HttpOnly
  cookie tied to the dashboard session. Signing out revokes access to every
  tunnel. gate2sky's cookies are stripped before requests reach the app.
- **OAuth:** authorization code flow with PKCE, state and (OIDC) nonce checks.

## Development

```bash
go test -race ./...
```

`scripts/setup-check.sh` walks the installer against builds of this tree:
install, update, reinstall, a bad checksum, uninstall and `--purge`.

The dashboard is a [jq79](https://github.com/jgermade/jq79) app in
[`internal/web/ui`](internal/web/ui): single-file `.html` components loaded
at runtime, with no build step, embedded in the binary and talking to a JSON
API under `/api`. The server sends one page shell for every dashboard path,
with a fresh CSP nonce and the session's boot data; jq79 builds each
component's functions as scripts carrying that nonce
(`Component79.safeEval({ nonce: true })`). Edit a component and rebuild the
binary to see it.

`internal/e2e` runs the whole system: SSH clients opening tunnels, browsers
signing in with email codes, a software WebAuthn authenticator and a fake
OpenID Connect provider, and the configuration wizard against a live admin
socket.

### Builds and releases

Two workflows:

- **Build** (`.github/workflows/build.yml`) runs on every push: downloads
  and verifies the dependencies, runs the tests, builds
  `gate2sky-<os>-<arch>.tar.gz` for Linux and macOS (amd64, arm64), walks
  the installer against this tree, builds the Docker image, renders the Helm
  chart and checks the landing.
- **Release** (`.github/workflows/release.yml`) is started by hand from the
  Actions tab on the default branch, choosing `patch`, `minor` or `major`. It
  raises [`VERSION`](VERSION) and the Helm chart's version, commits and tags
  `vX.Y.Z`, runs Build on that commit, creates the GitHub release with the
  binaries, `SHA256SUMS` (what `setup.sh` installs) and the Helm chart, pushes
  the Docker image and the chart to GHCR, attests the provenance of all of
  them, and deploys [`pages/`](pages/) — the landing and `setup.sh` — to
  GitHub Pages, with the Helm repository's `charts/index.yaml`, which adds
  each release's chart to the one already served. `dry-run` builds everything
  and publishes nothing.

The landing is built from [`scripts/landing`](scripts/landing): edit
`template.html` (or the drawings in `hero.py`, whose geometry is computed),
then run `python3 scripts/landing/gen.py scripts/landing/template.html
pages/index.html`. Build checks that the two agree. The icon is
[`pages/favicon.svg`](pages/favicon.svg), the same file as the dashboard's
[`internal/web/ui/logo.svg`](internal/web/ui/logo.svg) (the landing's header
inlines it); after changing it, copy it to both and run `node
scripts/landing/icons.js`, which renders `favicon.ico` and
`apple-touch-icon.png` from it.

## Roadmap

- TCP tunnels on dedicated ports.
- Sharing private subdomains with specific users.
- Custom domains (CNAME to a subdomain).
- Request inspector in the dashboard.
