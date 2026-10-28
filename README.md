# securegate

Expose local HTTP services on your own domain through SSH, like
[sish](https://github.com/antoniomika/sish) or ngrok, with a web dashboard
behind OAuth sign-in.

```bash
ssh -p 2222 -R myapp:80:localhost:3000 gate.example.com
# → https://myapp.gate.example.com now serves your localhost:3000
```

- **Subdomains and SSH keys are managed in the dashboard.** Users sign in with
  GitHub or any OpenID Connect provider, register subdomains and authorize SSH
  public keys per subdomain. A key can only open tunnels on the subdomains it
  was added to; unknown keys are rejected during the SSH handshake.
- **Access control per subdomain:** *public*, *signed-in users* (anyone allowed
  to sign in) or *private* (only the owner). Protected tunnels redirect
  visitors to sign in and work with any app behind them; the app never sees
  securegate's cookies.
- **Live view:** connected client, key used, requests and traffic, with a
  disconnect button. Removing a key or disabling a user closes their tunnels.
- **Request log in your terminal**, like sish: the SSH session prints every
  request served through the tunnel.
- **Single static binary**, SQLite storage, optional automatic HTTPS
  (Let's Encrypt) for the dashboard and every registered subdomain.

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
streaming included) opens a `forwarded-tcpip` channel back to the client.

The subdomain is taken from the bind address of `-R`. When it is omitted
(`ssh -R 80:localhost:3000 ...`), securegate uses the SSH user name if it is
an authorized subdomain, or the key's only subdomain. A new connection for a
subdomain replaces the previous one, so reconnecting (e.g. with
`autossh -M 0`) takes over immediately.

## Running it

Requirements: Go 1.26+, a domain where both `gate.example.com` and
`*.gate.example.com` point to the server.

```bash
go build -o securegate ./cmd/securegate
cp securegate.example.yaml securegate.yaml   # then edit it
GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=... ./securegate -config securegate.yaml
```

Or with Docker:

```bash
docker build -t securegate .
docker run -p 80:80 -p 443:443 -p 2222:2222 -v securegate-data:/data -v $PWD/securegate.yaml:/etc/securegate/securegate.yaml:ro -e GITHUB_CLIENT_ID -e GITHUB_CLIENT_SECRET securegate
```

Set `data_dir: /data` in the configuration when using the container.

See [`securegate.example.yaml`](securegate.example.yaml) for every option.
Highlights:

- `public_url`: the dashboard URL. Tunnels live on its subdomains.
- `http.tls`: a wildcard certificate (`cert_file`/`key_file`) or `acme`
  for on-demand Let's Encrypt certificates. Leave it out when a reverse proxy
  terminates TLS.
- `auth.providers`: `github` or `oidc` (Google, GitLab, Microsoft Entra ID,
  Keycloak, Authentik...). The OAuth callback URL is
  `<public_url>/auth/<id>/callback`.
- `auth.admins`, `auth.allowed_emails`, `auth.allowed_domains`,
  `auth.allow_everyone`: who may sign in. Only verified emails are accepted.
- `${VAR}` in values is replaced with environment variables.

### Local development

`*.localhost` resolves to 127.0.0.1 in browsers, so a dashboard on
`http://localhost:8080` serves tunnels on `http://<name>.localhost:8080`:

```yaml
public_url: http://localhost:8080
ssh:
  listen: "127.0.0.1:2222"
```

## Security notes

- SSH: public-key authentication only; keys are checked again for every
  forward, so revoking a key takes effect immediately. Local forwarding
  (`ssh -L`) and other channel types are refused, and only HTTP forwards on
  registered subdomains are allowed.
- Dashboard: server-side sessions (only a hash of the token is stored),
  `__Host-` cookies over HTTPS, CSRF tokens plus an `Origin` check on every
  form (tunnel subdomains are same-site with the dashboard, so SameSite
  cookies alone are not enough), and a strict Content-Security-Policy.
- OAuth: authorization code flow with PKCE, state and (OIDC) nonce checks.
- Protected tunnels: the dashboard issues a short-lived, single-use, host-bound
  token that the tunnel host exchanges for a host-only, HttpOnly cookie tied to
  the dashboard session. Signing out revokes access to every tunnel.
- securegate cookies are stripped before requests reach the tunnelled app.

## Development

```bash
go test -race ./...
```

`internal/e2e` runs the whole system: a real SSH server and clients opening
tunnels, and browsers signing in through a fake OpenID Connect provider.

## Roadmap

- TCP tunnels on dedicated ports.
- Sharing private subdomains with specific users.
- Custom domains (CNAME to a subdomain).
- Request inspector in the dashboard.
