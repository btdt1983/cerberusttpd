# Cerberusttpd

A self-contained file server in Go: sign in with your Linux account (PAM) plus
TOTP 2FA, HTTPS with its own local CA, HTTP/3, resumable downloads and uploads
(tus), file management and a live sidebar with bandwidth, online users and
server load.

## How it works

Three kinds of processes, so that permissions are right:

| Process | Runs as | Job |
|---|---|---|
| `run` | root | opens the ports, keeps the CA key, PAM, 2FA, starts the others |
| `serve` | `cerberusttpd` | HTTP/1.1, HTTP/2, HTTP/3, pages; has no access to files or keys |
| `worker` | the signed-in user | all file actions; the kernel decides what is allowed |

## Installing

    make rpm                              # builds rpmbuild/RPMS/x86_64/cerberusttpd-*.rpm
    sudo rpm -Uvh rpmbuild/RPMS/x86_64/cerberusttpd-*.rpm
    # or without an RPM: sudo make install

    sudo firewall-cmd --permanent --add-service=cerberusttpd && sudo firewall-cmd --reload
    sudo systemctl enable --now cerberusttpd

The binary deliberately lives in `/opt/cerberusttpd`: there it keeps the default
SELinux label (`usr_t`) and systemd starts it as `unconfined_service_t`.
Do not move it to `/usr/sbin` (it would become `init_t` and signing in breaks).

Logs: `journalctl -u cerberusttpd -f`. Settings: `/etc/cerberusttpd/cerberusttpd.conf`.

## First use

1. Open `https://<server>:8443/` and import the CA once
   (`/.well-known/cerberusttpd/ca.crt` for Windows/Android, `ca.pem` for Linux/macOS).
   Firefox has its own certificate store.
2. Sign in with your Linux account and set up 2FA (QR code or key).
   **Save the recovery codes.**

## Administration

- Reset a user's 2FA: `sudo /opt/cerberusttpd/cerberusttpd 2fa-reset -config /etc/cerberusttpd/cerberusttpd.conf <user>`
- Administrator = member of the `wheel` group.
- A user can sign in if their uid is >= `min-uid`, PAM allows the account and 2FA is correct.
- Faillock: 10 failed attempts lock an account for 5 minutes (`/etc/pam.d/cerberusttpd`);
  on top of that the app throttles per IP + user.

## Backup (important)

Back up `/var/lib/cerberusttpd`, at least:

- `ca/ca-key.pem` and `ca/ca.pem`: without them everyone has to trust the CA again.
- `2fa.key` together with `2fa/`: without the key the 2FA data is unreadable.

Anyone who has `ca-key.pem` or `2fa.key` can forge certificates or 2FA codes: keep them safe.
The RPM never removes `/var/lib/cerberusttpd` or the `cerberusttpd` user.

## Ports and TLS

By default Cerberusttpd listens on port 8443 (`addr` in the config): TCP for HTTP/1.1 and
HTTP/2, UDP for HTTP/3. Both must be reachable; the firewalld service opens them. Because it
does not use 80 or 443, it can run next to a web server such as nginx.

`tls = local` (the default) uses the private CA described above. `tls = acme` is meant for a
public domain with Let's Encrypt (via certmagic) but is **experimental and untested**: it
answers TLS-ALPN-01 challenges on the TLS listener, so that listener has to be reachable on
port 443, and HTTP-01 is not possible because the unprivileged `serve` process cannot open
port 80. If another server already holds port 443, you would need to pass TLS traffic for
your domain through to Cerberusttpd by SNI (for example with the nginx `stream` module).
DNS-01, which needs no open port, is not implemented.

## Limitations

- Bandwidth counts HTTP content only, not TLS/QUIC overhead or headers.
- An open page does not keep your session alive: after 30 minutes without a click you are signed out.
- Deleting is permanent (no trash); moving is not possible yet.
- SELinux: runs as `unconfined_service_t`. A dedicated confining policy needs
  `selinux-policy-devel` and has not been written yet.

## License

Copyright (C) 2026 David Bauer

GNU Affero General Public License, version 3 (AGPL-3.0-only), see `LICENSE`
(in the RPM: `/usr/share/licenses/cerberusttpd/LICENSE`).

Note for modified versions that you offer as a network service: section 13 of the AGPL
requires you to offer the corresponding source code to the users of that service.
The direct dependencies (quic-go, certmagic, go-qrcode, msteinert/pam, x/sys) are licensed
under MIT, BSD or Apache-2.0.
