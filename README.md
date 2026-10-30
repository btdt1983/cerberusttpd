# Cerberusttpd

A self-contained file server in Go: sign in with your Linux account (PAM) plus
TOTP 2FA, HTTPS with its own local CA or an automatic Let's Encrypt certificate for your
domain (`domain = files.example.com` is enough), HTTP/3, resumable downloads and uploads
(tus), file management, photo albums with a masonry gallery and a live sidebar with bandwidth, online users and server load.

## How it works

Three kinds of processes, so that permissions are right:

| Process | Runs as | Job |
|---|---|---|
| `run` | root | opens the ports, keeps the CA key, PAM, 2FA, starts the others |
| `serve` | `cerberusttpd` | HTTP/1.1, HTTP/2, HTTP/3, pages; has no access to files or keys |
| `worker` | the signed-in user | all file actions; the kernel decides what is allowed |

## Installing

From the signed dnf repository (RHEL 9 and 10 and compatibles; packages and metadata are GPG-signed):

    sudo curl -o /etc/yum.repos.d/techhack.repo https://repo.techhack.nl/techhack.repo
    sudo dnf install cerberusttpd

Or build it yourself:

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

1. Open `https://<server>:8443/`. With the default private CA, import the CA once
   (`/.well-known/cerberusttpd/ca.crt` for Windows/Android, `ca.pem` for Linux/macOS;
   Firefox has its own certificate store). With a public domain (`tls = acme`, see
   [Ports and TLS](#ports-and-tls)) there is nothing to import.
2. Sign in with your Linux account and set up 2FA (QR code or key).
   **Save the recovery codes.**

## Photo albums

A folder with pictures can be made into an album: open it and use *Make a photo album*
(you need write access). From then on the folder opens as a masonry gallery with a
lightbox (arrow keys, swipe, full screen picture, links to the original and a download).
*Show as a list of files* on the album page gives the normal file list back.

- *Edit album* (on the album page, for folders you can write to) sets the title, a description,
  a caption per picture, the cover and the order: drag a row by its handle or use the arrows.
  The cover is shown next to the folder in the file list; album folders get an "album" label.
  *Remove album* deletes only the metadata file.
- An album is just a folder plus a small hidden file, `.cerberusttpd-album.json`, with the
  title, description, order and captions. The pictures are whatever images the folder
  holds, so uploading, renaming and deleting work as always. Delete the file to undo it.
- JPEG, PNG, GIF and WebP are shown. HEIC/HEIF and SVG are not (no safe decoder; SVG is
  active content). Photos rotated by the camera (EXIF orientation) are shown upright.
- Thumbnails and lightbox pictures are made by the worker, as the signed-in user, and cached in
  `~/.cache/cerberusttpd/thumbs/` in that user's own home (so it works for a shared or read-only
  `root`, and for administrators; it counts towards their quota; unused thumbnails are
  removed after 60 days). If that directory cannot be created, pictures are made on the fly
  for every request. Pictures over 100 MB or 60 megapixels are not decoded; a picture
  that cannot be decoded shows its file name instead.

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

`tls = local` (the default) uses the private CA described above. The shortest setup is one line in `/etc/cerberusttpd/cerberusttpd.conf`:

    domain = files.example.com

A domain implies `tls = acme` and `addr = :443` (set `tls` or `addr` yourself to override). Point
the domain's A record at the server and keep port 443 reachable over TCP and UDP. This works
when nothing else uses port 443; otherwise read on.

`tls = acme` gets a public Let's Encrypt certificate for your own domain (via certmagic), so
clients need no CA import. Point the domain's A record at the server; it does not have to be
reachable from the internet when you use DNS-01.

**Behind nginx (or another reverse proxy) that owns 80/443.** Optional: only needed when
something else already holds those ports. Keep cerberusttpd on 8443 and let it answer the
HTTP-01 challenge on a local port:

    # /etc/cerberusttpd/cerberusttpd.conf
    domain = files.example.com
    addr = :8443
    acme-http-addr = 127.0.0.1:8080

    # nginx: port 80 for this domain must be reachable from the internet
    server {
        listen 80;
        server_name files.example.com;
        location /.well-known/acme-challenge/ {
            proxy_pass http://127.0.0.1:8080;
            proxy_set_header Host $host;      # the challenge is looked up by host name
        }
        location / { return 301 https://$host:8443$request_uri; }
    }

The local port only listens while a certificate is being issued or renewed. `acme-http-addr`
and `dns-provider` are alternatives.

**DNS-01.** Set `dns-provider = cloudflare` or `transip` and put the credentials in
a file that only root can read (`chmod 600`), referenced by `dns-credentials`:

    # /etc/cerberusttpd/dns.conf  (cloudflare)
    api-token = <API token with Zone:DNS:Edit>

    # /etc/cerberusttpd/dns.conf  (transip)
    login = <username>
    private-key-file = /etc/cerberusttpd/transip.key

    # /etc/cerberusttpd/cerberusttpd.conf
    tls = acme
    domain = files.example.com
    acme-email = you@example.com
    dns-provider = cloudflare
    dns-credentials = /etc/cerberusttpd/dns.conf

The credentials never appear on a command line: `run` reads the file and passes the values to
the network process over a pipe. DNS-01 needs no inbound port, so it works on 8443 while nginx
keeps 80 and 443. Try it first with `acme-ca = staging` (untrusted test certificates, no rate
limit trouble) and switch to `production` when it works.

Without `dns-provider` or `acme-http-addr` it uses TLS-ALPN-01, which needs the TLS listener
reachable on port 443 (cerberusttpd itself never opens port 80: the unprivileged `serve` process
cannot). If another server holds 443 and you do not want a proxy for port 80, you would have to
pass TLS for your domain through by SNI (nginx `stream` module).

All `tls = acme` variants are **new and not yet verified against a live domain**.

## Limitations

- Bandwidth counts everything the server reads and writes on its sockets, so TLS and QUIC
  overhead, handshakes and HTTP headers are included (IP/TCP/UDP headers and TCP
  retransmissions are not). The sidebar's own live stream counts too: a few hundred bytes
  per second for each open page.
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
