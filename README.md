# Cerberusttpd

A self-contained file server in Go: sign in with your Linux account (PAM) plus
TOTP 2FA, HTTPS with its own local CA or an automatic Let's Encrypt certificate for your
domain (`domain = files.example.com` is enough), HTTP/3, resumable downloads and uploads
(tus), file management, photo albums with a masonry gallery, an audit log, optional Microsoft
(Entra ID) single sign-on, and a live sidebar with bandwidth, online users and server load.

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

Albums are on by default. Set `albums = off` in the settings file to switch them off completely:
no album or thumbnail pages, no *Make a photo album* button, and folders stay plain file lists.

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

## Single sign-on (Microsoft Entra ID)

Optional. Besides the Linux password, people can sign in with their organisation's Microsoft
account (Microsoft Entra ID, formerly Azure AD): the *Sign in with Microsoft* button appears
on the login page and Microsoft does the password and the second factor. Without the settings
below nothing changes, and passwords keep working next to it.

> **Status: new and not yet verified against a live Microsoft tenant.** It is tested against a
> simulated provider (token checks, mapping, browser flow, configuration), like the automatic
> certificates were at first. If you try it, please open an issue with what worked or did not;
> the troubleshooting list below is based on Microsoft's documented behaviour.

### What you need

- A working HTTPS address with a certificate browsers trust, for example `tls = acme` (see
  *Ports and TLS*). Microsoft only sends people back to an `https` address.
- A Microsoft Entra tenant, and a role that may register applications (Global Administrator or
  Application Developer), or ask your IT department to do step 1 for you.
- The people who will sign in must exist in that tenant **and** have a Linux account on the
  server. This is by design: cerberusttpd never creates accounts.

### Step 1: register the application in Microsoft Entra

1. Sign in to <https://entra.microsoft.com>, then *Entra ID* → *App registrations* → *New registration*.
2. *Name*: anything, for example `Cerberusttpd`.
3. *Supported account types*: **Accounts in this organizational directory only (Single tenant)**.
4. *Redirect URI*: choose the platform **Web** and enter the address people use to reach the
   server plus `/oidc/callback`, for example `https://files.example.com/oidc/callback` (or
   `https://files.example.com:8443/oidc/callback` if you use port 8443). It must match exactly,
   including the port. Click *Register*.
5. On the *Overview* page copy the **Application (client) ID** and the **Directory (tenant) ID**.
   Both are GUIDs like `11111111-2222-3333-4444-555555555555`.
6. Go to *Certificates & secrets* → *Client secrets* → *New client secret*. Copy the **Value**
   right away (not the *Secret ID*); Microsoft shows it only once. Note the expiry date: when
   it passes, sign-in stops until you make a new secret and replace the file in step 2.
7. Find each person's **Object ID** under *Entra ID* → *Users* → the user. You need it in step 3
   (their user name, such as `jan@example.com`, works too, but see below).

No API permissions are needed: the default *User.Read* is enough.

### Step 2: put the secret on the server

The secret file must belong to root and be readable by root only. Type the value without it
ending up in your shell history:

    umask 077
    read -rsp 'Client secret: ' S; echo
    printf '%s' "$S" > /etc/cerberusttpd/oidc-secret; unset S
    chown root:root /etc/cerberusttpd/oidc-secret

### Step 3: say who may sign in as whom

Create `/etc/cerberusttpd/oidc-users`, owned by root and not writable by anyone else
(`chown root:root` and `chmod 600`), one line per person, `identity = linux user`:

    # Microsoft identity            = Linux account
    oid:00000000-0000-0000-0000-000000000000 = jan
    piet@example.com                         = piet

- `oid:<Object ID>` is the recommended form: it never changes. A user name (`jan@example.com`)
  is also accepted (case does not matter), but Microsoft documents it as something an
  administrator can change or reuse, so it is weaker. If both match, the Object ID wins.
- Only people listed here can sign in. Someone who signs in correctly with Microsoft but is not
  listed gets a refusal, and the audit log says `result=unmapped idp_user=<who>` so you can see
  whom to add. The file is read at every sign-in: edits apply immediately.
- The Linux account must exist, be an ordinary user (uid at least `min-uid`, never root) and
  pass the PAM account checks.

### Step 4: switch it on

Add to `/etc/cerberusttpd/cerberusttpd.conf` (all five lines are needed together):

    oidc-issuer = https://login.microsoftonline.com/<Directory (tenant) ID>/v2.0
    oidc-client-id = <Application (client) ID>
    oidc-client-secret-file = /etc/cerberusttpd/oidc-secret
    oidc-users = /etc/cerberusttpd/oidc-users
    oidc-redirect-url = https://files.example.com/oidc/callback
    #oidc-label = Microsoft        # the name on the button

Use the tenant **ID** (the GUID), not a domain such as `contoso.onmicrosoft.com`. Then
`systemctl restart cerberusttpd` (this signs everyone out). A mistake in the settings, or in the
permissions of the two files, is reported at start-up: see `journalctl -u cerberusttpd`.

### Step 5: try it

Open the site in a private window. Under the password form there is now *Sign in with
Microsoft*. After signing in at Microsoft you land in the file list as the mapped Linux user.
Check `journalctl -u cerberusttpd | grep msg=audit`: a successful sign-in shows `auth=oidc`.

### If it does not work

Microsoft's own error page (at login.microsoftonline.com) shows an `AADSTS` code; problems after
that show only a general message here, with the details in `journalctl -u cerberusttpd`
(search for `oidc`).

| What you see | Likely cause |
| --- | --- |
| Microsoft: `AADSTS50011` redirect URI mismatch | The URI in step 1 differs from `oidc-redirect-url` (port, `http`/`https`, trailing slash). |
| Microsoft: `AADSTS700016` application not found | Wrong client ID, or the tenant ID does not belong to that application. |
| Microsoft: `AADSTS65001` consent required | An administrator must click *Grant admin consent* under *API permissions*. |
| Microsoft: `AADSTS50105` user not assigned | The application requires assignment: add the user under *Enterprise applications* → *Users and groups*. |
| Here: "Signing in is not possible right now" | The server could not reach Microsoft, or the issuer is wrong (domain instead of tenant ID). Journal: `oidc discovery`. |
| Here: "Signing in with Microsoft failed" | Journal says why: `AADSTS7000215` invalid client secret (you used the *Secret ID*, or copied it wrongly), `AADSTS7000222` secret expired, or a token check failed. |
| Here: "not linked to a user on this server" | The person is not in `oidc-users`, or the Linux account is missing, is root or has a uid below `min-uid`. |
| Here: "Signing in with Microsoft failed", journal: `account not valid` | The Linux account is expired or its password has expired (PAM account check). |

### Good to know

- **Skips TOTP.** A Microsoft sign-in does not ask for the cerberusttpd authenticator code,
  whatever `2fa` says; require MFA in Microsoft (Conditional Access / security defaults). It
  does not check how Microsoft authenticated the person.
- **Locking an account.** `usermod -L` (locked password) does *not* stop single sign-on. Remove the
  person from `oidc-users`, or expire the account (`chage -E 0 <user>`).
- **Sign out** ends the session on this server only, not at Microsoft.
- **Limits.** One provider; no automatic account creation; no group or role mapping. Other
  OpenID Connect providers that send a `preferred_username` claim (Keycloak, for example) should
  work with the same settings but are untested. Providers that only give an e-mail address
  (Google) cannot be used: an e-mail address is never trusted as an identity.
- **How it stays safe.** The root process does the entire sign-in itself: the exchange of the
  code using the secret (with PKCE), the token's signature, issuer (which pins your tenant),
  audience, expiry and nonce, and the choice of Linux account. The network process only carries
  the browser's code; it never sees the secret and cannot pick the user, so compromising it
  does not let anyone sign in as somebody else.

## Audit log

Security-relevant events are written to the journal, one line each, with `msg=audit`:

    journalctl -u cerberusttpd | grep msg=audit

    event=login user=jan ip=192.0.2.7 auth=password+totp result=ok
    event=download user=jan ip=192.0.2.7 auth=password+totp result=ok path=docs/report.pdf size=48211 range=""

Fields: `event`, `user` (the typed name on a failed login), `ip`, `auth` (`password` or
`password+totp`), `result` (`ok`, or why not: `denied`, `throttled`, `forbidden`, `exists`, ...)
and event details such as `path`. Logged: sign-in (success, failure, throttled, second
factor), sign-out, downloads (a `range` marks a partial read), uploads, new folders, renames
(`to`), deletes, refused access, and album changes. Not logged: directory listings,
thumbnails and the live sidebar. Values are quoted, so a file name with a newline cannot
forge a line. Passwords, codes and session tokens never appear. The journal is the place to
keep it safe: forward it to a log server if the host itself is not trusted.

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
