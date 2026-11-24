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

### Many users: automatic mapping, and switching off passwords

For a few people the users file is fine. For hundreds or thousands, keep it small and let the
account name follow the user name:

    oidc-auto-domains = uwv.nl            # comma separated

A person who is **not** in the users file then signs in as the account named exactly like their
Microsoft user name, lower-cased: `Jan.Jansen@uwv.nl` signs in as the Linux account
`jan.jansen@uwv.nl` (what sssd gives you with fully qualified names). Rules:

- **The account must already exist** (nothing is created) and be an ordinary user: uid at least
  `min-uid`, PAM allows it, and, if you set `login-group`, a member of that group.
- **Only the listed domains.** The part after the last `@` must be one of them; anything else is
  refused as "not linked".
- **The users file wins.** An entry there is used instead; a line `jan.jansen@uwv.nl = -` refuses
  that person outright.
- **Names can be recycled, so the first sign-in is pinned.** A user name is not a stable
  identity: when someone leaves and a new colleague later gets the same name, the new person
  would inherit the account and the files of the first. The first automatic sign-in therefore
  pins the account to Microsoft's object id (`/var/lib/cerberusttpd/oidc-pins.json`, root only).
  A later sign-in with the same name but another object id is refused (`result=mismatch`
  in the audit log, "linked to a different person" on screen). To settle it, remove the line for
  that account from the pins file (or map the person explicitly in the users file, which skips
  the pin). Without an object id in the token an automatic sign-in is refused.
- This turns the users file from a list of who may sign in into an exception list. If that is
  too wide, set `login-group` and put in it only the people who may use this service: it is
  checked at every sign-in, whatever the method.

If everybody signs in with single sign-on, switch password sign-in off:

    password-login = off

The login page then shows only the single sign-on button, the server refuses a posted password,
and the root process does not check passwords at all. Consider the consequences before you do:
**while the provider is unreachable nobody can sign in**, and there is no way in over the web
for an emergency. The way out is on the server: set `password-login = on` in the config and
restart the service (and `chage`, SSH and the console are unaffected). Two-factor (`2fa`) only
applies to password sign-in.

### Keeping the users file up to date

Where the account name does not follow the user name, or for exceptions, the users file lists
`identity = account` lines. For many entries do not edit it by hand: generate it from your own
source (an export from the directory, an HR list) and replace it in one step. The packaged
`/usr/share/doc/cerberusttpd/make-oidc-users` (also in `contrib/`) does that:

    make-oidc-users people.csv /etc/cerberusttpd/oidc-users

`people.csv` is `identity,account` per line, where the identity is a user name or
`oid:<object id>` (the stable key: prefer it when you have it) and the account `-` refuses the
person:

    jan.jansen@example.com,jjansen
    oid:3f2a9c1e-0000-0000-0000-000000000000,piet.pieters@example.com
    ex.employee@example.com,-

The script is meant to run as root from a job or from configuration management. It checks every
line (valid account names, no duplicates, no empty list), writes a temporary file next to the target
and moves it into place, so a mistake changes nothing and a reader never sees half a file; the
result is owned by root and mode 0600. The service reads the file at every sign-in, so there is no
restart. Run it again when people join or leave.

The Linux accounts themselves come from your directory (sssd) and are not made by this service. For
the people allowed to use it, use a group in the directory as `login-group`: sssd resolves the
membership, so adding or removing someone in the directory is all it takes. Both belong in your
automation, for example (an Ansible sketch; it was not run as part of the tests of this project):

    - name: oidc-users from the HR export
      ansible.builtin.copy:
        src: people.csv
        dest: /etc/cerberusttpd/people.csv
        owner: root
        mode: "0600"
      register: people
    - name: rebuild the mapping when the list changed
      ansible.builtin.command: /usr/share/doc/cerberusttpd/make-oidc-users /etc/cerberusttpd/people.csv /etc/cerberusttpd/oidc-users
      when: people.changed

### Good to know

- **Skips TOTP.** A Microsoft sign-in does not ask for the cerberusttpd authenticator code,
  whatever `2fa` says; require MFA in Microsoft (Conditional Access / security defaults). It
  does not check how Microsoft authenticated the person.
- **Locking an account.** `usermod -L` (locked password) does *not* stop single sign-on. Remove the
  person from `oidc-users`, or expire the account (`chage -E 0 <user>`).
- **Sign out** ends the session on this server only, not at Microsoft. The other way round too:
  switching off or disabling the account at Microsoft does **not** end a session that is already
  open here (there is no back-channel logout). It ends after 30 minutes without activity or 12
  hours at most, or when an administrator ends it on the Admin page. Provider tokens are only
  used during sign-in: nothing here depends on a token that could run out in the middle of a
  long upload or download.
- **Faillock and throttling are for passwords.** The 10 attempts / 5 minutes of faillock and the
  per-IP throttle count failed *password* sign-ins. With single sign-on the password and the
  second factor are Microsoft's, and so is their lock-out.
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

Passwords, codes, session tokens and the secrets of share links never appear. Every value is
quoted or escaped, so a file name or user name with a newline or a quote cannot forge a second
line. The journal is where to keep it safe; send it to a log server if the host itself is not
trusted (see "Sending the audit log to a central server" below).

**Format.** `audit-format = text` (the default) gives the `key=value` lines above. `audit-format =
json` writes one JSON object per line, for log platforms that would otherwise have to parse
`key=value`:

    {"time":"2026-11-24T10:00:01.2-05:00","level":"INFO","msg":"audit","event":"download","user":"jan","ip":"192.0.2.7","auth":"password+totp","result":"ok","path":"docs/report.pdf","size":48211,"range":""}

Both carry the same fields. A restart is needed to change the format.

**Fields.**

| Field | Meaning |
| --- | --- |
| `time`, `level` | When it happened and `INFO`. |
| `msg` | Always `audit`: this is what separates these lines from the service's other messages. |
| `event` | What happened, see below. |
| `user` | Who: the Linux account; for a failed sign-in the name that was typed; empty for an anonymous share link. |
| `ip` | The address the request came from. Behind a reverse proxy that is the proxy's address. |
| `auth` | How the person proved who they are: `password`, `password+totp`, `oidc`, or `share` (a link). |
| `result` | `ok`, or why not (`denied`, `throttled`, `forbidden`, `notfound`, `infected`, `scanfail`, `nospace`, `nohome`, `unmapped`, `mismatch`, `disabled`, `expired`, `exhausted`, ...). |
| others | Details of the event: `path`, `size`, `range`, `to`, `share`, `target`, `idp_user`, `signature`, `why`. |

**Events.** `login` (also `mfa` for the second factor, `logout`), `download` (a `range` marks a
partial read), `access` (refused access to a file), `upload` and `upload_cancel`, `mkdir`, `rename`
(`to`), `delete`, `album_create` and `album_save`, `share_create`, `share_revoke`, `share_open`
and `share_view` (share links), `people_share`, `people_stop` and `shared_open` (sharing with users
and groups), and the administrators' `admin` (refused), `admin_session_end`, `admin_share_revoke`
and `admin_people_stop`. Not logged: directory listings, thumbnails and the live sidebar. Events
that happen only inside the root process (for example a pin refusing someone) also leave a line in
the journal without `msg=audit`; the `result=` of the matching `login` line is what to alert on.

### Sending the audit log to a central server

The lines are on the host's journal; a shipper has to pick them up. Three ways, from the simplest.

1. **Read them directly.** Every audit line, newest last, without the journal's own fields:

        journalctl -u cerberusttpd -o cat | grep ' msg=audit '                       # text format
        journalctl -u cerberusttpd -o cat -f | jq -R -c 'fromjson? | select(.msg=="audit")'   # json format

   and, for example, what was refused:
   `... | jq -R -c 'fromjson? | select(.msg=="audit" and .result!="ok")'`.

2. **rsyslog** forwards the journal to a syslog server over TCP with TLS. The packaged example
   `/usr/share/doc/cerberusttpd/30-cerberusttpd-audit.conf.example` passes only the audit lines (both
   formats, and nothing else of the service's output), keeps them in a disk queue while the server is
   away, and encrypts the connection:

        cp /usr/share/doc/cerberusttpd/30-cerberusttpd-audit.conf.example /etc/rsyslog.d/30-cerberusttpd-audit.conf
        # edit the target and the permitted peer name, install rsyslog-gnutls, then
        rsyslogd -N1 && systemctl restart rsyslog

   `rsyslogd -N1` checks the syntax; the filter was tried with both formats.

3. **Another shipper** (Filebeat, Vector, Fluent Bit, the Splunk or Elastic agents): read the systemd
   journal for the unit `cerberusttpd.service`, keep only messages that contain `msg=audit`
   (text) or `"msg":"audit"` (json) and, with `audit-format = json`, parse the message as JSON. The
   JSON format is the easiest for these: the fields arrive ready to use.

Whichever way, think about: **TLS** to the server (the trail names who downloaded what);
**time** (the lines carry the host's local time with its offset: keep the clocks right);
**buffering**, so a gap in the network does not lose events; **retention** that matches your policy;
and **alerts** on at least `result=mismatch`, a burst of `result=denied` or `throttled`, `event=admin*`,
and `event=share_create`/`share_open` if links are allowed. The Admin page keeps only the last 2000
events in memory and is not a log.

## Share links (files for people without an account)

Off by default, because it opens a way in without a login. Turn it on in the settings file:

    shares = on
    share-max-days = 30        # the longest a link may stay valid (default 30)

A signed-in user then sees a **Share** link next to every file. They pick how long the link
stays valid (up to `share-max-days`), optionally set a password (at most 64 bytes) and a
download limit, and get a link like `https://files.example.com/s/<secret>`. The link is shown
**once**: the server keeps only a hash of the secret, so a lost link cannot be looked up and
has to be replaced. **Share links** in the header lists a user's links and revokes them.

- One file per link (no folders). The person who opens the link sees the file name and a
  Download button, and asks for the password first if there is one.
- Unknown, expired, revoked and used-up links all show the same "this link does not work" page.
- Every check is made by the root process (`run`), not by the network process: the secret, the
  expiry, the password (bcrypt), the limit and a throttle on wrong passwords. The network
  process cannot ask for a user's files; it receives one open file for the path the root process
  stored when the owner made the link.
- The file is opened with the owner's own rights at the moment of the download. If the file is
  gone, or the owner's account has expired, its password has expired or the user was removed,
  the link stops working. Locking the account alone (`usermod -L`) does **not** stop links,
  just as it does not stop single sign-on: PAM account management does not look at it. When
  someone leaves, revoke their links or expire the account (`chage -E 0 <user>`). A link follows
  the file's path, not the file: replace the file and the link serves the new one.
- A link with a **download limit** counts every request and always sends the whole file, so it
  cannot be resumed or fetched in pieces (otherwise a range such as `0-99999999` would get around
  the limit). A download cancelled halfway has still used one. Links without a limit support
  resuming. A password-protected download is a form POST, which browsers cannot resume.
- Share links are built from the address the owner used to open the page, so they are meant for
  a public name (`tls = acme`). On a host that is only reachable by IP address with the
  private CA, the link works only for people who trust that CA.
- A password-protected link does not show the file name before the password is entered. A link
  without a password does.
- `share-require-password = on` makes a password mandatory when a link is made, and it also
  switches off the links made before without one. Together with a short `share-max-days` this
  is the usual policy for an organisation that wants no anonymous downloads without a secret.
- At most 100 active links per user. Expired links stay in the list for a day.
- Links are stored in `shares.json` in the data directory (root only, backed up with it).

Audit events: `share_create` and `share_revoke` (by the owner), `share_open` (results `ok`,
`unavailable` with a `why`, `badpassword`, `password`, `throttled`, `busy`) and `share_view`
for a link that does not work. They carry the share's id (`share=`), never the secret. Treat
the link as a password: whoever has it, and the password if you set one, can download the file.
The second factor does not apply to a download through a link; that is the point of it.

## Sharing with users and groups

Off by default. Two settings:

    share-users = on                 # users can name other users to share a file with
    share-groups = finance, hr       # groups a file may be shared with (empty = none)

A user opens **Share** next to a file, types user names and/or ticks groups, and presses
Share. The recipients find the file under **Shared** and can download it, nothing else:
read only, one file per record, and sharing the same file again replaces the earlier list.
**Stop sharing** (on the same page or under Shared) ends it. This is separate from share
links: either, both or neither can be on.

- The recipient is always the user who is signed in. The root process looks up who is in a
  group again at every download, so removing someone from a group takes effect on their next
  click, with no sign-out needed. A group that is taken out of `share-groups` stops applying
  at once.
- The file is opened with the **owner's** rights at the moment of the download and follows the
  path, not the file: replace the file and the recipients get the new one. If the file is gone
  or the owner's account has expired or was removed, the share stops working.
  (`usermod -L` alone does not, see "Share links".)
- You can only name accounts that may sign in here (not root or system accounts) and not
  yourself; one error covers a name that does not exist, is not allowed or is you. Groups must
  be on the `share-groups` list. A group that is listed but cannot be found (for example sssd
  is not ready yet at boot) is only logged as a warning.
- Administrators see every record under **Admin → Shared with people** and can stop it.
  Audit events: `people_share`, `people_stop`, `shared_open`, `admin_people_stop`.
- Not included: folders, write access and expiry dates. For a folder the whole group works in,
  use a shared root instead (below).

### A folder for a group

Without any setting above, a shared root with Unix rights already gives group folders. Set
`root = /srv/share` (see the packaged config) and prepare the folders:

    mkdir -p /srv/share/finance
    chgrp finance /srv/share/finance
    chmod 2770 /srv/share/finance        # the 2 (setgid) keeps new files in the group

Everybody then sees the same tree and the kernel decides who may read or write what. Mind that
`root` applies to **all** users and replaces their home directories, and the folder must exist
or sign-in fails with the "no folder" message.

## Admin page

Members of the `wheel` group see an **Admin** link in the header (`/admin`). It shows:

- **Settings**: the version and which features are on (two-factor, single sign-on, albums, share
  links, virus scan, upload limit, certificate mode). Read only: settings stay in the config file.
- **Signed in now**: every session with its user, sign-in method, address, start time and idle
  time, and an **End session** button (not for your own session; use Sign out for that).
- **Shared with people** (when sharing with users or groups is on): who shared which file with
  whom, with **Stop sharing**.
- **Share links** (when `shares = on`): every user's links with owner, file, status and downloads,
  and **Revoke**. Use it when someone leaves: `usermod -L` does not stop links.
- **Recent events**: the last 2000 audit events since the service started, newest first, with a
  filter on user, event and result. They are only a quick look: the journal has everything
  (see "Audit log").

An administrator sees who shared what and who is signed in, never the contents of files. Whether
someone is an administrator is decided by the root process when they sign in; the network process
cannot claim it. Revoking another user's link is refused by the root process unless the sign-in
was an administrator's. Ending a session, revoking a link and refused access are audited
(`admin_session_end`, `admin_share_revoke`, `admin` with result `forbidden`).

## Virus scanning of uploads

Optional. Set `scan-command` and every finished upload is scanned before it gets its real
name. A file the scanner flags is deleted and the uploader sees *"file rejected: the virus
scanner found something in it"*. If the scan itself fails (scanner missing, crashed, or
slower than `scan-timeout`, default 5 minutes) the upload is refused too, so a broken
scanner never lets files through unchecked. Both cases are in the audit log
(`event=upload result=infected signature=<name>` or `result=scanfail`).

    scan-command = /usr/bin/clamdscan --fdpass --no-summary
    #scan-timeout = 5m

The command is an absolute path followed by fixed arguments (split on spaces, no shell, no
quoting); the file's path is added as the last argument. It runs as the user who uploads, with
an almost empty environment, and follows the `clamscan` exit codes: **0 clean, 1 infected,
anything else is a failure**. Any scanner that behaves like that works.

> **Status: verified with ClamAV 1.4.6 from EPEL on AlmaLinux 9 under the packaged systemd unit and
> SELinux enforcing** (a clean file passes, the EICAR test file is refused). The steps below are
> what that took.

Setting up ClamAV on EL (EPEL), step by step:

    dnf install clamav clamd                    # from EPEL; clamav-freshclam comes along
    freshclam                                   # fetch the signatures once
    systemctl enable --now clamav-freshclam     # keeps them current (it is NOT enabled by the package)
    # /etc/clamd.d/scan.conf: set the socket so every user can reach it
    #     LocalSocket /run/clamd.scan/clamd.sock
    #     LocalSocketMode 666
    echo 'd /run/clamd.scan 0755 clamscan virusgroup' > /etc/tmpfiles.d/clamd.scan.conf
    systemd-tmpfiles --create /etc/tmpfiles.d/clamd.scan.conf
    setsebool -P antivirus_can_scan_system 1
    systemctl enable --now clamd@scan
    # then in cerberusttpd.conf, and restart cerberusttpd:
    scan-command = /usr/bin/clamdscan --fdpass --no-summary

- **`setsebool -P antivirus_can_scan_system 1` is required.** Without it SELinux stops `clamd` from
  reading the uploaded file, every upload fails with "could not be scanned" (`result=scanfail`) and
  the journal shows an `antivirus_t` AVC on a `user_home_t` file.
- **The socket has to be reachable by every user** (mode 666 in a 0755 directory), because the scan runs
  as the uploading user. Any local user can then ask `clamd` to scan files they hand it; that is a
  small denial-of-service surface, not a way to read other people's files (`--fdpass` passes an
  already opened file).
- `--fdpass` is needed: home directories are 0700 and `clamd` runs as its own user.
- `clamd` keeps the signatures in memory (about 1.2 GB on EL9): plan for it.
- **Large uploads keep working, but they are not scanned.** Files larger than clamd's `MaxFileSize`
  (400 MB by default) or `MaxScanSize` are passed as clean, quickly, without being scanned. This is
  the recommended setting when you accept very large uploads. `AlertExceedsMax yes` would refuse
  such uploads instead, so leave it off if big files must work. To scan bigger files, raise
  `MaxFileSize` and `MaxScanSize` in `/etc/clamd.d/scan.conf` (clamd allows up to 4 GB) and also
  raise `scan-timeout` (default 5 minutes): a scan that runs out of time refuses the upload.
- To try it: upload a text file with the EICAR test string; it must be refused.

This is a check at upload time, not a guarantee: the owner can still change a file afterwards,
and files that reach the folder in other ways (SSH, Samba) are not scanned. Empty files are
not scanned.

## Disk quota

If Linux user quotas are switched on for the filesystem (ext4 `usrquota` or XFS `uquota`), the
sidebar shows the quota instead of the whole disk: *"3.0 MiB left of 8.0 MiB"*, and an upload that
runs into the limit stops with *"no space left or quota exceeded"* and leaves nothing behind.
Without quotas nothing changes and the sidebar shows the free space of the disk. Only user quotas
are shown (not group or project quotas); the smaller of the free disk space and the quota left is
used. Verified with an XFS filesystem with a user quota (`uquota`) under the packaged unit, and on
ext4 (`usrquota`, quota feature) with a live test that fills a user's quota (the limit and the
space left are read correctly and the write that crosses the limit is reported as "no space"). The unit lists
`quotactl` in its system call filter for this: without it the quota simply does not appear, so
after upgrading from an older package make sure the new unit is in use.

## Active Directory and LDAP (through sssd)

Sign-in goes through PAM, so any directory your Linux server is joined to works: Active
Directory, FreeIPA or plain LDAP, using sssd. cerberusttpd knows nothing about the directory
itself; file permissions are the ordinary Linux permissions of the directory users and groups.

> **Status: new and not yet verified against a real Active Directory.** The name rules, the
> PAM handling and the missing-home check are tested on a local system; the sssd side follows
> the documented behaviour of `realm`, `authselect` and `pam_sss`. Please report what you find.

1. **Join the server** (once, as root; see your distribution's documentation):

        dnf install realmd sssd adcli oddjob-mkhomedir
        realm join --user=Administrator corp.example.com
        authselect select sssd with-faillock with-mkhomedir --force

   `id jan.jansen@corp.example.com` must now show the user and their groups.
2. **PAM.** The packaged `/etc/pam.d/cerberusttpd` checks local accounts only. Replace it with
   the example that follows the system stack (`password-auth`, which `authselect` now builds
   with `pam_sss`):

        cp /usr/share/doc/cerberusttpd/cerberusttpd.sssd.example /etc/pam.d/cerberusttpd

3. **Names.** `realm join` makes sssd use fully qualified names, so people sign in as
   `jan.jansen@corp.example.com`. For short names (`jan.jansen`) set
   `use_fully_qualified_names = False` in `/etc/sssd/sssd.conf` (only sensible with one domain)
   and restart sssd. Letters of either case, digits and `. _ @ -` are accepted; a
   `DOMAIN\user` form, machine accounts (`PC01$`) and all-digit names are not. If the directory
   ignores case, `Jan.Jansen` and `jan.jansen` count as one person for the attempt limits.
4. **Home directories.** Signing in on the web does not open a PAM session, so nothing
   creates a home directory (`pam_oddjob_mkhomedir` only runs for SSH or console logins).
   Someone who has never logged in that way sees *"Your account has no folder on this server
   yet"* (`result=nohome` in the audit log). Either let them log in once over SSH, create the
   folders yourself (`mkhomedir_helper <user>`), or give everyone a shared folder with
   `root = /srv/files` (permissions then decide who may do what).
5. **Limits.** Administrators (who see the admin marks in the sidebar) are members of the local
   `wheel` group only, not a directory group. Passwords that must be changed at the next login
   are refused (a web form cannot do the change); change them elsewhere first. There is no
   Kerberos/Windows pass-through sign-in; combine with the Microsoft sign-in above if you want
   single sign-on. Locked or expired directory accounts are refused by PAM.

## Administration

- Reset a user's 2FA: `sudo /opt/cerberusttpd/cerberusttpd 2fa-reset -config /etc/cerberusttpd/cerberusttpd.conf <user>`
- Administrator = member of `admin-group` (default `wheel`). Give the application its own group
  (`admin-group = cerberus-admins`) when the people who run it should not be able to use
  `sudo`; leave it empty for nobody. Who is in that group decides who can end sessions, revoke
  other people's links and see the audit overview, so manage and monitor it like `wheel`.
- A user can sign in if their uid is >= `min-uid`, PAM allows the account, they are in
  `login-group` (when set) and 2FA is correct (password sign-in) or Microsoft says so (single
  sign-on).
- Faillock: 10 failed attempts lock an account for 5 minutes (`/etc/pam.d/cerberusttpd`);
  on top of that the app throttles per IP + user.

## Home directories

By default everybody sees their own home directory (or one shared `root`). A sign-in on the web
does not open a PAM session, so `pam_mkhomedir` / `oddjob-mkhomedir` never runs for people who only
use this service; with a directory such as Active Directory they have no home yet and see
*"Your account has no folder on this server yet"* (`result=nohome`). Options:

1. Create the homes beforehand (`mkhomedir_helper <user>`, or a script / Ansible for the
   whole group), or use a shared `root`.
2. Let the service do it at the first sign-in:

        create-home = on
        create-home-base = /home         # the default

   After the password (and second factor) or single sign-on has succeeded, the root process makes
   the home itself: the files of `/etc/skel` (regular files and folders only, no access for group
   and others), the SELinux labels the system's policy wants (`restorecon`), and then it hands the
   folder to the user (mode 0700). Missing parent directories (`/home/uwv.nl/` for
   `/home/uwv.nl/jan`) are created root-owned, 0755. Safeguards: it only works when no shared
   `root` is set; the home path from the directory must be absolute, clean and at most three
   levels below `create-home-base`; that base and every existing parent must be real directories
   owned by root and not writable by others; the home itself must not exist yet. It never runs for a
   share link or a file shared with people, and never before the last factor.
   - **SELinux and nested homes.** `/home/jan` gets `user_home_dir_t` as it should. A home one level
     deeper (`/home/uwv.nl/jan`) is labelled `user_home_t` by the default policy, which is wrong for a
     home directory; the usual fix, also for sssd, is an equivalence rule:
     `semanage fcontext -a -e /home /home/uwv.nl && restorecon -R /home/uwv.nl`. Check the
     first new home with `ls -dZ` and `restorecon -nv`.

## Backup and restore (important)

Back up these, at least (root only: they hold secrets):

| What | Why |
| --- | --- |
| `/var/lib/cerberusttpd/ca/` (`ca-key.pem`, `ca.pem`) | Without them everyone has to trust a new CA. |
| `/var/lib/cerberusttpd/2fa.key` and `2fa/` | Without the key the second-factor data is unreadable. |
| `/var/lib/cerberusttpd/users.json` | Who signed in lately (the clean-up of abandoned uploads). |
| `/var/lib/cerberusttpd/shares.json` | Share links (hashes of the secrets, expiry, counters). |
| `/var/lib/cerberusttpd/shared.json` | Files shared with users and groups. |
| `/var/lib/cerberusttpd/oidc-pins.json` | Which person an automatic single sign-on account belongs to. |
| `/var/lib/cerberusttpd/net/` | With `tls = acme`: the ACME account and certificates (otherwise a new certificate is requested, and Let's Encrypt limits that). |
| `/etc/cerberusttpd/` | The settings, the single sign-on secret and the `oidc-users` file. |

Anyone who has `ca-key.pem` or `2fa.key` can forge certificates or 2FA codes: keep them safe.
The RPM never removes `/var/lib/cerberusttpd` or the `cerberusttpd` user, and an upgrade
(`rpm -Uvh`, `dnf upgrade`) leaves them and your edited config alone.

**Restore** onto a fresh install of the same version (or newer), service stopped:

    systemctl stop cerberusttpd
    cp -a <backup>/var/lib/cerberusttpd/. /var/lib/cerberusttpd/      # keep modes and owners
    cp -a <backup>/etc/cerberusttpd/. /etc/cerberusttpd/
    chown root:root /var/lib/cerberusttpd /etc/cerberusttpd
    chmod 0700 /var/lib/cerberusttpd                                   # 0711 with tls = acme
    chmod 0600 /var/lib/cerberusttpd/*.json /var/lib/cerberusttpd/2fa.key /etc/cerberusttpd/oidc-secret
    chown -R cerberusttpd: /var/lib/cerberusttpd/net                   # the network process owns this
    restorecon -R /var/lib/cerberusttpd /etc/cerberusttpd /opt/cerberusttpd
    systemctl start cerberusttpd

`ca/` and `2fa/` stay root only (`0700`/`0600`). Restore into an *empty* data directory:
copying over a running one mixes two states. The users file `oidc-users` must be owned by
root and not writable by others, or single sign-on refuses to start.

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

## Rolling out to an organisation

A checklist for hundreds or thousands of users (for example a government agency with
Microsoft sign-in and Active Directory through sssd):

1. **Accounts and homes.** Accounts come from sssd; they must exist before the first sign-in and
   have a uid of at least `min-uid`. Either create homes beforehand or set `create-home = on`
   (see "Home directories"). Test with a domain account, with the short and the fully
   qualified name as sssd gives it.
2. **Who may sign in.** Create a group for the users of this service and set `login-group`.
   With `oidc-auto-domains` that group is your allow-list; without it the users file is.
3. **Single sign-on only.** `password-login = off` once SSO works, so there is no second door.
   Decide who may still sign in when the provider is down (nobody, over the web).
4. **Administrators.** Own group, `admin-group`; keep it small and review its members.
5. **Sharing.** Decide: share links off (`shares = off`, the default), or on with a short
   `share-max-days` and `share-require-password = on`; sharing with users and groups with
   `share-users` and a list of `share-groups`. A link is a way in without an account.
6. **Keeping lists current.** Generate `oidc-users` from your source with `make-oidc-users`, and keep
   the accounts and `login-group` in step with the directory (see "Keeping the users file up to
   date").
   **Leavers.** Expire the account (`chage -E 0 <user>`; `usermod -L` alone is not enough), end
   their session and revoke their links on the Admin page, and remove them from `oidc-users` and
   from the pins file.
7. **Logging.** Set `audit-format = json` and send the audit lines to your log platform / SIEM (see
   "Sending the audit log to a central server": an rsyslog example is packaged), with alerts on
   `result=mismatch`, bursts of `denied`/`throttled`, and `admin*` events. The Admin page keeps
   only the last 2000 events in memory.
8. **Virus scan sizing.** `clamd` holds about 1.2 GB; give the host room, and see "Virus scanning"
   for the limits that make large files pass unscanned and for `scan-timeout`.
9. **Network.** HTTP/3 is UDP on the same port as HTTPS. Behind a firewall, NAT or load balancer,
   and also after a redirect to `:8443`, UDP must reach that port unchanged or browsers quietly
   stay on HTTP/2. For a public certificate behind a web server on 80/443, the HTTP-01 route
   (`acme-http-addr`) is the plain one; TLS passthrough on the same port only works when nothing
   else terminates TLS there.
10. **Test it for real:** a pilot group first, a load test with your own numbers, and the
    single sign-on and directory parts against your own tenant and directory (see below).

## What has been verified

What was tried, and where. "Throwaway" means a separate instance on AlmaLinux 9 with test
accounts; "live" means the packaged service under its systemd unit with SELinux enforcing.

| Part | Status |
| --- | --- |
| Password sign-in (PAM), faillock, throttling | Live |
| TOTP second factor, recovery codes | Live |
| HTTP/2 and HTTP/3, local CA | Live |
| Uploads (resumable), downloads, rename, delete | Live |
| Photo albums, thumbnails | Live |
| Audit log | Live |
| Admin page | Live (viewed), sessions/links/people in a throwaway |
| Share links | Live (create, download with a password); expiry, limits, throttling in a throwaway |
| Sharing with users and groups | Throwaway (users, groups, live group removal); not live |
| Virus scan with ClamAV | Live (clean file passes, EICAR refused) |
| Disk quota | XFS and ext4 on loop devices (throwaway) |
| ACME HTTP-01 (Let's Encrypt, production) | Live once; **renewal, DNS-01 and TLS-ALPN-01 not verified** |
| Single sign-on (Microsoft Entra ID) | **Not verified**: only against a simulated provider |
| `password-login = off`, `login-group`, `admin-group`, `share-require-password` | Throwaway under a copy of the packaged unit (SELinux enforcing); the sign-in page and refusals were checked. The single sign-on part was a stand-in provider |
| Automatic mapping (`oidc-auto-domains`) and the object-id pins | Unit tests only: they need a real provider and an account named like a user name (`jan@example.com`) |
| Create-home (`create-home = on`) | Throwaway under a copy of the packaged unit: home, nested parent, labels and ownership checked, the worker starts in it. Not with a real directory (sssd) |
| Active Directory / sssd | **Not verified** against a real directory |
| AlmaLinux 10 package | Builds; **not run on a live EL10 system** |
| Behaviour under heavy load (thousands of users) | **Not tested** |

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
