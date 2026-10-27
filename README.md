# Cerberusttpd

Een zelfstandige bestandsserver in Go: inloggen met je Linux-account (PAM) plus
TOTP-2FA, HTTPS met een eigen lokale CA, HTTP/3, hervatbare downloads en
uploads (tus), bestandsbeheer en een live zijbalk met bandbreedte, gebruikers
en serverbelasting.

## Hoe het werkt

Drie soorten processen, zodat rechten kloppen:

| Proces | Draait als | Taak |
|---|---|---|
| `run` | root | opent de poorten, bewaart de CA-sleutel, PAM, 2FA, start de rest |
| `serve` | `cerberusttpd` | HTTP/1.1, HTTP/2, HTTP/3, pagina's; heeft geen toegang tot bestanden of sleutels |
| `worker` | de ingelogde gebruiker | alle bestandsacties; de kernel bepaalt wat mag |

## Installeren

    make rpm                              # bouwt rpmbuild/RPMS/x86_64/cerberusttpd-*.rpm
    sudo rpm -Uvh rpmbuild/RPMS/x86_64/cerberusttpd-*.rpm
    # of zonder RPM: sudo make install

    sudo firewall-cmd --permanent --add-service=cerberusttpd && sudo firewall-cmd --reload
    sudo systemctl enable --now cerberusttpd

De binary staat bewust in `/opt/cerberusttpd`: daar houdt hij het standaard
SELinux-label (`usr_t`) en start systemd hem als `unconfined_service_t`.
Verplaats hem niet naar `/usr/sbin` (dan wordt het `init_t` en gaat inloggen stuk).

Logs: `journalctl -u cerberusttpd -f`. Instellingen: `/etc/cerberusttpd/cerberusttpd.conf`.

## Eerste keer

1. Open `https://<server>:8443/` en importeer eenmalig de CA
   (`/.well-known/cerberusttpd/ca.crt` voor Windows/Android, `ca.pem` voor Linux/macOS).
   Firefox heeft een eigen certificaatarchief.
2. Log in met je Linux-account en stel 2FA in (QR-code of sleutel).
   **Bewaar de herstelcodes.**

## Beheer

- 2FA van een gebruiker resetten: `sudo /opt/cerberusttpd/cerberusttpd 2fa-reset -config /etc/cerberusttpd/cerberusttpd.conf <gebruiker>`
- Beheerder = lid van de groep `wheel`.
- Een gebruiker kan inloggen als uid >= `min-uid`, PAM de account toestaat en 2FA klopt.
- Faillock: 10 foute pogingen vergrendelen een account 5 minuten (`/etc/pam.d/cerberusttpd`);
  daarnaast remt de app per IP+gebruiker.

## Back-up (belangrijk)

Maak een back-up van `/var/lib/cerberusttpd`, in elk geval:

- `ca/ca-key.pem` en `ca/ca.pem`: zonder deze moet iedereen de CA opnieuw vertrouwen.
- `2fa.key` samen met `2fa/`: zonder de sleutel zijn de 2FA-gegevens onleesbaar.

Wie `ca-key.pem` of `2fa.key` heeft, kan certificaten of 2FA-codes namaken: bewaar ze veilig.
Het RPM verwijdert `/var/lib/cerberusttpd` en de gebruiker `cerberusttpd` nooit.

## Poorten, nginx en een eigen domein

Op deze machine houdt nginx poort 80 en 443 vast, daarom luistert Cerberusttpd op 8443
(TCP en UDP; UDP is voor HTTP/3). `tls = acme` (Let's Encrypt) werkt zoals gebouwd nog niet:
TLS-ALPN-01 vraagt poort 443 en de onbevoorrechte `serve` kan poort 80 niet openen. Voor een
domein zijn er twee routes: DNS-01 (geen open poort nodig) of nginx als SNI-doorgever.

## Beperkingen

- Bandbreedte telt alleen HTTP-inhoud, niet TLS/QUIC-overhead of headers.
- Een geopende pagina houdt je sessie niet levend: na 30 minuten zonder klik loop je eruit.
- Verwijderen is definitief (geen prullenbak); verplaatsen kan nog niet.
- SELinux: draait als `unconfined_service_t`. Een eigen beperkend beleid vraagt
  `selinux-policy-devel` en is nog niet gemaakt.

## Licentie

Copyright (C) 2026 David Bauer

GNU Affero General Public License, versie 3 (AGPL-3.0-only), zie `LICENSE`
(in de RPM: `/usr/share/licenses/cerberusttpd/LICENSE`).

Let op bij aangepaste versies die je als netwerkdienst aanbiedt: artikel 13 van de AGPL
vereist dat je de gebruikers van die dienst de bijbehorende broncode aanbiedt.
De directe afhankelijkheden (quic-go, certmagic, go-qrcode, msteinert/pam, x/sys) hebben een MIT-, BSD- of Apache-2.0-licentie.
