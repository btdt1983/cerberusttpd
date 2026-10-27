%global debug_package %{nil}
%global __strip /bin/true

Name:           cerberusttpd
Version:        %{ver}
Release:        2%{?dist}
Summary:        File sharing server with PAM login, TOTP 2FA, HTTP/3 and resumable transfers
License:        AGPL-3.0-only
BuildArch:      x86_64
Source0:        cerberusttpd-%{version}.tar.gz
BuildRequires:  systemd-rpm-macros
Requires:       pam
Requires(pre):  shadow-utils
%{?systemd_requires}

%description
Cerberusttpd serves files over HTTPS (HTTP/1.1, HTTP/2, HTTP/3) with its own
local CA, Linux PAM logins plus TOTP, per-user file access enforced by the
kernel, resumable uploads (tus) and downloads, and a live status sidebar.

%prep
%setup -q

%build
# prebuilt: "make rpm" builds the binary and stages the tree

%install
cp -a . %{buildroot}

%pre
getent passwd cerberusttpd >/dev/null || \
    useradd -r -M -s /sbin/nologin -c "Cerberusttpd network process" cerberusttpd
exit 0

%post
# State holds the CA key and the 2FA records: created here, owned by no
# package, so removing the package never deletes it.
install -d -m 700 /var/lib/cerberusttpd
%sysctl_apply 90-cerberusttpd.conf
%systemd_post cerberusttpd.service

%preun
%systemd_preun cerberusttpd.service

%postun
%systemd_postun_with_restart cerberusttpd.service

%files
%dir /opt/cerberusttpd
/opt/cerberusttpd/cerberusttpd
%dir %{_sysconfdir}/cerberusttpd
%config(noreplace) %{_sysconfdir}/cerberusttpd/cerberusttpd.conf
%config(noreplace) %{_sysconfdir}/pam.d/cerberusttpd
%config(noreplace) %{_sysconfdir}/sysctl.d/90-cerberusttpd.conf
%{_unitdir}/cerberusttpd.service
/usr/lib/firewalld/services/cerberusttpd.xml
%doc %{_docdir}/cerberusttpd/README.md
%license %{_licensedir}/cerberusttpd/LICENSE
