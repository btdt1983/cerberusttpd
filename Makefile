# pam's cgo needs _GNU_SOURCE for RTLD_NEXT.
export CGO_CFLAGS += -D_GNU_SOURCE
VERSION ?= 0.7.2
PREFIX  ?= /opt/cerberusttpd
DESTDIR ?=

build:
	go build -ldflags "-X main.version=$(VERSION)" -o cerberusttpd ./cmd/cerberusttpd

test:
	go vet ./... && go test ./...

# Everything that goes on disk, under $(DESTDIR). The binary lives in /opt so
# it keeps the default SELinux label (usr_t): systemd then starts it as
# unconfined_service_t instead of the stricter init_t. It must be readable and
# executable by the service user and every login user (homes are 0700).
stage:
	install -d -m 755 $(DESTDIR)$(PREFIX) $(DESTDIR)/etc/cerberusttpd $(DESTDIR)/usr/lib/systemd/system \
		$(DESTDIR)/usr/lib/firewalld/services $(DESTDIR)/etc/pam.d $(DESTDIR)/etc/sysctl.d $(DESTDIR)/usr/share/doc/cerberusttpd \
		$(DESTDIR)/usr/share/licenses/cerberusttpd
	install -m 755 cerberusttpd $(DESTDIR)$(PREFIX)/cerberusttpd
	[ -e $(DESTDIR)/etc/cerberusttpd/cerberusttpd.conf ] || install -m 644 packaging/cerberusttpd.conf $(DESTDIR)/etc/cerberusttpd/cerberusttpd.conf
	install -m 644 packaging/pam.d/cerberusttpd $(DESTDIR)/etc/pam.d/cerberusttpd
	install -m 644 packaging/sysctl-cerberusttpd.conf $(DESTDIR)/etc/sysctl.d/90-cerberusttpd.conf
	install -m 644 packaging/cerberusttpd.service $(DESTDIR)/usr/lib/systemd/system/cerberusttpd.service
	install -m 644 packaging/firewalld/cerberusttpd.xml $(DESTDIR)/usr/lib/firewalld/services/cerberusttpd.xml
	install -m 644 README.md $(DESTDIR)/usr/share/doc/cerberusttpd/README.md
	install -m 644 LICENSE $(DESTDIR)/usr/share/licenses/cerberusttpd/LICENSE

# Install on this machine (the RPM does the same through its scriptlets).
install: build
	$(MAKE) stage
	id cerberusttpd >/dev/null 2>&1 || useradd -r -M -s /sbin/nologin cerberusttpd
	install -d -m 700 /var/lib/cerberusttpd
	sysctl -p /etc/sysctl.d/90-cerberusttpd.conf >/dev/null
	systemctl daemon-reload
	systemctl try-restart cerberusttpd

rpm: build
	rm -rf rpmbuild && mkdir -p rpmbuild/SOURCES rpmbuild/stage
	$(MAKE) stage DESTDIR=$(CURDIR)/rpmbuild/stage
	tar -C rpmbuild/stage -czf rpmbuild/SOURCES/cerberusttpd-$(VERSION).tar.gz --transform 's,^\./,cerberusttpd-$(VERSION)/,' .
	rpmbuild -bb --define "_topdir $(CURDIR)/rpmbuild" --define "ver $(VERSION)" packaging/cerberusttpd.spec
	@ls rpmbuild/RPMS/*/*.rpm

.PHONY: build test stage install rpm
