// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/quic-go/quic-go/http3"

	"github.com/btdt1983/cerberusttpd/internal/helper"
	"github.com/btdt1983/cerberusttpd/internal/ipc"
	"github.com/btdt1983/cerberusttpd/internal/web"
)

var stopping atomic.Bool

func serveMain(args []string) error {
	var o options
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	o.register(fs)
	fs.Parse(args)

	tcp, err := net.FileListener(os.NewFile(3, "tcp"))
	if err != nil {
		return err
	}
	udp, err := net.FilePacketConn(os.NewFile(4, "udp"))
	if err != nil {
		return err
	}
	hc, err := ipc.NewClient(os.NewFile(5, "helper"))
	if err != nil {
		return err
	}
	w := web.New(hc)
	w.MaxUpload = o.maxUpload
	tcp, udp = w.CountListener(tcp), w.CountPacketConn(udp)

	var tlsConf *tls.Config
	switch o.mode {
	case "local":
		var cur atomic.Pointer[tls.Certificate]
		refresh := func() error {
			var resp helper.Response
			if _, err := hc.Call(helper.Request{Op: "leaf"}, &resp); err != nil {
				return err
			}
			c, err := tls.X509KeyPair(resp.Cert, resp.Key)
			if err != nil {
				return err
			}
			cur.Store(&c)
			if w.CAPEM == nil {
				w.CAPEM = resp.CAPEM
			}
			return nil
		}
		if err := refresh(); err != nil {
			return err
		}
		go func() {
			for range time.Tick(24 * time.Hour) {
				if err := refresh(); err != nil {
					log.Printf("serve: renew certificate: %v", err)
				}
			}
		}()
		tlsConf = &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cur.Load(), nil }}
	case "acme":
		var ds []string
		for _, d := range strings.Split(o.domains, ",") {
			if d = strings.TrimSpace(d); d != "" {
				ds = append(ds, d)
			}
		}
		if len(ds) == 0 {
			log.Fatal("-tls=acme requires -domain")
		}
		certmagic.DefaultACME.Agreed = true
		certmagic.DefaultACME.Email = o.email
		certmagic.Default.Storage = &certmagic.FileStorage{Path: o.data + "/net/acme"}
		cfg := certmagic.NewDefault()
		// Async: challenges are answered on the listener we start below.
		if err := cfg.ManageAsync(context.Background(), ds); err != nil {
			return err
		}
		tlsConf = cfg.TLSConfig()
	default:
		log.Fatalf("unknown -tls mode %q", o.mode)
	}
	tlsConf.MinVersion = tls.VersionTLS12

	_, port, err := net.SplitHostPort(o.addr)
	if err != nil {
		return err
	}
	handler := w.Handler(`h3=":` + port + `"; ma=86400`)

	h3 := &http3.Server{Handler: handler, TLSConfig: http3.ConfigureTLSConfig(tlsConf)}
	go func() {
		if err := h3.Serve(udp); err != nil && !stopping.Load() {
			log.Fatal(err)
		}
	}()

	h12 := tlsConf.Clone()
	h12.NextProtos = []string{"h2", "http/1.1"}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig:         h12,
	}
	// On SIGTERM stop accepting, end the live streams, give transfers a few
	// seconds, then leave (uploads are resumable).
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		stopping.Store(true)
		w.Shutdown()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		go h3.Shutdown(ctx)
		srv.Shutdown(ctx)
		h3.Close()
		os.Exit(0)
	}()
	log.Printf("serve: https on %s (tcp h1/h2, udp h3, tls=%s)", o.addr, o.mode)
	if err := srv.ServeTLS(tcp, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	select {} // the shutdown goroutine exits the process
}
