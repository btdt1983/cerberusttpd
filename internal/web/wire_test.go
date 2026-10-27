// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package web

import (
	"io"
	"net"
	"testing"

	"golang.org/x/net/ipv4"
)

func TestCountListener(t *testing.T) {
	s := &Server{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cl := s.CountListener(ln)
	defer cl.Close()

	done := make(chan struct{})
	go func() { // echo server
		defer close(done)
		c, err := cl.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	msg := make([]byte, 5000)
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, len(msg))); err != nil {
		t.Fatal(err)
	}
	c.Close()
	<-done

	if in, out := s.stats.in.Load(), s.stats.out.Load(); in != 5000 || out != 5000 {
		t.Errorf("in=%d out=%d, want 5000 each", in, out)
	}
}

func TestCountPacketConn(t *testing.T) {
	s := &Server{}
	rc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	wrapped := s.CountPacketConn(rc)
	defer wrapped.Close()
	w, ok := wrapped.(*wirePacketConn)
	if !ok {
		t.Fatalf("got %T, want *wirePacketConn", wrapped)
	}

	tx, err := net.DialUDP("udp", nil, rc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	for _, n := range []int{100, 300, 1200} {
		if _, err := tx.Write(make([]byte, n)); err != nil {
			t.Fatal(err)
		}
	}

	// Receive through the batch path quic-go uses.
	got := 0
	for got < 3 {
		ms := make([]ipv4.Message, 3)
		for i := range ms {
			ms[i].Buffers = [][]byte{make([]byte, 1500)}
		}
		n, err := w.ReadBatch(ms, 0)
		if err != nil {
			t.Fatal(err)
		}
		got += n
	}
	if in := s.stats.in.Load(); in != 1600 {
		t.Errorf("batch read counted %d, want 1600", in)
	}

	// Send through WriteMsgUDP, which quic-go uses (also with GSO).
	if _, _, err := w.WriteMsgUDP(make([]byte, 700), nil, tx.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	if out := s.stats.out.Load(); out != 700 {
		t.Errorf("WriteMsgUDP counted %d, want 700", out)
	}
}
