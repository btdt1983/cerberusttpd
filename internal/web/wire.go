// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package web

import (
	"net"

	"golang.org/x/net/ipv4"
)

// CountListener makes the TCP side count what crosses the socket. It sits
// below TLS, so handshakes, TLS record overhead and HTTP headers are included.
func (s *Server) CountListener(l net.Listener) net.Listener {
	return &wireListener{Listener: l, st: &s.stats}
}

// CountPacketConn does the same for the UDP socket quic-go runs on: every
// QUIC datagram, handshakes and headers included. It returns pc unchanged if
// it is not a *net.UDPConn.
func (s *Server) CountPacketConn(pc net.PacketConn) net.PacketConn {
	c, ok := pc.(*net.UDPConn)
	if !ok {
		return pc
	}
	return &wirePacketConn{UDPConn: c, st: &s.stats, bc: ipv4.NewPacketConn(c)}
}

type wireListener struct {
	net.Listener
	st *stats
}

func (l *wireListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &wireConn{Conn: c, st: l.st}, nil
}

type wireConn struct {
	net.Conn
	st *stats
}

func (c *wireConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.st.in.Add(int64(n))
	return n, err
}

func (c *wireConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.st.out.Add(int64(n))
	return n, err
}

// wirePacketConn counts datagrams. quic-go reads through ReadBatch when the
// connection provides it (and keeps its ECN/GSO optimisations) and writes
// through WriteMsgUDP; ReadFrom, ReadMsgUDP and WriteTo cover the fallbacks.
type wirePacketConn struct {
	*net.UDPConn
	st *stats
	bc *ipv4.PacketConn
}

func (c *wirePacketConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	n, err := c.bc.ReadBatch(ms, flags)
	for i := 0; i < n; i++ {
		c.st.in.Add(int64(ms[i].N))
	}
	return n, err
}

func (c *wirePacketConn) ReadMsgUDP(b, oob []byte) (int, int, int, *net.UDPAddr, error) {
	n, oobn, flags, addr, err := c.UDPConn.ReadMsgUDP(b, oob)
	c.st.in.Add(int64(n))
	return n, oobn, flags, addr, err
}

func (c *wirePacketConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (int, int, error) {
	n, oobn, err := c.UDPConn.WriteMsgUDP(b, oob, addr)
	c.st.out.Add(int64(n))
	return n, oobn, err
}

func (c *wirePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.UDPConn.ReadFrom(b)
	c.st.in.Add(int64(n))
	return n, addr, err
}

func (c *wirePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := c.UDPConn.WriteTo(b, addr)
	c.st.out.Add(int64(n))
	return n, err
}
