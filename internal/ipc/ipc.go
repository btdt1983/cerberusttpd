// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

// Package ipc is a small request/response protocol over a Unix stream socket
// with file-descriptor passing (SCM_RIGHTS). Frames are a 4-byte length plus a
// JSON envelope; descriptors travel with the first bytes of a frame. Requests
// are multiplexed by id, so slow calls never block fast ones.
package ipc

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
)

const (
	maxFrame = 16 << 20
	maxFDs   = 4
)

type envelope struct {
	ID   uint64          `json:"id"`
	Body json.RawMessage `json:"body"`
}

// Pair returns two connected endpoints as *os.File, for handing one to a child.
func Pair() (*os.File, *os.File, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(fds[0]), "ipc-a"), os.NewFile(uintptr(fds[1]), "ipc-b"), nil
}

type conn struct {
	c   *net.UnixConn
	wmu sync.Mutex
}

// fromFile takes ownership of f.
func fromFile(f *os.File) (*conn, error) {
	defer f.Close()
	nc, err := net.FileConn(f)
	if err != nil {
		return nil, err
	}
	uc, ok := nc.(*net.UnixConn)
	if !ok {
		nc.Close()
		return nil, errors.New("ipc: not a unix socket")
	}
	return &conn{c: uc}, nil
}

func (c *conn) send(e envelope, files []*os.File) error {
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if len(body) > maxFrame {
		return errors.New("ipc: frame too large")
	}
	buf := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(buf, uint32(len(body)))
	copy(buf[4:], body)
	var oob []byte
	if len(files) > 0 {
		fds := make([]int, len(files))
		for i, f := range files {
			fds[i] = int(f.Fd())
		}
		oob = syscall.UnixRights(fds...)
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	n, _, err := c.c.WriteMsgUnix(buf, oob, nil)
	if err != nil {
		return err
	}
	for n < len(buf) {
		m, err := c.c.Write(buf[n:])
		if err != nil {
			return err
		}
		n += m
	}
	for _, f := range files {
		runtimeKeepAlive(f)
	}
	return nil
}

func (c *conn) recv() (envelope, []*os.File, error) {
	var e envelope
	hdr := make([]byte, 4)
	var oobAll []byte
	got := 0
	for got < 4 {
		oob := make([]byte, syscall.CmsgSpace(4*maxFDs))
		n, oobn, _, _, err := c.c.ReadMsgUnix(hdr[got:], oob)
		oobAll = append(oobAll, oob[:oobn]...)
		got += n
		if err != nil {
			closeFDs(oobAll)
			if got == 0 && errors.Is(err, io.EOF) {
				return e, nil, io.EOF
			}
			return e, nil, err
		}
	}
	size := binary.BigEndian.Uint32(hdr)
	if size > maxFrame {
		closeFDs(oobAll)
		return e, nil, fmt.Errorf("ipc: frame too large (%d)", size)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(c.c, body); err != nil {
		closeFDs(oobAll)
		return e, nil, err
	}
	files, err := filesFromOOB(oobAll)
	if err != nil {
		return e, nil, err
	}
	if err := json.Unmarshal(body, &e); err != nil {
		for _, f := range files {
			f.Close()
		}
		return e, nil, err
	}
	return e, files, nil
}

func parseFDs(oob []byte) []int {
	var out []int
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	for _, m := range msgs {
		if fds, err := syscall.ParseUnixRights(&m); err == nil {
			out = append(out, fds...)
		}
	}
	return out
}

func closeFDs(oob []byte) {
	for _, fd := range parseFDs(oob) {
		syscall.Close(fd)
	}
}

func filesFromOOB(oob []byte) ([]*os.File, error) {
	fds := parseFDs(oob)
	files := make([]*os.File, 0, len(fds))
	for _, fd := range fds {
		files = append(files, os.NewFile(uintptr(fd), "ipc-fd"))
	}
	if len(files) > maxFDs {
		for _, f := range files {
			f.Close()
		}
		return nil, errors.New("ipc: too many descriptors")
	}
	return files, nil
}

// Client issues calls and matches replies by id.
type Client struct {
	c       *conn
	mu      sync.Mutex
	next    uint64
	pending map[uint64]chan reply
	err     error
}

type reply struct {
	body  json.RawMessage
	files []*os.File
	err   error
}

func NewClient(f *os.File) (*Client, error) {
	c, err := fromFile(f)
	if err != nil {
		return nil, err
	}
	cl := &Client{c: c, pending: map[uint64]chan reply{}}
	go cl.readLoop()
	return cl, nil
}

func (cl *Client) readLoop() {
	for {
		e, files, err := cl.c.recv()
		if err != nil {
			cl.fail(err)
			return
		}
		cl.mu.Lock()
		ch, ok := cl.pending[e.ID]
		delete(cl.pending, e.ID)
		cl.mu.Unlock()
		if !ok {
			for _, f := range files {
				f.Close()
			}
			continue
		}
		ch <- reply{body: e.Body, files: files}
	}
}

func (cl *Client) fail(err error) {
	cl.mu.Lock()
	if cl.err == nil {
		cl.err = err
	}
	pend := cl.pending
	cl.pending = map[uint64]chan reply{}
	cl.mu.Unlock()
	cl.c.c.Close()
	for _, ch := range pend {
		ch <- reply{err: err}
	}
}

// Close shuts the connection; the peer sees EOF.
func (cl *Client) Close() { cl.fail(errors.New("ipc: closed")) }

// Call sends req and decodes the reply into resp. Received descriptors are returned.
func (cl *Client) Call(req, resp any) ([]*os.File, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	ch := make(chan reply, 1)
	cl.mu.Lock()
	if cl.err != nil {
		err := cl.err
		cl.mu.Unlock()
		return nil, err
	}
	cl.next++
	id := cl.next
	cl.pending[id] = ch
	cl.mu.Unlock()
	if err := cl.c.send(envelope{ID: id, Body: body}, nil); err != nil {
		cl.fail(err)
		return nil, err
	}
	r := <-ch
	if r.err != nil {
		return nil, r.err
	}
	if err := json.Unmarshal(r.body, resp); err != nil {
		for _, f := range r.files {
			f.Close()
		}
		return nil, err
	}
	return r.files, nil
}

// Handler answers one request. Returned files are closed after sending.
type Handler func(req json.RawMessage) (resp any, files []*os.File)

// Serve answers requests concurrently until the peer closes. It owns f.
func Serve(f *os.File, h Handler) error {
	c, err := fromFile(f)
	if err != nil {
		return err
	}
	defer c.c.Close()
	for {
		e, files, err := c.recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		for _, f := range files { // requests carry no descriptors
			f.Close()
		}
		go func() {
			resp, out := h(e.Body)
			body, err := json.Marshal(resp)
			if err == nil {
				err = c.send(envelope{ID: e.ID, Body: body}, out)
			}
			for _, f := range out {
				f.Close()
			}
			if err != nil {
				c.c.Close()
			}
		}()
	}
}

func runtimeKeepAlive(f *os.File) { _ = f.Fd() }
