// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package worker

import (
	"errors"
	"os"
	"path"
	"syscall"

	"golang.org/x/sys/unix"
)

// stat reports what name is without following a final symlink.
func stat(root *os.Root, name string) Response {
	fi, err := root.Lstat(name)
	if err != nil {
		return Response{Err: errCode(err)}
	}
	kind := "file"
	if fi.IsDir() {
		kind = "dir"
	}
	return Response{Kind: kind, Name: path.Base(name), Size: fi.Size()}
}

// remove deletes a file, symlink or directory. A directory with content needs
// recursive, so the UI can ask first. The kernel decides whether we may.
func remove(root *os.Root, name string, recursive bool) Response {
	if name == "." {
		return Response{Err: "invalid"}
	}
	fi, err := root.Lstat(name)
	if err != nil {
		return Response{Err: errCode(err)}
	}
	if fi.IsDir() && recursive {
		err = root.RemoveAll(name)
	} else {
		err = root.Remove(name)
	}
	if err != nil {
		return Response{Err: errCode(err)}
	}
	return Response{}
}

// rename gives name a new base name in the same directory. It never replaces
// an existing entry: renameat2(RENAME_NOREPLACE) is atomic.
func rename(root *os.Root, name, to string) Response {
	if name == "." || !validName(to) {
		return Response{Err: "invalid"}
	}
	dir, old := path.Split(name)
	if dir == "" {
		dir = "."
	}
	if old == to {
		return Response{}
	}
	d, err := root.Open(dir)
	if err != nil {
		return Response{Err: errCode(err)}
	}
	defer d.Close()
	fd := int(d.Fd())
	err = unix.Renameat2(fd, old, fd, to, unix.RENAME_NOREPLACE)
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOSYS) {
		// Filesystem without NOREPLACE: best effort check, then plain rename.
		if _, serr := root.Lstat(path.Join(dir, to)); serr == nil {
			return Response{Err: "exists"}
		}
		err = unix.Renameat(fd, old, fd, to)
	}
	if err != nil {
		return Response{Err: errCode(&os.PathError{Op: "rename", Path: name, Err: err})}
	}
	return Response{Name: to}
}

// fsInfo reports the size and free space of the filesystem holding the root,
// as this user sees it (Bavail excludes space reserved for root).
func fsInfo(root *os.Root) Response {
	f, err := root.Open(".")
	if err != nil {
		return Response{Err: errCode(err)}
	}
	defer f.Close()
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &st); err != nil {
		return Response{Err: "internal"}
	}
	return Response{Total: int64(st.Blocks) * int64(st.Bsize), Avail: int64(st.Bavail) * int64(st.Bsize)}
}
