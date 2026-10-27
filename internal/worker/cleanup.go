// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package worker

import (
	"io/fs"
	"log"
	"os"
	"path"
	"strings"
	"syscall"
	"time"
)

// Cleanup removes abandoned uploads under rootDir that have not been written to
// for maxAge. It runs with the user's own credentials, so only what that user
// may delete is deleted. It stays on one filesystem and follows no symlinks.
func Cleanup(rootDir string, maxAge time.Duration) error {
	syscall.RawSyscall(syscall.SYS_PRCTL, 38 /* PR_SET_NO_NEW_PRIVS */, 1, 0)
	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return err
	}
	defer root.Close()
	rootInfo, err := root.Stat(".")
	if err != nil {
		return err
	}
	dev := devOf(rootInfo)
	cutoff := time.Now().Add(-maxAge)
	removed := 0

	fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir // unreadable directory: not ours to clean
			}
			return nil
		}
		if d.IsDir() {
			if fi, err := d.Info(); err == nil && devOf(fi) != dev {
				return fs.SkipDir
			}
			return nil
		}
		base := path.Base(p)
		if !strings.HasPrefix(base, partPrefix) || !strings.HasSuffix(base, ".part") {
			return nil
		}
		fi, err := d.Info()
		if err != nil || !fi.Mode().IsRegular() || !fi.ModTime().Before(cutoff) {
			return nil
		}
		meta := strings.TrimSuffix(p, ".part") + ".json"
		if err := root.Remove(p); err != nil {
			return nil // no delete right here
		}
		root.Remove(meta)
		removed++
		return nil
	})
	// Orphaned metadata whose part is already gone.
	fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if fi, err := d.Info(); err == nil && devOf(fi) != dev {
				return fs.SkipDir
			}
			return nil
		}
		base := path.Base(p)
		if strings.HasPrefix(base, partPrefix) && strings.HasSuffix(base, ".json") {
			if fi, err := d.Info(); err == nil && fi.ModTime().Before(cutoff) {
				if _, err := root.Lstat(strings.TrimSuffix(p, ".json") + ".part"); err != nil {
					if root.Remove(p) == nil {
						removed++
					}
				}
			}
		}
		return nil
	})
	if removed > 0 {
		log.Printf("cleanup: removed %d abandoned upload file(s) under %s", removed, rootDir)
	}
	return nil
}

func devOf(fi fs.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev)
	}
	return 0
}
