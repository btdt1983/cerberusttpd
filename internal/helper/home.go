// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Creating a home directory at the first sign-in (create-home = on). A sign-in
// on the web does not open a PAM session, so pam_mkhomedir or oddjob never
// runs for people who only use this service, and with a directory such as
// Active Directory nobody has a home yet. The work is done by the system's
// own skeleton (/etc/skel) with no access for group and others, the system's
// SELinux labels (restorecon) and ownership by the user.
//
// It happens only after every factor has passed (see complete), never for the
// share paths, never with a shared root, and only below create-home-base.
const (
	restoreconBin   = "/usr/sbin/restorecon"
	skelDir         = "/etc/skel"
	skelMaxEntries  = 200
	skelMaxBytes    = 4 << 20
	mkhomeTimeout   = 30 * time.Second
	mkhomeMaxDepth  = 3 // path components below the base
	defaultHomeBase = "/home"
)

// homeReady is the early check, before a second factor: the home exists, or
// would be created. It creates nothing.
func (s *server) homeReady(u *user.User) bool {
	if s.homeOK(u) {
		return true
	}
	_, err := s.homePlan(u)
	return err == nil
}

// ensureHome makes sure the home exists, creating it when that is switched on.
func (s *server) ensureHome(u *user.User) bool {
	if s.homeOK(u) {
		return true
	}
	if err := s.createHome(u); err != nil {
		log.Printf("helper: create home for %q: %v", u.Username, err)
		return false
	}
	return s.homeOK(u)
}

// homePlan checks that a home may be created for u and returns the parent
// directories that are missing, outermost first. It changes nothing.
func (s *server) homePlan(u *user.User) ([]string, error) {
	if !s.CreateHome {
		return nil, errors.New("create-home is off")
	}
	if s.Root != "" {
		return nil, errors.New("a shared root is set: the folder must exist")
	}
	home := u.HomeDir
	base := s.CreateHomeBase
	if base == "" {
		base = defaultHomeBase
	}
	if !filepath.IsAbs(home) || filepath.Clean(home) != home || !strings.HasPrefix(home, base+"/") {
		return nil, fmt.Errorf("home %q is not a clean path below %s", home, base)
	}
	rel := strings.TrimPrefix(home, base+"/")
	parts := strings.Split(rel, "/")
	if len(parts) > mkhomeMaxDepth {
		return nil, fmt.Errorf("home %q is more than %d levels below %s", home, mkhomeMaxDepth, base)
	}
	if _, err := os.Lstat(home); err == nil || !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s exists or cannot be checked", home)
	}
	// The base must be a real directory that only root can write in.
	if err := rootOnlyDir(base); err != nil {
		return nil, err
	}
	var missing []string
	cur := base
	for _, p := range parts[:len(parts)-1] {
		cur = cur + "/" + p
		fi, err := os.Lstat(cur)
		switch {
		case err == nil:
			if err := rootOnlyDir(cur); err != nil {
				return nil, err
			}
			_ = fi
		case errors.Is(err, os.ErrNotExist):
			missing = append(missing, cur)
		default:
			return nil, err
		}
	}
	return missing, nil
}

// rootOnlyDir demands a real directory (not a link), owned by root and not
// writable by group or others, so nobody else can plant something in it.
func rootOnlyDir(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s must be a directory owned by root and not writable by others", p)
	}
	return nil
}

func (s *server) createHome(u *user.User) error {
	missing, err := s.homePlan(u)
	if err != nil {
		return err
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return errors.New("the account has no numeric uid and gid")
	}
	for _, d := range missing {
		if err := os.Mkdir(d, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	// Everything is made as root in a directory only root can enter, labelled,
	// and only then handed over. (The unit has no CAP_DAC_OVERRIDE or
	// CAP_FOWNER: once the folder belongs to the user, root could neither fill
	// it nor relabel it.)
	if err := os.Mkdir(u.HomeDir, 0o700); err != nil {
		return err
	}
	if err := fillHome(u.HomeDir, skelDir, uid, gid); err != nil {
		os.RemoveAll(u.HomeDir)
		return err
	}
	log.Printf("helper: created home %s for %q", u.HomeDir, u.Username)
	return nil
}

// fillHome copies the skeleton into home (mode 0700, owned by root), gives
// everything the system's SELinux label and then makes it the user's.
func fillHome(home, skel string, uid, gid int) error {
	if err := copySkel(skel, home); err != nil {
		return fmt.Errorf("copy %s: %w", skel, err)
	}
	if out, err := restoreCon(home); err != nil {
		return fmt.Errorf("restorecon: %v: %s", err, out)
	}
	return filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	})
}

// restoreCon relabels home as the system's policy wants it. Without SELinux
// (no restorecon, or it is switched off) there is nothing to do.
func restoreCon(home string) (string, error) {
	if _, err := os.Stat(restoreconBin); err != nil {
		return "", nil
	}
	if b, err := os.ReadFile("/sys/fs/selinux/enforce"); err != nil || len(b) == 0 {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), mkhomeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, restoreconBin, "-R", "-F", home)
	cmd.Dir = "/"
	cmd.Env = []string{}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// copySkel copies regular files and directories from skel into home, with no
// access for group and others. Links and special files are skipped, and the
// amount is bounded: /etc/skel is root's, but a mistake there must not fill a disk.
func copySkel(skel, home string) error {
	if _, err := os.Stat(skel); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	root, err := os.OpenRoot(home)
	if err != nil {
		return err
	}
	defer root.Close()
	var total int64
	n := 0
	return filepath.WalkDir(skel, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(skel, p)
		if err != nil || rel == "." {
			return err
		}
		if n++; n > skelMaxEntries {
			return errors.New("too many entries")
		}
		switch {
		case d.IsDir():
			return root.Mkdir(rel, 0o700)
		case d.Type().IsRegular():
			fi, err := d.Info()
			if err != nil {
				return err
			}
			if total += fi.Size(); total > skelMaxBytes {
				return errors.New("too large")
			}
			src, err := os.Open(p)
			if err != nil {
				return err
			}
			defer src.Close()
			dst, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fi.Mode().Perm()&0o700)
			if err != nil {
				return err
			}
			if _, err := io.Copy(dst, io.LimitReader(src, fi.Size())); err != nil {
				dst.Close()
				return err
			}
			return dst.Close()
		}
		return nil // links and special files are not copied
	})
}
