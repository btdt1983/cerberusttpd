// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package worker

import (
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestQuotaLimitFrom(t *testing.T) {
	for name, c := range map[string]struct {
		d           dqblk
		used, limit int64
		ok          bool
	}{
		"hard limit":        {dqblk{BHardLimit: 10240, BSoftLimit: 5120, CurSpace: 4096, Valid: 3}, 4096, 10 << 20, true},
		"only a soft limit": {dqblk{BSoftLimit: 5120, CurSpace: 1, Valid: 3}, 1, 5 << 20, true},
		"no limit":          {dqblk{CurSpace: 7, Valid: 3}, 7, 0, true},
		"limits not valid":  {dqblk{BHardLimit: 99, CurSpace: 7, Valid: 2}, 7, 0, true},
		"space not valid":   {dqblk{BHardLimit: 99, Valid: 1}, 0, 0, false},
	} {
		used, limit, ok := limitFrom(c.d)
		if used != c.used || limit != c.limit || ok != c.ok {
			t.Errorf("%s: %d %d %v", name, used, limit, ok)
		}
	}
}

// Where quotas are not available the answer is "no quota", not an error.
func TestNoQuotaOnPlainFilesystems(t *testing.T) {
	f, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, _, ok := userQuota(f, os.Getuid()); ok {
		t.Skip("this filesystem has user quotas switched on")
	}
	if r := fsInfo(openRoot(t, t.TempDir())); r.Err != "" || r.QuotaLimit != 0 || r.Total == 0 {
		t.Errorf("%+v", r)
	}
}

func TestDeviceOf(t *testing.T) {
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	var st unix.Stat_t
	unix.Fstat(int(dir.Fd()), &st)
	mm := fmt.Sprintf("%d:%d", unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)))
	line := func(src, fstype string) string {
		return "36 35 " + mm + " / /mnt rw,relatime shared:1 - " + fstype + " " + src + " rw,seclabel\n"
	}
	for name, c := range map[string]struct{ table, want string }{
		"xfs on lvm":            {"1 2 0:5 / /x rw - tmpfs tmpfs rw\n" + line("/dev/mapper/vg-home", "xfs"), "/dev/mapper/vg-home"},
		"ext4 partition":        {line("/dev/sda3", "ext4"), "/dev/sda3"},
		"a mount without a dev": {line("tmpfs", "tmpfs"), ""},
		"nfs":                   {line("srv:/export", "nfs4"), ""},
		"another device":        {"36 35 8:99 / /mnt rw - xfs /dev/sdz rw\n", ""},
		"empty":                 {"", ""},
	} {
		if got := deviceOf(dir, c.table); got != c.want {
			t.Errorf("%s: %q want %q", name, got, c.want)
		}
	}
}

// A live check against a real filesystem, for ext4 and XFS: set CT_QUOTA_DIR to
// a directory on a filesystem with user quotas that this test's user owns, and
// CT_QUOTA_LIMIT to that user's hard block limit in bytes. Skipped otherwise.
func TestQuotaLive(t *testing.T) {
	dir := os.Getenv("CT_QUOTA_DIR")
	if dir == "" {
		t.Skip("CT_QUOTA_DIR is not set")
	}
	var want int64
	if _, err := fmt.Sscan(os.Getenv("CT_QUOTA_LIMIT"), &want); err != nil || want <= 0 {
		t.Fatal("CT_QUOTA_LIMIT must be the hard limit in bytes")
	}
	root := openRoot(t, dir)
	before := fsInfo(root)
	if before.QuotaLimit != want || before.Avail > want {
		t.Fatalf("before: limit %d (want %d), avail %d", before.QuotaLimit, want, before.Avail)
	}
	f, err := root.Create("fill.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	chunk := make([]byte, 1<<20)
	var werr error
	for i := 0; i < int(want>>20)+4 && werr == nil; i++ {
		_, werr = f.Write(chunk)
	}
	if code := errCode(werr); werr == nil || code != "nospace" {
		t.Fatalf("writing past the quota: err %v, code %q (want nospace)", werr, code)
	}
	f.Sync()
	after := fsInfo(root)
	if after.QuotaUsed < want/2 || after.Avail > want/4 {
		t.Errorf("after filling: used %d, avail %d of limit %d", after.QuotaUsed, after.Avail, after.QuotaLimit)
	}
	t.Logf("limit %d, used %d, avail %d before=%d", after.QuotaLimit, after.QuotaUsed, after.Avail, before.Avail)
}
