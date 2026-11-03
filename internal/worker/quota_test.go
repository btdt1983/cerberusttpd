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
