// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package worker

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Disk quota of the user the worker runs as, on the filesystem of the shared
// folder. A user may always ask for their own quota, so no privilege is needed.
// It uses the classic quotactl(2) with the block device of the filesystem
// (found through /proc/self/mountinfo), which works for ext4 and XFS user quotas
// alike; the unit lists quotactl in its system call filter. When the filesystem,
// the kernel or the quota setup does not answer, there simply is no quota to show.

const (
	qGetQuota = 0x800007 // Q_GETQUOTA
	usrQuota  = 0
	qifBLimit = 1 // dqb_bhardlimit and dqb_bsoftlimit are valid
	qifSpace  = 2 // dqb_curspace is valid
	dqBlkSize = 1024
)

// dqblk is the kernel's struct if_dqblk.
type dqblk struct {
	BHardLimit, BSoftLimit, CurSpace  uint64
	IHardLimit, ISoftLimit, CurInodes uint64
	BTime, ITime                      uint64
	Valid                             uint32
}

// limitFrom turns the kernel's answer into bytes used and the limit that
// applies: the hard limit, or the soft one when there is no hard limit. A
// limit of 0 means none.
func limitFrom(d dqblk) (used, limit int64, ok bool) {
	if d.Valid&qifSpace == 0 {
		return 0, 0, false
	}
	used = int64(d.CurSpace)
	if d.Valid&qifBLimit != 0 {
		l := d.BHardLimit
		if l == 0 {
			l = d.BSoftLimit
		}
		limit = int64(l) * dqBlkSize
	}
	return used, limit, true
}

// deviceOf returns the block device holding dir, from the mount table.
func deviceOf(dir *os.File, mountinfo string) string {
	var st unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &st) != nil {
		return ""
	}
	want := fmt.Sprintf("%d:%d", unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)))
	for _, line := range strings.Split(mountinfo, "\n") {
		before, after, ok := strings.Cut(line, " - ")
		f := strings.Fields(before)
		if !ok || len(f) < 5 || f[2] != want {
			continue
		}
		// after: fstype source superblock-options
		if g := strings.Fields(after); len(g) >= 2 && strings.HasPrefix(g[1], "/dev/") {
			return g[1]
		}
	}
	return ""
}

// userQuota reports the user's space used and limit on the filesystem holding
// dir; ok is false when quotas are off or cannot be read.
func userQuota(dir *os.File, uid int) (used, limit int64, ok bool) {
	mi, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return 0, 0, false
	}
	dev := deviceOf(dir, string(mi))
	if dev == "" {
		return 0, 0, false
	}
	special, err := syscall.BytePtrFromString(dev)
	if err != nil {
		return 0, 0, false
	}
	var d dqblk
	_, _, errno := syscall.Syscall6(unix.SYS_QUOTACTL, uintptr(qGetQuota<<8|usrQuota), uintptr(unsafe.Pointer(special)), uintptr(uid), uintptr(unsafe.Pointer(&d)), 0, 0)
	if errno != 0 {
		return 0, 0, false
	}
	return limitFrom(d)
}
