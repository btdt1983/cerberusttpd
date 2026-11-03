// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package helper

import "strings"

const maxUserName = 128 // sssd with fully qualified names: jan.jansen@corp.example.com

// ValidUser reports whether name may be looked up as a login name. The
// name ends up in file names (2fa/<name>.json), so the rules keep it plain:
// letters, digits and . _ @ -, starting with a letter, digit or underscore
// (no leading dot or dash), and never all digits (those read as uids).
// Linux accounts and Active Directory accounts through sssd, such as
// jan.jansen or Jan.Jansen@corp.example.com, fit; machine accounts (PC01$),
// DOMAIN\user and anything with a slash or a space do not.
func ValidUser(name string) bool {
	if name == "" || len(name) > maxUserName {
		return false
	}
	digits := true
	for i := 0; i < len(name); i++ {
		c := name[i]
		letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		digit := c >= '0' && c <= '9'
		switch {
		case letter || c == '_':
			digits = false
		case digit:
		case i > 0 && strings.IndexByte("._@-", c) >= 0:
			digits = false
		default:
			return false
		}
	}
	return !digits
}

// limiterKey is the name attempts are counted under: with a case-insensitive
// directory, Jan and jan are one person and share one budget.
func limiterKey(name string) string { return strings.ToLower(name) }
