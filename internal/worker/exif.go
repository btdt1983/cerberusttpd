// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package worker

import "encoding/binary"

// exifOrientation reads the EXIF orientation (1..8) from the start of a JPEG.
// head is the first bytes of the file; anything unexpected gives 1 (upright).
// Decoders in the standard library ignore the tag, browsers do not, so
// thumbnails have to apply it themselves.
func exifOrientation(head []byte) int {
	if len(head) < 4 || head[0] != 0xFF || head[1] != 0xD8 {
		return 1
	}
	p := 2
	for p+4 <= len(head) {
		if head[p] != 0xFF {
			return 1
		}
		marker := head[p+1]
		if marker == 0xFF { // fill byte
			p++
			continue
		}
		if marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) {
			p += 2
			continue
		}
		if marker == 0xDA || marker == 0xD9 { // image data: no EXIF after this
			return 1
		}
		n := int(binary.BigEndian.Uint16(head[p+2:]))
		if n < 2 || p+2+n > len(head) {
			return 1
		}
		if marker == 0xE1 {
			return tiffOrientation(head[p+4 : p+2+n])
		}
		p += 2 + n
	}
	return 1
}

func tiffOrientation(seg []byte) int {
	if len(seg) < 14 || string(seg[:6]) != "Exif\x00\x00" {
		return 1
	}
	t := seg[6:]
	var bo binary.ByteOrder
	switch string(t[:2]) {
	case "II":
		bo = binary.LittleEndian
	case "MM":
		bo = binary.BigEndian
	default:
		return 1
	}
	if bo.Uint16(t[2:]) != 42 {
		return 1
	}
	ifd := int(bo.Uint32(t[4:]))
	if ifd < 8 || ifd+2 > len(t) {
		return 1
	}
	count := int(bo.Uint16(t[ifd:]))
	for i := 0; i < count; i++ {
		e := ifd + 2 + i*12
		if e+12 > len(t) {
			return 1
		}
		if bo.Uint16(t[e:]) == 0x0112 { // Orientation, type SHORT
			if v := int(bo.Uint16(t[e+8:])); v >= 1 && v <= 8 {
				return v
			}
			return 1
		}
	}
	return 1
}

// swapsAxes reports whether the orientation turns the picture on its side.
func swapsAxes(o int) bool { return o >= 5 && o <= 8 }
