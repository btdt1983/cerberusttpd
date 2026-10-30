// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package worker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	_ "image/gif"
	"image/jpeg"
	_ "image/png"
	"io"
	"os"
	"path"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	xdraw "golang.org/x/image/draw"
	_ "golang.org/x/image/webp"
	"golang.org/x/sys/unix"
)

// An album is a folder with a metadata file next to the pictures. The file
// only adds a title, a description, an order and captions: the pictures are
// whatever image files the folder holds now, so renaming, deleting and
// uploading never have to know about albums.
//
// The file name must not start with partPrefix: the janitor removes orphaned
// ".cerb-*.json" files.
const (
	albumFile      = ".cerberusttpd-album.json"
	maxAlbumJSON   = 1 << 20
	maxAlbumImages = 5000
	maxImageBytes  = 100 << 20 // larger sources are not decoded
	maxImagePixels = 60_000_000
	thumbSide      = 640
	viewSide       = 1920
	maxAlbumCovers = 60 // folder lists look at this many albums for a cover
)

type Album struct {
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	Cover       string            `json:"cover,omitempty"`
	Order       []string          `json:"order,omitempty"`
	Captions    map[string]string `json:"captions,omitempty"`
}

// Image is one picture of an album; W and H are as displayed, so with the
// EXIF orientation already applied.
type Image struct {
	Name    string `json:"name"`
	W       int    `json:"w"`
	H       int    `json:"h"`
	Caption string `json:"caption,omitempty"`
	Size    int64  `json:"size"`
	MTime   int64  `json:"mtime"` // unix nanoseconds; part of the thumbnail URL so a replaced picture is fetched again
}

// IsImage reports whether the browser UI can show name as a picture. SVG is
// left out on purpose (it is active content), HEIC has no decoder.
func IsImage(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".jpg", ".jpeg", ".png", ".gif", ".webp":
		return true
	}
	return false
}

// AlbumFile is the name of the metadata file inside an album folder.
const AlbumFile = albumFile

// cacheDir is where one user's thumbnails live: outside the shared root (which
// may be read-only or shared with others), in the user's own home. The worker
// creates it on first use; if that fails, thumbnails are made on the fly.
type thumbCache struct {
	dir  string
	mu   sync.Mutex
	root *os.Root
}

func (c *thumbCache) get() *os.Root {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.root == nil && c.dir != "" && os.MkdirAll(c.dir, 0o700) == nil {
		c.root, _ = os.OpenRoot(c.dir)
	}
	return c.root
}

// Decoding untrusted pictures is the memory-hungry part (a 48 MP photo needs
// roughly 450 MB for the lightbox size), so concurrent decodes share a budget
// counted in megapixels: many small ones in parallel, but not two huge ones.
const decodeBudgetMP = 64

type budget struct {
	mu   sync.Mutex
	cond *sync.Cond
	free int
}

func newBudget(n int) *budget {
	b := &budget{free: n}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *budget) acquire(n int) {
	b.mu.Lock()
	for b.free < n {
		b.cond.Wait()
	}
	b.free -= n
	b.mu.Unlock()
}

func (b *budget) release(n int) {
	b.mu.Lock()
	b.free += n
	b.mu.Unlock()
	b.cond.Broadcast()
}

var decodeBudget = newBudget(decodeBudgetMP)

// decodeCost is a picture's share of the budget: one unit per started megapixel.
func decodeCost(cfg image.Config) int {
	return min(decodeBudgetMP, max(1, (cfg.Width*cfg.Height+999_999)/1_000_000))
}

func readAlbum(root *os.Root, dir string) (*Album, error) {
	f, err := root.OpenFile(path.Join(dir, albumFile), os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxAlbumJSON+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxAlbumJSON {
		return nil, errors.New("album file too large")
	}
	var a Album
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// albumGet returns the album in dir and its pictures in display order: the
// stored order first (skipping what is gone), the rest by name.
func albumGet(root *os.Root, dir string) Response {
	a, err := readAlbum(root, dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Response{} // no album here
		}
		// Present but unreadable or broken: show the folder as a plain list.
		return Response{Err: "invalid"}
	}
	d, err := root.Open(dir)
	if err != nil {
		return Response{Err: errCode(err)}
	}
	defer d.Close()
	ents, err := d.ReadDir(-1)
	if err != nil && len(ents) == 0 {
		return Response{Err: errCode(err)}
	}
	byName := map[string]Image{}
	var names []string
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, partPrefix) || !IsImage(n) {
			continue
		}
		fi, err := e.Info()
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if len(names) >= maxAlbumImages {
			break
		}
		w, h := dimensions(root, path.Join(dir, n), fi.Size(), fi.ModTime().UnixNano())
		if w == 0 {
			continue // not a picture we can read
		}
		byName[n] = Image{Name: n, W: w, H: h, Size: fi.Size(), MTime: fi.ModTime().UnixNano(), Caption: a.Captions[n]}
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
	var imgs []Image
	seen := map[string]bool{}
	for _, n := range a.Order {
		if im, ok := byName[n]; ok && !seen[n] {
			imgs = append(imgs, im)
			seen[n] = true
		}
	}
	for _, n := range names {
		if !seen[n] {
			imgs = append(imgs, byName[n])
		}
	}
	resp := Response{Kind: "album", Album: a, Images: imgs}
	resp.Writable = syscall.Access("/proc/self/fd/"+fdNum(d), 3) == nil
	return resp
}

func fdNum(f *os.File) string { return fmt.Sprint(int(f.Fd())) }

var dimMemo sync.Map // "name|size|mtime" -> [2]int

// dimensions reads only the headers: width and height as displayed.
func dimensions(root *os.Root, name string, size, mtime int64) (int, int) {
	key := fmt.Sprintf("%s|%d|%d", name, size, mtime)
	if v, ok := dimMemo.Load(key); ok {
		d := v.([2]int)
		return d[0], d[1]
	}
	w, h := 0, 0
	if f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0); err == nil {
		cfg, _, o := configOf(f)
		if cfg.Width > 0 && cfg.Height > 0 && cfg.Width*cfg.Height <= maxImagePixels {
			w, h = cfg.Width, cfg.Height
			if swapsAxes(o) {
				w, h = h, w
			}
		}
		f.Close()
	}
	dimMemo.Store(key, [2]int{w, h})
	return w, h
}

// configOf reads the image header and, for JPEG, the orientation.
func configOf(f *os.File) (image.Config, string, int) {
	head := make([]byte, 64<<10)
	n, _ := f.ReadAt(head, 0)
	head = head[:n]
	cfg, format, err := image.DecodeConfig(io.NewSectionReader(f, 0, maxImageBytes))
	if err != nil {
		return image.Config{}, "", 1
	}
	o := 1
	if format == "jpeg" {
		o = exifOrientation(head)
	}
	return cfg, format, o
}

func validAlbum(a *Album) bool {
	if utf8.RuneCountInString(a.Title) > 200 || utf8.RuneCountInString(a.Description) > 4000 || !utf8.ValidString(a.Title+a.Description) {
		return false
	}
	if a.Cover != "" && !validName(a.Cover) {
		return false
	}
	if len(a.Order) > maxAlbumImages*2 || len(a.Captions) > maxAlbumImages*2 {
		return false
	}
	for _, n := range a.Order {
		if !validName(n) {
			return false
		}
	}
	for n, c := range a.Captions {
		if !validName(n) || utf8.RuneCountInString(c) > 500 || !utf8.ValidString(c) {
			return false
		}
	}
	return true
}

// albumSave writes the metadata file atomically. With create it refuses to
// replace an existing album.
func albumSave(root *os.Root, dir string, a *Album, create bool) Response {
	if a == nil || !validAlbum(a) {
		return Response{Err: "invalid"}
	}
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil || len(b) > maxAlbumJSON {
		return Response{Err: "invalid"}
	}
	tmp := path.Join(dir, partPrefix+randID()+".part") // the janitor sweeps it if we crash
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return Response{Err: errCode(err)}
	}
	_, werr := f.Write(b)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		root.Remove(tmp)
		return Response{Err: errCode(werr)}
	}
	if create {
		d, err := root.Open(dir)
		if err != nil {
			root.Remove(tmp)
			return Response{Err: errCode(err)}
		}
		defer d.Close()
		fd := int(d.Fd())
		err = unix.Renameat2(fd, path.Base(tmp), fd, albumFile, unix.RENAME_NOREPLACE)
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOSYS) {
			if _, serr := root.Lstat(path.Join(dir, albumFile)); serr == nil {
				err = syscall.EEXIST
			} else {
				err = unix.Renameat(fd, path.Base(tmp), fd, albumFile)
			}
		}
		if err != nil {
			root.Remove(tmp)
			return Response{Err: errCode(&os.PathError{Op: "rename", Path: dir, Err: err})}
		}
		return Response{}
	}
	if err := root.Rename(tmp, path.Join(dir, albumFile)); err != nil {
		root.Remove(tmp)
		return Response{Err: errCode(err)}
	}
	return Response{}
}

// thumb answers with an open file holding a JPEG (or, for small sources, the
// original) no larger than the variant's side: "t" for the grid, "v" for the
// lightbox. Results are cached in the user's cache directory; where the cache cannot be written
// the bytes come back in Response.Data instead.
func thumb(root *os.Root, tc *thumbCache, name, variant string) (any, []*os.File) {
	side := thumbSide
	switch variant {
	case "t":
	case "v":
		side = viewSide
	default:
		return Response{Err: "invalid"}, nil
	}
	if !IsImage(name) {
		return Response{Err: "invalid"}, nil
	}
	src, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return Response{Err: errCode(err)}, nil
	}
	defer src.Close()
	fi, err := src.Stat()
	if err != nil {
		return Response{Err: errCode(err)}, nil
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxImageBytes {
		return Response{Err: "invalid"}, nil
	}

	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%d\x00%s", name, fi.Size(), fi.ModTime().UnixNano(), variant)))
	cache := hex.EncodeToString(sum[:16]) + ".jpg"
	cr := tc.get()
	if r, f := cached(cr, cache); f != nil {
		return r, []*os.File{f}
	}

	cfg, format, o := configOf(src)
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width*cfg.Height > maxImagePixels {
		return Response{Err: "invalid"}, nil
	}
	// The browser shows a picture that is small enough, or animated, as it is
	// (it applies the EXIF orientation itself).
	if variant == "v" && (format == "gif" || max(cfg.Width, cfg.Height) <= side) {
		f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
		if err != nil {
			return Response{Err: errCode(err)}, nil
		}
		return Response{Kind: "file", Name: path.Base(name), Size: fi.Size(), MTime: fi.ModTime().UnixNano()}, []*os.File{f}
	}
	cost := decodeCost(cfg)
	decodeBudget.acquire(cost)
	defer decodeBudget.release(cost)
	if cost >= 8 {
		// A worker lives as long as the session: hand the big buffers back when done.
		defer debug.FreeOSMemory()
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return Response{Err: "internal"}, nil
	}
	img, _, err := image.Decode(io.LimitReader(src, maxImageBytes))
	if err != nil {
		return Response{Err: "invalid"}, nil
	}
	data, err := encodeThumb(img, side, o)
	if err != nil {
		return Response{Err: "internal"}, nil
	}
	if writeCache(cr, cache, data) == nil {
		if r, f := cached(cr, cache); f != nil {
			return r, []*os.File{f}
		}
	}
	return Response{Kind: "data", Data: data, MTime: fi.ModTime().UnixNano()}, nil
}

func cached(root *os.Root, cache string) (Response, *os.File) {
	if root == nil {
		return Response{}, nil
	}
	f, err := root.OpenFile(cache, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return Response{}, nil
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() == 0 {
		f.Close()
		return Response{}, nil
	}
	// The modification time doubles as "last used", for the janitor.
	if time.Since(fi.ModTime()) > 24*time.Hour {
		now := time.Now()
		if root.Chtimes(cache, now, now) == nil {
			fi, _ = f.Stat()
		}
	}
	return Response{Kind: "file", Size: fi.Size(), MTime: fi.ModTime().UnixNano()}, f
}

func writeCache(root *os.Root, cache string, data []byte) error {
	if root == nil {
		return errors.New("no cache")
	}
	tmp := ".tmp-" + randID()
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = root.Rename(tmp, cache)
	}
	if werr != nil {
		root.Remove(tmp)
	}
	return werr
}

// encodeThumb scales img down to side pixels on its longest edge (never up),
// applies the EXIF orientation and encodes a JPEG. Transparency is flattened
// onto white.
func encodeThumb(img image.Image, side, orientation int) ([]byte, error) {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w <= 0 || h <= 0 {
		return nil, errors.New("empty image")
	}
	dw, dh := w, h
	if m := max(w, h); m > side {
		dw, dh = max(1, w*side/m), max(1, h*side/m)
	}
	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	draw.Draw(dst, dst.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	xdraw.BiLinear.Scale(dst, dst.Bounds(), img, b, xdraw.Over, nil)
	out := orient(dst, orientation)
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, out, &jpeg.Options{Quality: 82}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// orient turns an image upright according to its EXIF orientation value.
func orient(src *image.RGBA, o int) *image.RGBA {
	if o <= 1 || o > 8 {
		return src
	}
	w, h := src.Bounds().Dx(), src.Bounds().Dy()
	dw, dh := w, h
	if swapsAxes(o) {
		dw, dh = h, w
	}
	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	for y := 0; y < dh; y++ {
		for x := 0; x < dw; x++ {
			var sx, sy int
			switch o {
			case 2:
				sx, sy = w-1-x, y
			case 3:
				sx, sy = w-1-x, h-1-y
			case 4:
				sx, sy = x, h-1-y
			case 5:
				sx, sy = y, x
			case 6:
				sx, sy = y, h-1-x
			case 7:
				sx, sy = w-1-y, h-1-x
			case 8:
				sx, sy = w-1-y, x
			}
			dst.SetRGBA(x, y, src.RGBAAt(sx, sy))
		}
	}
	return dst
}
