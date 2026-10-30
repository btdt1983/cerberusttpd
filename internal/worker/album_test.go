// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package worker

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func writeJPEG(t *testing.T, dir, name string, w, h, orientation int) {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{uint8(x * 255 / w), uint8(y * 255 / h), 90, 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, nil); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	if orientation > 1 {
		b = withOrientation(b, orientation, binary.LittleEndian)
	}
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// withOrientation inserts an APP1/EXIF segment right after the SOI marker.
func withOrientation(jpg []byte, o int, bo binary.ByteOrder) []byte {
	var tiff bytes.Buffer
	if bo == binary.LittleEndian {
		tiff.WriteString("II")
	} else {
		tiff.WriteString("MM")
	}
	binary.Write(&tiff, bo, uint16(42))
	binary.Write(&tiff, bo, uint32(8))
	binary.Write(&tiff, bo, uint16(1)) // one entry
	binary.Write(&tiff, bo, uint16(0x0112))
	binary.Write(&tiff, bo, uint16(3)) // SHORT
	binary.Write(&tiff, bo, uint32(1))
	binary.Write(&tiff, bo, uint16(o))
	binary.Write(&tiff, bo, uint16(0))
	binary.Write(&tiff, bo, uint32(0)) // no next IFD
	seg := append([]byte("Exif\x00\x00"), tiff.Bytes()...)
	out := []byte{0xFF, 0xD8, 0xFF, 0xE1, byte((len(seg) + 2) >> 8), byte(len(seg) + 2)}
	out = append(out, seg...)
	return append(out, jpg[2:]...)
}

func TestExifOrientation(t *testing.T) {
	var base bytes.Buffer
	jpeg.Encode(&base, image.NewRGBA(image.Rect(0, 0, 4, 4)), nil)
	for _, bo := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for o := 1; o <= 8; o++ {
			if got := exifOrientation(withOrientation(base.Bytes(), o, bo)); got != o {
				t.Errorf("%v orientation %d: got %d", bo, o, got)
			}
		}
	}
	if exifOrientation(base.Bytes()) != 1 || exifOrientation(nil) != 1 || exifOrientation([]byte("not a jpeg")) != 1 {
		t.Error("missing or invalid EXIF must read as upright")
	}
	// A truncated or hostile segment must not panic.
	b := withOrientation(base.Bytes(), 6, binary.LittleEndian)
	for n := 0; n < 40 && n < len(b); n++ {
		exifOrientation(b[:n])
	}
}

func TestOrient(t *testing.T) {
	// 3x2 picture; pixel (x,y) carries x+10*y in the red channel.
	src := image.NewRGBA(image.Rect(0, 0, 3, 2))
	for y := 0; y < 2; y++ {
		for x := 0; x < 3; x++ {
			src.SetRGBA(x, y, color.RGBA{R: uint8(x + 10*y), A: 255})
		}
	}
	// Orientation 6 = rotate 90 degrees clockwise: the result is 2x3, the
	// top-left corner of the source ends up top-right.
	got := orient(src, 6)
	if got.Bounds().Dx() != 2 || got.Bounds().Dy() != 3 {
		t.Fatalf("bounds %v", got.Bounds())
	}
	if got.RGBAAt(1, 0).R != 0 || got.RGBAAt(0, 0).R != 10 || got.RGBAAt(1, 2).R != 2 {
		t.Errorf("rotate 90 cw wrong: %v %v %v", got.RGBAAt(1, 0), got.RGBAAt(0, 0), got.RGBAAt(1, 2))
	}
	// 8 = 90 counter-clockwise: top-left of the source ends up bottom-left.
	got = orient(src, 8)
	if got.RGBAAt(0, 2).R != 0 || got.RGBAAt(1, 2).R != 10 {
		t.Errorf("rotate 90 ccw wrong")
	}
	if g := orient(src, 3); g.RGBAAt(0, 0).R != 12 {
		t.Errorf("rotate 180 wrong")
	}
	if g := orient(src, 2); g.RGBAAt(0, 0).R != 2 {
		t.Errorf("mirror wrong")
	}
	for o := 1; o <= 8; o++ { // every orientation keeps all pixels
		g := orient(src, o)
		if g.Bounds().Dx()*g.Bounds().Dy() != 6 {
			t.Errorf("orientation %d lost pixels", o)
		}
	}
}

func openRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

// caches gives every test root its own cache directory, like each user has one.
var caches sync.Map // *os.Root -> *thumbCache

func cacheFor(t *testing.T, root *os.Root) *thumbCache {
	c, _ := caches.LoadOrStore(root, &thumbCache{dir: filepath.Join(t.TempDir(), "cache")})
	return c.(*thumbCache)
}

func thumbResp(t *testing.T, root *os.Root, name, variant string) (Response, []byte) {
	t.Helper()
	v, files := thumb(root, cacheFor(t, root), name, variant)
	r := v.(Response)
	if len(files) == 1 {
		defer files[0].Close()
		b, _ := io.ReadAll(files[0])
		return r, b
	}
	return r, r.Data
}

func TestThumbCachesAndOrients(t *testing.T) {
	dir := t.TempDir()
	writeJPEG(t, dir, "wide.jpg", 1600, 800, 6) // stored sideways: shows as 800x1600
	root := openRoot(t, dir)

	if w, h := dimensions(root, "wide.jpg", 1, 1); w != 800 || h != 1600 {
		t.Fatalf("displayed size %dx%d, want 800x1600", w, h)
	}
	r, b := thumbResp(t, root, "wide.jpg", "t")
	if r.Err != "" || r.Kind != "file" {
		t.Fatalf("resp %+v", r)
	}
	img, err := jpeg.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if img.Bounds().Dx() != 320 || img.Bounds().Dy() != 640 {
		t.Errorf("thumb is %v, want 320x640 (upright)", img.Bounds())
	}
	ents, _ := os.ReadDir(cacheFor(t, root).dir)
	if len(ents) != 1 {
		t.Fatalf("cache holds %d entries", len(ents))
	}
	// Second request is served from the cache: the file is not rewritten.
	before, _ := ents[0].Info()
	_, b2 := thumbResp(t, root, "wide.jpg", "t")
	after, _ := os.ReadDir(cacheFor(t, root).dir)
	ai, _ := after[0].Info()
	if len(after) != 1 || !ai.ModTime().Equal(before.ModTime()) || !bytes.Equal(b, b2) {
		t.Error("second request did not come from the cache")
	}
	// A changed source gets a new thumbnail.
	writeJPEG(t, dir, "wide.jpg", 1600, 800, 1)
	_, b3 := thumbResp(t, root, "wide.jpg", "t")
	img3, _ := jpeg.Decode(bytes.NewReader(b3))
	if img3.Bounds().Dx() != 640 || img3.Bounds().Dy() != 320 {
		t.Errorf("changed source still served the old thumbnail: %v", img3.Bounds())
	}
}

func TestThumbVariantsAndSmallOriginal(t *testing.T) {
	dir := t.TempDir()
	writeJPEG(t, dir, "small.jpg", 300, 200, 1)
	writeJPEG(t, dir, "big.jpg", 4000, 3000, 1)
	root := openRoot(t, dir)

	// A picture that is already small enough for the lightbox is served as is.
	_, b := thumbResp(t, root, "small.jpg", "v")
	orig, _ := os.ReadFile(filepath.Join(dir, "small.jpg"))
	if !bytes.Equal(b, orig) {
		t.Error("small original was re-encoded")
	}
	// A thumbnail never scales up.
	_, b = thumbResp(t, root, "small.jpg", "t")
	if img, _ := jpeg.Decode(bytes.NewReader(b)); img.Bounds().Dx() != 300 {
		t.Errorf("small thumb scaled to %v", img.Bounds())
	}
	_, b = thumbResp(t, root, "big.jpg", "v")
	if img, _ := jpeg.Decode(bytes.NewReader(b)); img.Bounds().Dx() != viewSide || img.Bounds().Dy() != 1440 {
		t.Errorf("view is %v", img.Bounds())
	}
	if r, _ := thumbResp(t, root, "big.jpg", "x"); r.Err != "invalid" {
		t.Errorf("unknown variant: %+v", r)
	}
	if r, _ := thumbResp(t, root, "missing.jpg", "t"); r.Err != "notfound" {
		t.Errorf("missing file: %+v", r)
	}
}

// A picture whose header claims an enormous size must be refused before any
// pixel memory is allocated.
func TestThumbRefusesHugeDimensions(t *testing.T) {
	dir := t.TempDir()
	var b bytes.Buffer
	b.WriteString("\x89PNG\r\n\x1a\n")
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], 100000)
	binary.BigEndian.PutUint32(ihdr[4:], 100000)
	ihdr[8], ihdr[9] = 8, 2 // 8 bits, RGB
	chunk := append([]byte("IHDR"), ihdr...)
	binary.Write(&b, binary.BigEndian, uint32(len(ihdr)))
	b.Write(chunk)
	binary.Write(&b, binary.BigEndian, crc32.ChecksumIEEE(chunk))
	if err := os.WriteFile(filepath.Join(dir, "bomb.png"), b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	root := openRoot(t, dir)
	if r, _ := thumbResp(t, root, "bomb.png", "t"); r.Err != "invalid" {
		t.Errorf("huge image accepted: %+v", r)
	}
	if w, _ := dimensions(root, "bomb.png", 1, 1); w != 0 {
		t.Error("huge image listed in an album")
	}
	// Garbage with an image extension is refused, not a crash.
	os.WriteFile(filepath.Join(dir, "junk.jpg"), []byte("hello"), 0o644)
	if r, _ := thumbResp(t, root, "junk.jpg", "t"); r.Err != "invalid" {
		t.Errorf("junk accepted: %+v", r)
	}
	// Not-an-image extensions are never decoded.
	os.WriteFile(filepath.Join(dir, "a.svg"), []byte("<svg/>"), 0o644)
	if r, _ := thumbResp(t, root, "a.svg", "t"); r.Err != "invalid" {
		t.Errorf("svg accepted: %+v", r)
	}
}

// The cache lives outside the shared root, so a read-only root is cached too.
func TestThumbCachedWhenRootIsReadOnly(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores permissions")
	}
	dir := t.TempDir()
	writeJPEG(t, dir, "a.jpg", 1200, 900, 1)
	root := openRoot(t, dir)
	os.Chmod(dir, 0o555)
	defer os.Chmod(dir, 0o755)
	r, b := thumbResp(t, root, "a.jpg", "t")
	if r.Err != "" || r.Kind != "file" || len(b) == 0 {
		t.Fatalf("read-only root: %+v", r)
	}
	if _, err := jpeg.Decode(bytes.NewReader(b)); err != nil {
		t.Error(err)
	}
	if ents, _ := os.ReadDir(cacheFor(t, root).dir); len(ents) != 1 {
		t.Errorf("cache holds %d entries", len(ents))
	}
}

// Where the cache cannot be created the bytes come back directly.
func TestThumbWithoutUsableCache(t *testing.T) {
	dir := t.TempDir()
	writeJPEG(t, dir, "a.jpg", 1200, 900, 1)
	root := openRoot(t, dir)
	blocker := filepath.Join(t.TempDir(), "file")
	os.WriteFile(blocker, []byte("x"), 0o644)
	tc := &thumbCache{dir: filepath.Join(blocker, "sub")} // a file is in the way
	v, files := thumb(root, tc, "a.jpg", "t")
	r := v.(Response)
	if len(files) != 0 || r.Err != "" || r.Kind != "data" || len(r.Data) == 0 {
		t.Fatalf("no cache: %+v files=%d", r, len(files))
	}
	if _, err := jpeg.Decode(bytes.NewReader(r.Data)); err != nil {
		t.Error(err)
	}
	if v, _ := thumb(root, &thumbCache{}, "a.jpg", "t"); v.(Response).Kind != "data" {
		t.Error("empty cache dir must also work")
	}
}

func TestThumbConcurrent(t *testing.T) {
	dir := t.TempDir()
	writeJPEG(t, dir, "a.jpg", 2000, 1500, 1)
	root := openRoot(t, dir)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, b := thumbResp(t, root, "a.jpg", "t")
			if r.Err != "" {
				t.Errorf("resp %+v", r)
			}
			if _, err := jpeg.Decode(bytes.NewReader(b)); err != nil {
				t.Errorf("bad jpeg: %v", err)
			}
		}()
	}
	wg.Wait()
	ents, _ := os.ReadDir(cacheFor(t, root).dir)
	if len(ents) != 1 {
		t.Errorf("cache holds %d entries (leftover temp files?)", len(ents))
	}
}

func TestTransparencyIsFlattened(t *testing.T) {
	img := image.NewNRGBA(image.Rect(0, 0, 10, 10)) // fully transparent
	data, err := encodeThumb(img, 640, 1)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := jpeg.Decode(bytes.NewReader(data))
	r, g, b, _ := out.At(5, 5).RGBA()
	if r>>8 < 250 || g>>8 < 250 || b>>8 < 250 {
		t.Errorf("transparent pixel is not white: %d %d %d", r>>8, g>>8, b>>8)
	}
	var buf bytes.Buffer
	png.Encode(&buf, img)
	if _, err := encodeThumb(image.NewRGBA(image.Rect(0, 0, 0, 0)), 640, 1); err == nil {
		t.Error("empty image accepted")
	}
}

func TestAlbumMergesOrderWithFolder(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"b.jpg", "a.jpg", "c.jpg"} {
		writeJPEG(t, dir, n, 40, 30, 1)
	}
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, "x.heic"), []byte("x"), 0o644)
	root := openRoot(t, dir)

	if r := albumGet(root, "."); r.Album != nil || r.Err != "" {
		t.Fatalf("folder without album: %+v", r)
	}
	a := &Album{Title: "Trip", Order: []string{"c.jpg", "gone.jpg", "c.jpg", "b.jpg"}, Captions: map[string]string{"a.jpg": "Sunrise"}}
	if r := albumSave(root, ".", a, true); r.Err != "" {
		t.Fatalf("create: %+v", r)
	}
	if r := albumSave(root, ".", a, true); r.Err != "exists" {
		t.Errorf("second create: %+v", r)
	}
	r := albumGet(root, ".")
	var names []string
	for _, im := range r.Images {
		names = append(names, im.Name)
	}
	// Stored order first (no duplicates, nothing that is gone), the rest by name.
	if len(names) != 3 || names[0] != "c.jpg" || names[1] != "b.jpg" || names[2] != "a.jpg" {
		t.Errorf("order %v", names)
	}
	if r.Images[2].Caption != "Sunrise" || r.Images[0].W != 40 || r.Images[0].H != 30 || !r.Writable {
		t.Errorf("images %+v writable=%v", r.Images, r.Writable)
	}
	// Updating replaces atomically and leaves no temp files behind.
	a.Title = "Trip 2"
	if r := albumSave(root, ".", a, false); r.Err != "" {
		t.Fatal(r)
	}
	if got := albumGet(root, "."); got.Album.Title != "Trip 2" {
		t.Errorf("title %q", got.Album.Title)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if len(e.Name()) > 6 && e.Name()[:6] == partPrefix {
			t.Errorf("leftover %s", e.Name())
		}
	}
}

func TestAlbumValidationAndBrokenFile(t *testing.T) {
	dir := t.TempDir()
	root := openRoot(t, dir)
	for _, a := range []*Album{
		nil,
		{Cover: "../x.jpg"},
		{Order: []string{"a/b.jpg"}},
		{Captions: map[string]string{".cerb-x.part": "x"}},
		{Title: string(make([]byte, 0)) + "\xff"},
	} {
		if r := albumSave(root, ".", a, false); r.Err != "invalid" {
			t.Errorf("%+v accepted: %+v", a, r)
		}
	}
	os.WriteFile(filepath.Join(dir, albumFile), []byte("{not json"), 0o644)
	if r := albumGet(root, "."); r.Err != "invalid" {
		t.Errorf("broken album file: %+v", r)
	}
	os.WriteFile(filepath.Join(dir, albumFile), bytes.Repeat([]byte(" "), maxAlbumJSON+10), 0o644)
	if r := albumGet(root, "."); r.Err != "invalid" {
		t.Errorf("oversized album file: %+v", r)
	}
}

func TestListMarksAlbumsAndCovers(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"plain", "withcover", "nocover"} {
		os.Mkdir(filepath.Join(dir, d), 0o755)
	}
	root := openRoot(t, dir)
	if r := albumSave(root, "withcover", &Album{Title: "A", Cover: "x.jpg"}, true); r.Err != "" {
		t.Fatal(r)
	}
	if r := albumSave(root, "nocover", &Album{Title: "B"}, true); r.Err != "" {
		t.Fatal(r)
	}
	got := map[string]Entry{}
	for _, e := range list(root, ".").Entries {
		got[e.Name] = e
	}
	if got["plain"].Album || !got["withcover"].Album || !got["nocover"].Album {
		t.Errorf("album flags: %+v", got)
	}
	if got["withcover"].Cover != "" || got["nocover"].Cover != "" {
		t.Errorf("a cover that does not exist was passed on: %+v", got)
	}
	// Once the picture exists it is passed on; deleted again, it is dropped.
	writeJPEG(t, filepath.Join(dir, "withcover"), "x.jpg", 10, 10, 1)
	found := func() string {
		for _, e := range list(root, ".").Entries {
			if e.Name == "withcover" {
				return e.Cover
			}
		}
		return "?"
	}
	if found() != "x.jpg" {
		t.Errorf("cover: %q", found())
	}
	os.Remove(filepath.Join(dir, "withcover", "x.jpg"))
	if found() != "" {
		t.Errorf("deleted cover still passed on: %q", found())
	}
	// A cover name that is not a plain file name is never passed on.
	os.WriteFile(filepath.Join(dir, "plain", albumFile), []byte(`{"title":"t","cover":"../../etc/passwd"}`), 0o644)
	for _, e := range list(root, ".").Entries {
		if e.Name == "plain" && e.Cover != "" {
			t.Errorf("hostile cover passed on: %q", e.Cover)
		}
	}
}

func TestCacheHitRefreshesAndPruneDropsOldOnes(t *testing.T) {
	dir := t.TempDir()
	writeJPEG(t, dir, "a.jpg", 1200, 900, 1)
	root := openRoot(t, dir)
	tc := cacheFor(t, root)
	thumbResp(t, root, "a.jpg", "t")
	ents, _ := os.ReadDir(tc.dir)
	if len(ents) != 1 {
		t.Fatalf("cache holds %d entries", len(ents))
	}
	used := filepath.Join(tc.dir, ents[0].Name())
	// Unused for 3 days: a hit marks it as used now, so pruning keeps it.
	old := time.Now().Add(-72 * time.Hour)
	os.Chtimes(used, old, old)
	thumbResp(t, root, "a.jpg", "t")
	if fi, _ := os.Stat(used); time.Since(fi.ModTime()) > time.Hour {
		t.Error("a cache hit did not refresh the modification time")
	}
	stale := filepath.Join(tc.dir, "0123456789abcdef0123456789abcdef.jpg")
	os.WriteFile(stale, []byte("x"), 0o600)
	tmp := filepath.Join(tc.dir, ".tmp-leftover")
	os.WriteFile(tmp, []byte("x"), 0o600)
	veryOld := time.Now().Add(-thumbMaxAge - time.Hour)
	os.Chtimes(stale, veryOld, veryOld)
	os.Chtimes(tmp, time.Now().Add(-2*time.Hour), time.Now().Add(-2*time.Hour))
	pruneThumbs(tc.dir)
	for _, gone := range []string{stale, tmp} {
		if _, err := os.Stat(gone); err == nil {
			t.Errorf("%s was not pruned", filepath.Base(gone))
		}
	}
	if _, err := os.Stat(used); err != nil {
		t.Error("a recently used thumbnail was pruned")
	}
	pruneThumbs(filepath.Join(dir, "does-not-exist")) // no cache yet: nothing to do
}

func TestDecodeBudgetLimitsHugePicturesNotSmallOnes(t *testing.T) {
	b := newBudget(64)
	b.acquire(48)
	b.acquire(12) // fits next to it
	blocked := make(chan struct{})
	go func() { b.acquire(48); close(blocked) }() // a second huge one has to wait
	select {
	case <-blocked:
		t.Fatal("two huge pictures decode at the same time")
	case <-time.After(100 * time.Millisecond):
	}
	b.release(48)
	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("waiting picture was never woken up")
	}
	if got := decodeCost(image.Config{Width: 8000, Height: 6000}); got != 48 {
		t.Errorf("48 MP costs %d", got)
	}
	if got := decodeCost(image.Config{Width: 10, Height: 10}); got != 1 {
		t.Errorf("tiny picture costs %d", got)
	}
	if got := decodeCost(image.Config{Width: 20000, Height: 20000}); got != 64 {
		t.Errorf("cost is not capped at the budget: %d", got)
	}
}
