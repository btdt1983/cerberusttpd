// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package web

import (
	"bytes"
	"net/url"
	"strings"
	"testing"
	"time"
)

// A template error would only show up when a page is first rendered (or as a
// startup panic under systemd), so render every page with sample data.
func TestTemplatesRender(t *testing.T) {
	tpl := newTemplates()
	row := map[string]any{"Name": "folder & \"x\"/", "Href": "x/", "Rename": "/rename?path=x", "Delete": "/delete?path=x", "Full": "x",
		"Icon": "folder", "Download": "x?dl", "Dir": true, "Album": true, "Cover": "/thumb/x/c.jpg?s=t", "Size": int64(0), "MTime": time.Now()}
	file := map[string]any{"Name": "<b>a</b>.txt", "Href": "a.txt", "Rename": "/rename?path=a", "Delete": "/delete?path=a", "Full": "a.txt",
		"Icon": "file", "Download": "a.txt?dl", "Dir": false, "Size": int64(2048), "MTime": time.Now()}
	rows := []any{}
	pages := map[string]any{
		"login":    map[string]any{"Error": "failed"},
		"mfa":      map[string]any{"Enroll": true, "Secret": "ABCD EFGH", "User": "u", "Error": "x"},
		"recovery": map[string]any{"Codes": []string{"aaaaa-bbbbb"}},
		"error":    map[string]any{"Title": "Not found", "Message": "gone"},
		"edit":     map[string]any{"User": "u", "Path": "a/b", "Name": "b", "Back": "/files/a/", "Error": "duplicate"},
		"delete":   map[string]any{"User": "u", "Items": []delItem{{Path: "a", Name: "a", IsDir: true}, {Path: "b", Name: "b", Error: "no"}}, "AnyDir": true, "Back": "/files/"},
		"deleted":  map[string]any{"User": "u", "Failed": []delItem{{Path: "a", Name: "a", Error: "no"}}, "Done": 2, "Retry": "/delete?path=a", "Back": "/files/"},
		"album": map[string]any{"Title": "Trip", "Description": "Two\nlines", "Crumbs": crumbs("Trip"), "User": "u", "Writable": true, "Dir": "Trip",
			"Photos": []photo{{Name: "a.jpg", Alt: "a", Caption: "Sunrise", Full: "/files/Trip/a.jpg", Thumb: "/thumb/Trip/a.jpg?s=t", View: "/thumb/Trip/a.jpg?s=v", Download: "/files/Trip/a.jpg?dl", W: 40, H: 30}}},
		"albumedit": map[string]any{"Title": "Edit Trip", "User": "u", "Dir": "Trip", "Back": "/files/Trip/", "Error": true, "RemoveURL": "/delete?path=Trip%2F.x",
			"Album":  map[string]any{"Title": "Trip", "Description": "d", "Cover": "a.jpg"},
			"Photos": []photo{{Name: "a.jpg", Caption: "c", Thumb: "/thumb/Trip/a.jpg?s=t", Cover: true}, {Name: "b.jpg", Thumb: "/thumb/Trip/b.jpg?s=t"}}},
		"browse": map[string]any{"Title": "Docs", "Crumbs": crumbs("Docs/sub"), "User": "u", "Admin": true, "Path": "/Docs/", "Root": false,
			"Cut": true, "Writable": true, "Dir": "Docs", "Rows": append(rows, file, row),
			"HasAlbum": true, "CanAlbum": true, "AlbumTitle": "Docs"},
	}
	for name, data := range pages {
		var b bytes.Buffer
		if err := tpl.ExecuteTemplate(&b, name, data); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !strings.Contains(b.String(), "<title>") {
			t.Errorf("%s: no <title>", name)
		}
	}
}

func TestBrowseEscapesNames(t *testing.T) {
	var b bytes.Buffer
	data := map[string]any{"Title": "t", "Crumbs": crumbs(""), "User": "u", "Path": "/", "Root": true, "Writable": false, "Dir": "",
		"Rows": []any{map[string]any{"Name": "<script>alert(1)</script>", "Href": rowHref("<script>alert(1)</script>"), "Icon": "file", "Download": "x?dl",
			"Dir": false, "Size": int64(1), "MTime": time.Now()}}}
	if err := newTemplates().ExecuteTemplate(&b, "browse", data); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "<script>alert(1)") {
		t.Fatal("file name was not escaped")
	}
}

func TestCrumbsAndHrefs(t *testing.T) {
	c := crumbs("a b/é/?q/#x/%y/z:w")
	want := []string{"/files/", "/files/a%20b/", "/files/a%20b/%C3%A9/", "/files/a%20b/%C3%A9/%3Fq/",
		"/files/a%20b/%C3%A9/%3Fq/%23x/", "/files/a%20b/%C3%A9/%3Fq/%23x/%25y/", "/files/a%20b/%C3%A9/%3Fq/%23x/%25y/z:w/"}
	if len(c) != len(want) {
		t.Fatalf("got %d crumbs", len(c))
	}
	for i, w := range want {
		if c[i].Href != w {
			t.Errorf("crumb %d: %q want %q", i, c[i].Href, w)
		}
	}
	if !c[len(c)-1].Last || c[0].Last {
		t.Error("Last flag wrong")
	}
	for in, want := range map[string]string{"a b": "a%20b", "x#y": "x%23y", "q?r": "q%3Fr", "p%q": "p%25q", "a:b": "./a:b", "é": "%C3%A9"} {
		if got := rowHref(in); got != want {
			t.Errorf("rowHref(%q) = %q want %q", in, got, want)
		}
	}
}

func TestAlbumEscapesNamesAndCaptions(t *testing.T) {
	evil := `"><script>alert(1)</script>`
	var b bytes.Buffer
	data := map[string]any{"Title": evil, "Description": evil, "Crumbs": crumbs(""), "User": "u", "Writable": false, "Dir": "",
		"Photos": []photo{{Name: evil, Alt: evil, Caption: evil, Full: fileURL("/files/", evil+".jpg"), Thumb: fileURL("/thumb/", evil+".jpg") + "?s=t",
			View: fileURL("/thumb/", evil+".jpg") + "?s=v", Download: fileURL("/files/", evil+".jpg") + "?dl", W: 1, H: 1}}}
	if err := newTemplates().ExecuteTemplate(&b, "album", data); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "<script>alert(1)") {
		t.Fatal("album text was not escaped")
	}
}

func TestFileURL(t *testing.T) {
	for in, want := range map[string]string{
		"a.jpg":             "/thumb/a.jpg",
		"My Trip/é #1?.jpg": "/thumb/My%20Trip/%C3%A9%20%231%3F.jpg",
		"p%q/x.png":         "/thumb/p%25q/x.png",
	} {
		if got := fileURL("/thumb/", in); got != want {
			t.Errorf("fileURL(%q) = %q want %q", in, got, want)
		}
	}
}

func TestAlbumFromForm(t *testing.T) {
	good := url.Values{"title": {"  Trip "}, "description": {"a\r\nb"}, "cover": {"b.jpg"},
		"name": {"b.jpg", "a.jpg", "c.jpg"}, "caption": {"Second", "  ", ""}}
	a, err := albumFromForm(good)
	if err != nil {
		t.Fatal(err)
	}
	if a.Title != "Trip" || a.Description != "a\nb" || a.Cover != "b.jpg" || strings.Join(a.Order, ",") != "b.jpg,a.jpg,c.jpg" {
		t.Errorf("%+v", a)
	}
	if len(a.Captions) != 1 || a.Captions["b.jpg"] != "Second" {
		t.Errorf("captions %v", a.Captions)
	}
	bad := map[string]url.Values{
		"no title":         {"title": {" "}, "name": {"a.jpg"}, "caption": {""}},
		"length mismatch":  {"title": {"t"}, "name": {"a.jpg", "b.jpg"}, "caption": {""}},
		"duplicate name":   {"title": {"t"}, "name": {"a.jpg", "a.jpg"}, "caption": {"", ""}},
		"empty name":       {"title": {"t"}, "name": {""}, "caption": {""}},
		"title too long":   {"title": {strings.Repeat("x", 201)}},
		"description long": {"title": {"t"}, "description": {strings.Repeat("x", 4001)}},
	}
	for name, f := range bad {
		if _, err := albumFromForm(f); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// A cover that is not in the list is dropped rather than stored.
	a, _ = albumFromForm(url.Values{"title": {"t"}, "cover": {"zzz.jpg"}, "name": {"a.jpg"}, "caption": {""}})
	if a.Cover != "" {
		t.Errorf("cover %q", a.Cover)
	}
}

func TestAlbumEditEscapes(t *testing.T) {
	evil := `"><script>alert(1)</script>`
	var b bytes.Buffer
	data := map[string]any{"Title": evil, "User": "u", "Dir": evil, "Back": "/files/", "RemoveURL": "/delete?path=x",
		"Album":  map[string]any{"Title": evil, "Description": evil, "Cover": evil},
		"Photos": []photo{{Name: evil, Caption: evil, Thumb: fileURL("/thumb/", evil) + "?s=t"}}}
	if err := newTemplates().ExecuteTemplate(&b, "albumedit", data); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "<script>alert(1)") {
		t.Fatal("edit form was not escaped")
	}
}
