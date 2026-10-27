// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package web

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// A template error would only show up when a page is first rendered (or as a
// startup panic under systemd), so render every page with sample data.
func TestTemplatesRender(t *testing.T) {
	tpl := newTemplates()
	row := map[string]any{"Name": "map & \"x\"/", "Href": "x/", "Rename": "/rename?path=x", "Delete": "/delete?path=x", "Full": "x",
		"Icon": "folder", "Download": "x?dl", "Dir": true, "Size": int64(0), "MTime": time.Now()}
	file := map[string]any{"Name": "<b>a</b>.txt", "Href": "a.txt", "Rename": "/rename?path=a", "Delete": "/delete?path=a", "Full": "a.txt",
		"Icon": "file", "Download": "a.txt?dl", "Dir": false, "Size": int64(2048), "MTime": time.Now()}
	_ = row
	rows := []any{}
	pages := map[string]any{
		"login":    map[string]any{"Error": "fout"},
		"mfa":      map[string]any{"Enroll": true, "Secret": "ABCD EFGH", "User": "u", "Error": "x"},
		"recovery": map[string]any{"Codes": []string{"aaaaa-bbbbb"}},
		"error":    map[string]any{"Title": "Niet gevonden", "Message": "weg"},
		"edit":     map[string]any{"User": "u", "Path": "a/b", "Name": "b", "Back": "/files/a/", "Error": "dubbel"},
		"delete":   map[string]any{"User": "u", "Items": []delItem{{Path: "a", Name: "a", IsDir: true}, {Path: "b", Name: "b", Error: "nee"}}, "AnyDir": true, "Back": "/files/"},
		"deleted":  map[string]any{"User": "u", "Failed": []delItem{{Path: "a", Name: "a", Error: "nee"}}, "Done": 2, "Retry": "/delete?path=a", "Back": "/files/"},
		"browse": map[string]any{"Title": "Docs", "Crumbs": crumbs("Docs/sub"), "User": "u", "Admin": true, "Path": "/Docs/", "Root": false,
			"Cut": true, "Writable": true, "Dir": "Docs", "Rows": append(rows, file, row)},
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
