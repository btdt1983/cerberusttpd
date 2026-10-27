// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package web

import "html/template"

func newTemplates() *template.Template {
	return template.Must(template.New("").Funcs(funcs).Parse(pages))
}

const pages = `
{{define "head"}}<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>{{.}} · Cerberusttpd</title><link rel="icon" href="/static/favicon.svg" type="image/svg+xml"><link rel="stylesheet" href="/static/app.css"></head><body>{{end}}
{{define "login"}}{{template "head" "Sign in"}}
<form class="login card" method="post" action="/login">
<div class="brandmark"><svg width="28" height="28" viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="7" fill="currentColor"/><circle cx="9" cy="16" r="3.2" fill="#fff"/><circle cx="16" cy="16" r="3.2" fill="#fff"/><circle cx="23" cy="16" r="3.2" fill="#fff"/></svg><h2>Cerberusttpd</h2></div><p class="mut">Sign in with your Linux account.</p>
<label for="user">Username</label><input id="user" name="user" autocomplete="username" autocapitalize="none" required autofocus>
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required>
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
<button type="submit">Sign in</button>
</form></body></html>{{end}}
{{define "mfa"}}{{template "head" "Two-factor authentication"}}
<div class="login card">
{{if .Enroll}}<h2>Set up two-factor authentication</h2>
<p class="mut">Scan the QR code with an authenticator app (for example Aegis, FreeOTP, Google Authenticator or Microsoft Authenticator) and enter the 6-digit code.</p>
<p><img src="/2fa/qr.png" width="256" height="256" alt="QR code for your authenticator app"></p>
<p class="mut">Cannot scan it? Enter this key instead: <code>{{.Secret}}</code></p>
{{else}}<h2>Two-factor authentication</h2><p class="mut">Enter the code from your authenticator app, {{.User}}. A recovery code works too.</p>{{end}}
<form method="post" action="/2fa">
<label for="code">Code</label><input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" autocapitalize="none" maxlength="16" required autofocus>
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
<button type="submit">{{if .Enroll}}Confirm{{else}}Continue{{end}}</button>
</form>
<form method="post" action="/logout"><button class="link" type="submit">Cancel</button></form>
</div></body></html>{{end}}
{{define "recovery"}}{{template "head" "Recovery codes"}}
<div class="login card"><h2>Save your recovery codes</h2>
<p class="mut">A recovery code lets you sign in if you lose your phone. Each code works once. You will only see this list once.</p>
<pre class="codes">{{range .Codes}}{{.}}
{{end}}</pre>
<p><a href="/files/">I have saved them, continue</a></p></div></body></html>{{end}}
{{define "edit"}}{{template "head" "Rename"}}
<header><b>Cerberusttpd</b><span class="mut">{{.User}}{{if .Admin}} · admin{{end}}</span></header>
<main><div class="card">
<h2>Rename</h2><p class="mut">{{.Path}}</p>
<form method="post" action="/rename"><input type="hidden" name="path" value="{{.Path}}">
<label for="name">New name</label><input id="name" name="name" value="{{if .Value}}{{.Value}}{{else}}{{.Name}}{{end}}" required maxlength="255" autofocus>
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
<button type="submit">Rename</button> &nbsp; <a href="{{.Back}}">Cancel</a></form>
</div></main></body></html>{{end}}
{{define "delete"}}{{template "head" "Delete"}}
<header><b>Cerberusttpd</b><span class="mut">{{.User}}{{if .Admin}} · admin{{end}}</span></header>
<main><div class="card"><h2>Delete</h2>
<p>Are you sure you want to delete {{if eq (len .Items) 1}}this item{{else}}these {{len .Items}} items{{end}}? This cannot be undone.</p>
<ul class="items">{{range .Items}}<li>{{.Name}}{{if .IsDir}}/{{end}}{{if .Error}} <span class="err">{{.Error}}</span>{{end}}</li>{{end}}</ul>
<form method="post" action="/delete">{{range .Items}}{{if not .Error}}<input type="hidden" name="path" value="{{.Path}}">{{end}}{{end}}
{{if .AnyDir}}<label class="chk"><input type="checkbox" name="recursive" value="1"> Also delete everything inside folders</label>{{end}}
<button class="danger" type="submit">Delete</button> &nbsp; <a href="{{.Back}}">Cancel</a></form>
</div></main></body></html>{{end}}
{{define "deleted"}}{{template "head" "Delete"}}
<header><b>Cerberusttpd</b><span class="mut">{{.User}}{{if .Admin}} · admin{{end}}</span></header>
<main><div class="card"><h2>Not everything was deleted</h2>
<p class="mut">{{.Done}} succeeded, {{len .Failed}} failed:</p>
<ul class="items">{{range .Failed}}<li>{{.Path}} <span class="err">{{.Error}}</span></li>{{end}}</ul>
<p><a href="{{.Retry}}">Try again</a> &nbsp; <a href="{{.Back}}">Back to the folder</a></p>
</div></main></body></html>{{end}}
{{define "error"}}{{template "head" .Title}}
<header><b>Cerberusttpd</b><a href="/files/">To my files</a></header>
<main><div class="card"><h2>{{.Title}}</h2><p>{{.Message}}</p><p><a href="/files/">Back to the files</a></p></div></main></body></html>{{end}}
{{define "sprite"}}<svg class="sprite" aria-hidden="true" focusable="false"><symbol id="i-folder" viewBox="0 0 24 24"><path d="M3 6.5A2.5 2.5 0 0 1 5.5 4h3.9c.5 0 1 .2 1.3.6L12 6h6.5A2.5 2.5 0 0 1 21 8.5v9a2.5 2.5 0 0 1-2.5 2.5h-13A2.5 2.5 0 0 1 3 17.5z"/></symbol><symbol id="i-file" viewBox="0 0 24 24"><path d="M7 3h6.5L19 8.5V19a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z"/><path class="ln" d="M13 3v6h6"/></symbol><symbol id="i-image" viewBox="0 0 24 24"><rect x="3.5" y="4.5" width="17" height="15" rx="2.5"/><circle class="cut" cx="9" cy="10" r="1.6"/><path class="cut" d="M5 18l4.5-4.5 3 3 2.5-2.5L20 18.5z"/></symbol><symbol id="i-archive" viewBox="0 0 24 24"><rect x="4" y="3.5" width="16" height="17" rx="2.5"/><path class="cut" d="M11 5h2v2h-2zm0 3h2v2h-2zm0 3h2v2h-2zm-1 3h4v3a2 2 0 0 1-4 0z"/></symbol><symbol id="i-media" viewBox="0 0 24 24"><rect x="3.5" y="4.5" width="17" height="15" rx="2.5"/><path class="cut" d="M10 9l5 3-5 3z"/></symbol><symbol id="i-dl" viewBox="0 0 24 24"><path class="ln" d="M12 4v11m0 0l-4-4m4 4l4-4M5 19h14"/></symbol></svg>{{end}}
{{define "browse"}}{{template "head" .Title}}
<header><b>Cerberusttpd</b><form method="post" action="/logout"><span class="mut">{{.User}}{{if .Admin}} · admin{{end}}</span> &nbsp; <button class="link" type="submit">Sign out</button></form></header>
<div class="layout">{{template "sprite"}}<main data-dir="{{.Dir}}">
{{if .Writable}}<div class="card up"><label class="drop" id="drop"><input id="pick" type="file" multiple hidden>Drag files here or <u>choose files</u> to upload</label>
<ul id="uploads"></ul>
<form class="inline" method="post" action="/mkdir"><input type="hidden" name="dir" value="{{.Dir}}"><input name="name" placeholder="New folder" required maxlength="255"><button type="submit">Create</button></form></div>{{end}}
<div class="card"><nav class="crumbs" aria-label="Path">{{range $i, $c := .Crumbs}}{{if $i}}<span aria-hidden="true">/</span>{{end}}{{if $c.Last}}<b>{{$c.Name}}</b>{{else}}<a href="{{$c.Href}}">{{$c.Name}}</a>{{end}}{{end}}</nav>
<input type="search" id="filter" class="filter" placeholder="Filter by name…" aria-label="Filter by name" autocomplete="off">
{{if .Writable}}<form method="get" action="/delete" id="sel">{{end}}<table><thead><tr>{{if .Writable}}<th class="chkcol"><input type="checkbox" id="all" aria-label="Select all"></th>{{end}}<th>Name</th><th class="n">Size</th><th class="n mt">Modified</th>{{if .Writable}}<th class="n"></th>{{end}}</tr></thead><tbody>
{{if not .Root}}<tr>{{if .Writable}}<td></td>{{end}}<td class="nm"><svg class="ico folder"><use href="#i-folder"/></svg><a href="../">..</a></td><td></td><td class="mt"></td>{{if .Writable}}<td></td>{{end}}</tr>{{end}}
{{range .Rows}}<tr>{{if $.Writable}}<td class="chkcol"><input type="checkbox" name="path" value="{{.Full}}" aria-label="Select {{.Name}}"></td>{{end}}<td class="nm"><svg class="ico {{.Icon}}"><use href="#i-{{.Icon}}"/></svg><a href="{{.Href}}">{{.Name}}</a></td><td class="n">{{if not .Dir}}{{size .Size}} <a class="dl" href="{{.Download}}" title="Download" aria-label="Download {{.Name}}"><svg class="ico sm"><use href="#i-dl"/></svg></a>{{end}}</td><td class="n mt">{{.MTime.Format "2006-01-02 15:04"}}</td>{{if $.Writable}}<td class="n act"><a href="{{.Rename}}">Rename</a> <a href="{{.Delete}}">Delete</a></td>{{end}}</tr>
{{else}}<tr><td colspan="5" class="mut">This folder is empty.</td></tr>{{end}}
</tbody></table>{{if .Writable}}<p><button class="danger" type="submit" id="delsel" disabled>Delete selected</button></p></form>{{end}}{{if .Cut}}<p class="mut">List truncated.</p>{{end}}</div></main>
<aside id="side" aria-label="Server status">
<section class="card side"><h3>Network</h3>
<div class="figs"><div><span class="lbl"><i class="key k1"></i>Download</span><b id="v-out">–</b></div><div><span class="lbl"><i class="key k2"></i>Upload</span><b id="v-in">–</b></div></div>
<div class="chart" id="chart"></div>
<p class="mut small" id="totals"></p>
<details class="tbl"><summary>Table</summary><table><thead><tr><th>Time</th><th class="n">Download</th><th class="n">Upload</th></tr></thead><tbody id="bwtable"></tbody></table></details>
</section>
<section class="card side"><h3>Online <span class="mut" id="ucount"></span></h3><ul class="users" id="users"></ul></section>
<section class="card side"><h3>Server</h3>
<div class="meter"><div class="mrow"><span>Processor</span><b id="m-cpu">–</b></div><progress id="p-cpu" max="100" value="0" aria-labelledby="m-cpu"></progress></div>
<div class="meter"><div class="mrow"><span>Memory</span><b id="m-mem">–</b></div><progress id="p-mem" max="100" value="0" aria-labelledby="m-mem"></progress></div>
<div class="meter"><div class="mrow"><span>Disk (free for you)</span><b id="m-disk">–</b></div><progress id="p-disk" max="100" value="0" aria-labelledby="m-disk"></progress></div>
<dl class="facts"><dt>Load</dt><dd id="f-load">–</dd><dt>Uptime</dt><dd id="f-up">–</dd><dt>Transfers</dt><dd id="f-tr">–</dd></dl>
</section>
</aside></div>{{if .Writable}}<script src="/static/upload.js"></script><script src="/static/select.js"></script>{{end}}<script src="/static/filter.js"></script><script src="/static/sidebar.js"></script></body></html>{{end}}
`
