// Live sidebar: bandwidth chart, who is online and server load, fed by one
// Server-Sent Events stream. Names come from the server, so they only ever go
// into the page through textContent.
(() => {
  const $ = (id) => document.getElementById(id);
  if (!$('side')) return;
  const nf = new Intl.NumberFormat('en-GB', { maximumFractionDigits: 1 });
  const nf0 = new Intl.NumberFormat('en-GB', { maximumFractionDigits: 0 });
  const NS = 'http://www.w3.org/2000/svg';
  const HIST = 120, H = 96, PAD = { l: 4, r: 8, t: 10, b: 18 };

  const rate = (n) => n < 1e3 ? `${nf0.format(n)} B/s` : n < 1e6 ? `${nf.format(n / 1e3)} kB/s`
    : n < 1e9 ? `${nf.format(n / 1e6)} MB/s` : `${nf.format(n / 1e9)} GB/s`;
  const size = (n) => n < 1e6 ? `${nf0.format(n / 1e3)} kB` : n < 1e9 ? `${nf.format(n / 1e6)} MB`
    : n < 1e12 ? `${nf.format(n / 1e9)} GB` : `${nf.format(n / 1e12)} TB`;
  const clock = (t) => new Date(t).toLocaleTimeString('en-GB');
  const dur = (s) => { const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
    return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`; };
  const niceMax = (v) => { const f = Math.max(v, 1e5), p = Math.pow(10, Math.floor(Math.log10(f)));
    return [1, 2, 5, 10].map((m) => m * p).find((m) => m >= f); };
  const el = (name, attrs = {}, text) => { const e = document.createElementNS(NS, name);
    for (const k in attrs) e.setAttribute(k, attrs[k]); if (text != null) e.textContent = text; return e; };

  let hist = [], me = '', hover = null, W = 280;

  // ---- chart -------------------------------------------------------------
  const box = $('chart');
  const svg = el('svg', { role: 'group', tabindex: '0', 'aria-label': 'Bandwidth, last two minutes. Arrow keys show values.', height: H });
  const gGrid = el('g'), gArea = el('g'), gLine = el('g'), gDots = el('g');
  const cross = el('line', { class: 'cross', y1: PAD.t, y2: H - PAD.b });
  const hit = el('rect', { class: 'hit', x: 0, y: 0, height: H, fill: 'transparent' });
  svg.append(gGrid, gArea, gLine, cross, gDots, hit);
  const tip = document.createElement('div'); tip.className = 'tip'; tip.hidden = true;
  box.append(svg, tip);

  const xAt = (i, n) => W - PAD.r - (n - 1 - i) * ((W - PAD.l - PAD.r) / (HIST - 1));
  const yAt = (v, max) => H - PAD.b - (v / max) * (H - PAD.t - PAD.b);

  function draw() {
    W = Math.max(200, box.clientWidth);
    svg.setAttribute('width', W); svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
    hit.setAttribute('width', W);
    for (const g of [gGrid, gArea, gLine, gDots]) g.replaceChildren();
    const n = hist.length; if (!n) return;
    const max = niceMax(Math.max(...hist.map((s) => Math.max(s.in, s.out))));
    for (const f of [0, 0.5, 1]) {
      const y = yAt(max * f, max);
      gGrid.append(el('line', { class: f ? 'grid' : 'axis', x1: PAD.l, x2: W - PAD.r, y1: y, y2: y }));
    }
    gGrid.append(el('text', { class: 'ax', x: PAD.l, y: PAD.t - 1 }, rate(max)));
    gGrid.append(el('text', { class: 'ax', x: PAD.l, y: H - 4 }, '2 min ago'));
    gGrid.append(el('text', { class: 'ax', x: W - PAD.r, y: H - 4, 'text-anchor': 'end' }, 'now'));
    [['out', 1], ['in', 2]].forEach(([k, c]) => {
      const pts = hist.map((s, i) => `${xAt(i, n).toFixed(1)},${yAt(s[k], max).toFixed(1)}`);
      gLine.append(el('polyline', { class: `ln k${c}`, points: pts.join(' ') }));
      gArea.append(el('polygon', { class: `ar k${c}`, points: `${xAt(0, n)},${H - PAD.b} ${pts.join(' ')} ${xAt(n - 1, n)},${H - PAD.b}` }));
      gDots.append(el('circle', { class: `dot k${c}`, cx: xAt(hover ?? n - 1, n), cy: yAt(hist[hover ?? n - 1][k], max), r: 4 }));
    });
    if (hover !== null) {
      const x = xAt(hover, n);
      cross.setAttribute('x1', x); cross.setAttribute('x2', x); cross.style.display = '';
      showTip(hover, x);
    } else { cross.style.display = 'none'; tip.hidden = true; }
  }

  function showTip(i, x) {
    const s = hist[i];
    tip.replaceChildren();
    const t = document.createElement('div'); t.className = 'tt'; t.textContent = clock(s.t); tip.append(t);
    [['Download', s.out, 'k1'], ['Upload', s.in, 'k2']].forEach(([name, v, c]) => {
      const r = document.createElement('div'); r.className = 'tr';
      const key = document.createElement('i'); key.className = `key ${c}`;
      const b = document.createElement('b'); b.textContent = rate(v);
      const l = document.createElement('span'); l.textContent = name;
      r.append(key, b, l); tip.append(r);
    });
    tip.hidden = false;
    tip.style.left = Math.min(Math.max(x - tip.offsetWidth / 2, 0), W - tip.offsetWidth) + 'px';
  }

  const idxFromX = (px) => {
    const n = hist.length, step = (W - PAD.l - PAD.r) / (HIST - 1);
    return Math.min(n - 1, Math.max(0, Math.round(n - 1 - (W - PAD.r - px) / step)));
  };
  hit.addEventListener('pointermove', (e) => { hover = idxFromX(e.clientX - svg.getBoundingClientRect().left); draw(); });
  hit.addEventListener('pointerleave', () => { hover = null; draw(); });
  svg.addEventListener('keydown', (e) => {
    if (!hist.length) return;
    if (e.key === 'ArrowLeft') hover = Math.max(0, (hover ?? hist.length - 1) - 1);
    else if (e.key === 'ArrowRight') hover = Math.min(hist.length - 1, (hover ?? hist.length - 1) + 1);
    else if (e.key === 'Escape') hover = null; else return;
    e.preventDefault(); draw();
  });
  svg.addEventListener('blur', () => { hover = null; draw(); });
  new ResizeObserver(draw).observe(box);

  // ---- panels ------------------------------------------------------------
  function level(pct) { return pct >= 90 ? ['crit', 'critical'] : pct >= 75 ? ['warn', 'high'] : ['ok', '']; }
  function meter(id, textId, pct, detail) {
    const [cls, word] = level(pct);
    const p = $(id); p.value = pct; p.className = cls;
    $(textId).textContent = `${nf0.format(pct)}%${word ? ' · ' + word : ''}${detail ? ' · ' + detail : ''}`;
  }

  function users(list) {
    $('ucount').textContent = list.length ? `(${list.length})` : '';
    const ul = $('users'); ul.replaceChildren();
    for (const u of list) {
      const li = document.createElement('li');
      const dot = document.createElement('i'); dot.className = 'pres ' + (u.idle < 60 ? 'on' : 'off');
      const name = document.createElement('span'); name.className = 'uname';
      name.textContent = u.name + (u.name === me ? ' (you)' : '');
      li.append(dot, name);
      if (u.admin) { const b = document.createElement('span'); b.className = 'badge'; b.textContent = 'admin'; li.append(b); }
      const st = document.createElement('span'); st.className = 'mut small ust';
      const act = u.idle < 60 ? 'active' : `${Math.floor(u.idle / 60)} min idle`;
      st.textContent = act;
      li.append(st); ul.append(li);
    }
  }

  function table() {
    if (!$('bwtable').closest('details').open) return;
    const tb = $('bwtable'); tb.replaceChildren();
    for (const s of hist.slice(-10).reverse()) {
      const tr = document.createElement('tr');
      [clock(s.t), rate(s.out), rate(s.in)].forEach((t, i) => { const td = document.createElement('td'); td.textContent = t; if (i) td.className = 'n'; tr.append(td); });
      tb.append(tr);
    }
  }

  function apply(s) {
    hist.push(s); if (hist.length > HIST) hist.shift();
    $('v-out').textContent = rate(s.out); $('v-in').textContent = rate(s.in);
    $('totals').textContent = `Total since start: ↓ ${size(s.totalOut)} · ↑ ${size(s.totalIn)}`;
    meter('p-cpu', 'm-cpu', s.cpu);
    meter('p-mem', 'm-mem', s.memTotal ? 100 * s.memUsed / s.memTotal : 0, `${size(s.memUsed)} / ${size(s.memTotal)}`);
    $('f-load').textContent = `${s.load.map((x) => nf.format(x)).join(' · ')} (${s.cores} cores)`;
    $('f-up').textContent = dur(s.uptime);
    $('f-tr').textContent = s.transfers ? `${s.transfers} active` : 'none';
    users(s.users || []); table(); draw();
  }

  // ---- stream ------------------------------------------------------------
  let errors = 0;
  const es = new EventSource('/api/stats');
  es.addEventListener('hello', (e) => { const d = JSON.parse(e.data); me = d.me; hist = d.hist || []; errors = 0; if (hist.length) apply(hist.pop()); else draw(); });
  es.addEventListener('stats', (e) => { errors = 0; apply(JSON.parse(e.data)); });
  es.addEventListener('disk', (e) => {
    const d = JSON.parse(e.data), used = d.total - d.avail;
    meter('p-disk', 'm-disk', d.total ? 100 * used / d.total : 0, `${size(d.avail)} free`);
  });
  es.addEventListener('bye', () => { es.close(); $('totals').textContent = 'Session expired. Reload the page to sign in again.'; });
  es.onerror = () => { if (es.readyState === EventSource.CLOSED || ++errors > 3) { es.close(); $('totals').textContent = 'Connection lost. Reload the page.'; } };
})();
