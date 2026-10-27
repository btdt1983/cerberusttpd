// Resumable uploads with the tus protocol (creation extension). The upload URL
// is remembered per file, so an interrupted or reloaded upload continues
// where it stopped.
(() => {
  const dir = document.querySelector('[data-dir]').dataset.dir;
  const drop = document.getElementById('drop');
  const pick = document.getElementById('pick');
  const list = document.getElementById('uploads');
  const CHUNK = 8 * 1024 * 1024;
  const H = { 'Tus-Resumable': '1.0.0' };
  const store = {
    get: (k) => { try { return localStorage.getItem(k); } catch { return null; } },
    set: (k, v) => { try { localStorage.setItem(k, v); } catch {} },
    del: (k) => { try { localStorage.removeItem(k); } catch {} },
  };
  const b64 = (s) => btoa(String.fromCharCode(...new TextEncoder().encode(s)));
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  function row(name) {
    const li = document.createElement('li');
    const label = document.createElement('span');
    const state = document.createElement('span');
    const bar = document.createElement('progress');
    label.textContent = name;
    bar.max = 100; bar.value = 0;
    li.append(label, state, bar);
    list.append(li);
    return { bar, state, li };
  }

  async function status(url) {
    const r = await fetch(url, { method: 'HEAD', headers: H });
    return r.ok ? parseInt(r.headers.get('Upload-Offset'), 10) : null;
  }

  async function create(file) {
    const r = await fetch('/tus/', {
      method: 'POST',
      headers: { ...H, 'Upload-Length': String(file.size),
        'Upload-Metadata': `filename ${b64(file.name)},dir ${b64(dir)}` },
    });
    if (r.status === 409) throw new Error('bestaat al');
    if (r.status === 403) throw new Error('geen schrijfrechten');
    if (!r.ok) throw new Error((await r.text()).trim() || `fout ${r.status}`);
    return r.headers.get('Location');
  }

  async function send(file, ui) {
    const key = `tus:${dir}|${file.name}|${file.size}|${file.lastModified}`;
    let url = store.get(key), offset = null;
    if (url) { try { offset = await status(url); } catch {} }
    if (offset === null) { url = await create(file); store.set(key, url); offset = 0; }
    if (file.size === 0) { store.del(key); return; } // the server completes empty files on create
    let tries = 0;
    // The upload counts as done only when a PATCH ends at file.size: the server
    // answers 204 for that only after it has really created the file. Resuming
    // at offset == size sends an empty PATCH, which makes the server finish.
    for (;;) {
      const end = Math.min(offset + CHUNK, file.size);
      try {
        const r = await fetch(url, {
          method: 'PATCH',
          headers: { ...H, 'Content-Type': 'application/offset+octet-stream', 'Upload-Offset': String(offset) },
          body: file.slice(offset, end),
        });
        if (r.status === 409) {
          if (++tries > 5) throw new Error('offset komt niet overeen');
          const o = await status(url);
          if (o === null) throw Object.assign(new Error('upload niet gevonden'), { fatal: true });
          offset = o;
          continue;
        }
        if (r.status === 422) {
          store.del(key);
          throw Object.assign(new Error('bestaat al'), { fatal: true });
        }
        if ([403, 404, 413, 507].includes(r.status)) {
          if (r.status !== 403) store.del(key);
          throw Object.assign(new Error((await r.text()).trim() || `fout ${r.status}`), { fatal: true });
        }
        if (!r.ok) throw new Error(`fout ${r.status}`);
        offset = parseInt(r.headers.get('Upload-Offset'), 10);
        tries = 0;
        ui.bar.value = (offset / file.size) * 100;
        ui.state.textContent = Math.round(ui.bar.value) + '%';
        if (offset >= file.size) break;
      } catch (e) {
        if (e.fatal || ++tries > 5) throw e;
        ui.state.textContent = 'opnieuw proberen…';
        await sleep(1000 * tries);
        offset = (await status(url).catch(() => null)) ?? offset;
      }
    }
    store.del(key);
  }

  async function run(files) {
    let failed = false;
    for (const file of files) {
      const ui = row(file.name);
      try {
        await send(file, ui);
        ui.bar.value = 100; ui.state.textContent = 'klaar';
      } catch (e) {
        failed = true;
        ui.state.textContent = e.message || 'mislukt';
        ui.state.className = 'bad';
      }
    }
    if (!failed) location.reload();
  }

  pick.addEventListener('change', () => run([...pick.files]));
  ['dragenter', 'dragover'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', (e) => run([...e.dataTransfer.files]));
})();
