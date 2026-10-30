// Masonry layout and lightbox for photo albums. Without this script the page
// still works: CSS columns lay the pictures out and each one links to the file.
(function () {
  'use strict';
  var gal = document.getElementById('gal');
  if (!gal) return;
  var items = Array.prototype.slice.call(gal.querySelectorAll('a.ph'));
  var cols = 0;

  // Shortest-column placement keeps the reading order left to right and, because
  // every picture has its size in the markup, does not move while loading.
  function layout() {
    var w = gal.clientWidth;
    var n = w < 340 ? 1 : Math.max(2, Math.min(6, Math.floor(w / 250)));
    if (n === cols) return;
    cols = n;
    var heights = [], cs = [];
    gal.textContent = '';
    gal.classList.add('js');
    for (var i = 0; i < n; i++) {
      var c = document.createElement('div');
      c.className = 'col';
      gal.appendChild(c);
      cs.push(c);
      heights.push(0);
    }
    items.forEach(function (a) {
      var w = +a.dataset.w || 1, h = +a.dataset.h || 1, k = 0;
      for (var j = 1; j < n; j++) if (heights[j] < heights[k]) k = j;
      cs[k].appendChild(a);
      heights[k] += h / w;
    });
  }
  layout();
  var timer;
  window.addEventListener('resize', function () { clearTimeout(timer); timer = setTimeout(layout, 120); });

  // A header that parses but a body that does not (animated WebP, odd JPEGs):
  // show the file name instead of a broken-image icon.
  gal.addEventListener('error', function (e) {
    var img = e.target;
    if (img.tagName !== 'IMG') return;
    var a = img.closest('a.ph');
    if (!a) return;
    a.classList.add('broken');
    var label = document.createElement('span');
    label.textContent = img.alt;
    img.replaceWith(label);
  }, true);

  // ---- lightbox ----
  var lb, img, cap, count, dl, orig, cur = -1, startX = null, opener = null;

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text) e.textContent = text;
    return e;
  }

  function build() {
    lb = el('div', 'lb');
    lb.hidden = true;
    lb.setAttribute('role', 'dialog');
    lb.setAttribute('aria-modal', 'true');
    lb.setAttribute('aria-label', 'Photo viewer');
    var bar = el('div', 'bar');
    count = el('span', 'mut');
    var acts = el('div', 'acts');
    orig = el('a', null, 'Original');
    orig.target = '_blank';
    orig.rel = 'noopener';
    dl = el('a', null, 'Download');
    var close = el('button', null, 'Close');
    close.type = 'button';
    close.setAttribute('aria-label', 'Close');
    close.addEventListener('click', hide);
    acts.append(orig, dl, close);
    bar.append(count, acts);
    var stage = el('div', 'stage');
    img = el('img');
    img.alt = '';
    stage.appendChild(img);
    cap = el('div', 'cap');
    var prev = el('button', 'nav prev', '‹'), next = el('button', 'nav next', '›');
    prev.type = next.type = 'button';
    prev.setAttribute('aria-label', 'Previous photo');
    next.setAttribute('aria-label', 'Next photo');
    prev.addEventListener('click', function () { show(cur - 1); });
    next.addEventListener('click', function () { show(cur + 1); });
    stage.addEventListener('click', function (e) { if (e.target === stage) hide(); });
    stage.addEventListener('touchstart', function (e) { startX = e.touches.length === 1 ? e.touches[0].clientX : null; }, { passive: true });
    stage.addEventListener('touchend', function (e) {
      if (startX === null) return;
      var d = e.changedTouches[0].clientX - startX;
      startX = null;
      if (Math.abs(d) > 50) show(cur + (d < 0 ? 1 : -1));
    });
    lb.append(bar, stage, prev, next, cap);
    document.body.appendChild(lb);
  }

  // Reading order, not column order.
  function show(i) {
    if (i < 0 || i >= items.length) return;
    cur = i;
    var a = items[i];
    img.src = a.dataset.view;
    img.alt = a.firstElementChild.alt;
    cap.textContent = a.dataset.cap || '';
    count.textContent = (i + 1) + ' / ' + items.length;
    orig.href = a.href;
    dl.href = a.dataset.dl;
    [i - 1, i + 1].forEach(function (j) { if (items[j]) new Image().src = items[j].dataset.view; });
  }

  function open(i) {
    if (!lb) build();
    opener = document.activeElement;
    lb.hidden = false;
    document.documentElement.classList.add('lbopen');
    show(i);
    lb.querySelector('.acts button').focus();
  }

  function hide() {
    lb.hidden = true;
    img.removeAttribute('src');
    document.documentElement.classList.remove('lbopen');
    if (opener && opener.focus) opener.focus();
  }

  gal.addEventListener('click', function (e) {
    if (e.button || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
    var a = e.target.closest('a.ph');
    if (!a) return;
    e.preventDefault();
    open(items.indexOf(a));
  });

  document.addEventListener('keydown', function (e) {
    if (!lb || lb.hidden) return;
    if (e.key === 'Escape') hide();
    else if (e.key === 'ArrowLeft') show(cur - 1);
    else if (e.key === 'ArrowRight') show(cur + 1);
    else if (e.key === 'Tab') { // keep focus inside the viewer
      var f = lb.querySelectorAll('button, a[href]');
      var first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  });
})();
