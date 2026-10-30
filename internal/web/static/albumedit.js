// Reordering for the album edit form: drag a row by its handle, or use the arrows.
(function () {
  'use strict';
  var list = document.getElementById('erows');
  if (!list) return;
  var dragging = null;

  function rows() { return Array.prototype.slice.call(list.children); }

  list.addEventListener('click', function (e) {
    var b = e.target.closest('button.up, button.dn');
    if (!b) return;
    var row = b.closest('li');
    if (b.classList.contains('up') && row.previousElementSibling) list.insertBefore(row, row.previousElementSibling);
    if (b.classList.contains('dn') && row.nextElementSibling) list.insertBefore(row.nextElementSibling, row);
    b.focus();
  });

  // A row is only draggable while its handle is held, so the caption fields stay usable.
  list.addEventListener('mousedown', function (e) {
    var row = e.target.closest('li');
    if (row) row.draggable = !!e.target.closest('.hd');
  });
  list.addEventListener('dragstart', function (e) {
    dragging = e.target.closest('li');
    if (!dragging) return;
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', '');
    dragging.classList.add('drag');
  });
  list.addEventListener('dragover', function (e) {
    if (!dragging) return;
    e.preventDefault();
    var over = e.target.closest('li');
    rows().forEach(function (r) { r.classList.toggle('over', r === over && r !== dragging); });
    if (!over || over === dragging) return;
    var r = over.getBoundingClientRect();
    list.insertBefore(dragging, e.clientY < r.top + r.height / 2 ? over : over.nextElementSibling);
  });
  list.addEventListener('dragend', function () {
    if (dragging) dragging.classList.remove('drag');
    rows().forEach(function (r) { r.classList.remove('over'); r.draggable = false; });
    dragging = null;
  });

  document.getElementById('byname').addEventListener('click', function () {
    rows().sort(function (a, b) {
      return a.querySelector('.en').textContent.toLowerCase().localeCompare(b.querySelector('.en').textContent.toLowerCase());
    }).forEach(function (r) { list.appendChild(r); });
  });
})();
