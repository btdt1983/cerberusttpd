// Select-all and an enabled delete button only while something is ticked.
(() => {
  const form = document.getElementById('sel');
  if (!form) return;
  const boxes = () => [...form.querySelectorAll('tbody tr:not([hidden]) input[name="path"]')];
  const all = document.getElementById('all');
  const btn = document.getElementById('delsel');
  const sync = () => {
    const n = boxes().filter((b) => b.checked).length;
    btn.disabled = n === 0;
    btn.textContent = n > 1 ? `Verwijder ${n} geselecteerde` : 'Verwijder geselecteerde';
    all.checked = n > 0 && n === boxes().length;
    all.indeterminate = n > 0 && n < boxes().length;
  };
  all.addEventListener('change', () => { boxes().forEach((b) => { b.checked = all.checked; }); sync(); });
  form.addEventListener('change', sync);
  sync();
})();
