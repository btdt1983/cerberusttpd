// Filter the listing by name as you type. Hidden rows are unticked so a
// delete can never include something you cannot see.
(() => {
  const input = document.getElementById('filter');
  if (!input) return;
  const rows = [...document.querySelectorAll('main table tbody tr')].filter((r) => r.querySelector('.nm a'));
  input.addEventListener('input', () => {
    const q = input.value.trim().toLowerCase();
    for (const r of rows) {
      const hide = q && !r.querySelector('.nm a').textContent.toLowerCase().includes(q);
      r.hidden = !!hide;
      const box = r.querySelector('input[name="path"]');
      if (hide && box) box.checked = false;
    }
    const form = document.getElementById('sel');
    if (form) form.dispatchEvent(new Event('change', { bubbles: true }));
  });
})();
