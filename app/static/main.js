// main.js - lightweight helpers
document.addEventListener('DOMContentLoaded', () => {
  // If theme form exists, prevent full reload when clicking (we still submit to server)
  const themeForm = document.getElementById('themeToggleForm');
  if (themeForm) {
    themeForm.addEventListener('submit', (e) => {
      // let the server handle theme toggle; show small visual feedback
      const btn = themeForm.querySelector('button');
      btn.disabled = true;
      setTimeout(() => btn.disabled = false, 700);
    });
  }

  // simple client-side validation: scan form
  const scanForm = document.getElementById('scanForm');
  if (scanForm) {
    scanForm.addEventListener('submit', (e) => {
      const url = scanForm.querySelector('input[name="url"]').value.trim();
      if (!url) { e.preventDefault(); alert('Please enter a URL to analyze.'); }
    });
  }
});
