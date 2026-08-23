/* Applies the saved skin and light/dark before first paint, so the app never
   flashes the default palette on load. app.js re-applies both once it runs.
   A separate file rather than an inline script on purpose: the admin origin
   serves a strict default-src 'self' CSP, which blocks inline execution. */
(function () {
  var d = document.documentElement;
  try {
    d.dataset.skin = localStorage.getItem('qg_skin') || 'console';
    d.dataset.theme = localStorage.getItem('qg_theme') || 'dark';
  } catch (e) {
    d.dataset.skin = 'console';
    d.dataset.theme = 'dark';
  }
})();
