'use strict';

const $ = (id) => document.getElementById(id);
// Every value that did not come from this file (API data, and above all
// request data such as log paths and Host headers) goes through esc before it
// reaches innerHTML.
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const views = ['view-login', 'view-password', 'view-app'];
let hosts = [];
let accessLists = [];
let oidcProviders = [];
let customCerts = [];
let editingId = null;
let editingAclId = null;
let editingStreamId = null;
let editingCertId = null;

/* ---- theme ----
   Two independent axes: the skin (palette + typefaces) and light/dark within
   it. Both live on <html> as data attributes and in localStorage, and the
   skin is applied before first paint by an inline script in index.html so the
   UI never flashes the wrong palette. */
const SKINS = [
  { id: 'console', name: 'Console', note: 'near-black, lime, Geist', bg: '#0e0f13', accent: '#a3e635' },
  { id: 'brass', name: 'Brass & Iron', note: 'warm metals, serif, brass', bg: '#0f0c08', accent: '#d4a843' },
];

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem('qg_theme', theme);
  $('theme-light').checked = theme === 'light';
}
function applySkin(skin) {
  const chosen = SKINS.find((s) => s.id === skin) || SKINS[0];
  document.documentElement.dataset.skin = chosen.id;
  localStorage.setItem('qg_skin', chosen.id);
  for (const item of $('usermenu-skins').children) {
    item.setAttribute('aria-checked', String(item.dataset.skin === chosen.id));
  }
}
applyTheme(localStorage.getItem('qg_theme') || 'dark');

/* ---- user menu ----
   Account, appearance and sign-out live under the signed-in user, like in
   most admin consoles, instead of crowding the top bar. */
{
  const btn = $('usermenu-btn');
  const pop = $('usermenu-pop');
  for (const s of SKINS) {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = 'usermenu__item usermenu__skin';
    item.dataset.skin = s.id;
    item.setAttribute('role', 'menuitemradio');
    item.innerHTML =
      `<span class="usermenu__swatch" style="background:${s.bg}"><i style="background:${s.accent}"></i></span>` +
      `<span class="usermenu__skinname">${s.name}</span>` +
      '<span class="usermenu__tick" aria-hidden="true">&check;</span>';
    item.addEventListener('click', () => applySkin(s.id));
    $('usermenu-skins').appendChild(item);
  }
  const openMenu = () => {
    pop.hidden = false;
    btn.setAttribute('aria-expanded', 'true');
    document.addEventListener('click', onDocClick, true);
    document.addEventListener('keydown', onKey, true);
  };
  window.closeUserMenu = () => {
    pop.hidden = true;
    btn.setAttribute('aria-expanded', 'false');
    document.removeEventListener('click', onDocClick, true);
    document.removeEventListener('keydown', onKey, true);
  };
  function onDocClick(e) { if (!$('usermenu').contains(e.target)) closeUserMenu(); }
  function onKey(e) { if (e.key === 'Escape') { closeUserMenu(); btn.focus(); } }
  btn.addEventListener('click', () => (pop.hidden ? openMenu() : closeUserMenu()));
  pop.addEventListener('click', (e) => {
    const item = e.target.closest('[data-account]');
    if (item) { closeUserMenu(); switchPage('account', item.dataset.account); }
  });
  applySkin(localStorage.getItem('qg_skin') || SKINS[0].id);
}
$('theme-light').addEventListener('change', () => applyTheme($('theme-light').checked ? 'light' : 'dark'));

/* ---- page nav ----
   The page, and the section within Settings or Account, is kept in the URL
   fragment, so a reload or a shared link opens the same view. */
const pageLoaders = {
  overview: () => refreshOverview(),
  hosts: () => refresh(),
  access: () => refreshAcls(),
  streams: () => refreshStreams(),
  vpn: () => refreshVPN(),
  docker: () => refreshDocker(),
  certs: () => { refreshCerts(); refreshCustomCerts(); },
  logs: () => loadLogs(),
  settings: () => loadSettings(),
  account: () => loadProfile(),
  help: () => renderGuideIndex(),
};
const sectionNavs = { settings: 'settings-nav', account: 'account-nav' };
const currentSection = {};

function showSection(page, section) {
  const nav = $(sectionNavs[page]);
  const ids = [...nav.children].map((b) => b.dataset.section);
  const want = ids.includes(section) ? section : (currentSection[page] || ids[0]);
  currentSection[page] = want;
  for (const b of nav.children) b.classList.toggle('is-active', b.dataset.section === want);
  for (const sec of $(`page-${page}`).querySelectorAll('.setsec')) sec.hidden = sec.dataset.section !== want;
}

// setRoute puts the page in the address bar. A page or section the person
// opens is a history entry of its own, so the browser's Back button returns to
// the page before it instead of leaving quicgate; restoring a route (after
// signing in, or on Back and Forward themselves) replaces the entry it is on.
function setRoute(hash, replace) {
  if (location.hash === hash) return;
  if (replace) history.replaceState(null, '', hash);
  else history.pushState(null, '', hash);
}

function switchPage(name, section, { replace = false } = {}) {
  if (!pageLoaders[name]) name = 'overview';
  for (const b of $('pagenav').children) b.classList.toggle('is-active', b.dataset.page === name);
  for (const p of Object.keys(pageLoaders)) $(`page-${p}`).hidden = p !== name;
  if (sectionNavs[name]) showSection(name, section);
  setRoute(`#/${name}${sectionNavs[name] ? '/' + currentSection[name] : ''}`, replace);
  window.scrollTo(0, 0);
  pageLoaders[name]();
}

for (const [page, navId] of Object.entries(sectionNavs)) {
  $(navId).addEventListener('click', (e) => {
    const b = e.target.closest('[data-section]');
    if (!b) return;
    showSection(page, b.dataset.section);
    setRoute(`#/${page}/${b.dataset.section}`);
  });
}

// Back and Forward (and an address typed by hand) show the page the address
// names. Before signing in there is no page to show.
window.addEventListener('popstate', () => {
  if ($('view-app').hidden) return;
  const r = routeFromHash();
  switchPage(r.page, r.section, { replace: true });
});
$('pagenav').addEventListener('click', (e) => {
  if (e.target.dataset.page) switchPage(e.target.dataset.page);
});
$('btn-help').addEventListener('click', () => switchPage('help'));

function routeFromHash() {
  const [page, section] = location.hash.replace(/^#\/?/, '').split('/');
  return { page: page || 'overview', section };
}

// initials is the avatar text: the first letters of the account name.
function initials(email) {
  const name = String(email || '').replace(/^ldap:/, '').split('@')[0];
  const parts = name.split(/[._-]+/).filter(Boolean);
  const letters = parts.length > 1 ? parts[0][0] + parts[1][0] : name.slice(0, 2);
  return (letters || '?').toUpperCase();
}

/* ---- built-in guides (markdown, embedded in the binary) ---- */
const GUIDES = [
  { id: 'getting-started', title: 'Getting started', blurb: 'Run quicgate, add your first host, TLS modes, host types.' },
  { id: 'configuration', title: 'Configuration reference', blurb: 'Every env var and setting, real client IP, GeoIP, HTTP/3, IPv6.' },
  { id: 'sso', title: 'Access control & SSO', blurb: 'Access lists, built-in OIDC login, forward auth, per-path rules.' },
  { id: 'docker', title: 'Docker labels', blurb: 'Derive hosts and streams from container labels, multi-host.' },
  { id: 'streams', title: 'Streams & port forwards', blurb: 'TCP/UDP forwarding, PROXY protocol, SNI routing, UPnP, WireGuard sites.' },
  { id: 'vpn', title: 'VPN: devices, portal, LAN access', blurb: 'Hosts that exist on the VPN only, devices, single sign-on for the VPN, LAN policies.' },
];

function renderGuideIndex() {
  const idx = $('guide-index');
  if (idx.childElementCount) return;
  for (const g of GUIDES) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'guide-card';
    b.innerHTML = `<span class="guide-card__title">${g.title}</span><span class="guide-card__blurb">${g.blurb}</span>`;
    b.addEventListener('click', () => openGuide(g.id));
    idx.appendChild(b);
  }
}

async function openGuide(id) {
  const g = GUIDES.find((x) => x.id === id);
  if (!g) return;
  let md;
  try {
    const res = await fetch(`docs/${id}.md`);
    if (!res.ok) throw new Error(res.status);
    md = await res.text();
  } catch {
    md = '# Unavailable\n\nThis guide could not be loaded.';
  }
  $('guide-view').innerHTML = renderMarkdown(md);
  // Cross-guide links rendered by md.js carry data-guide.
  $('guide-view').querySelectorAll('a[data-guide]').forEach((a) => {
    a.addEventListener('click', (e) => { e.preventDefault(); openGuide(a.dataset.guide); });
  });
  $('guide-index').hidden = true;
  $('guide-view').hidden = false;
  $('btn-guide-back').hidden = false;
  $('guides-title').textContent = g.title;
  $('help-faq-card').hidden = true;
  $('guide-view').closest('.card').scrollIntoView({ block: 'start' });
}

function closeGuide() {
  $('guide-index').hidden = false;
  $('guide-view').hidden = true;
  $('btn-guide-back').hidden = true;
  $('guides-title').textContent = 'Guides';
  $('help-faq-card').hidden = false;
}
$('btn-guide-back').addEventListener('click', closeGuide);

// The search boxes and the 2FA fields sit in forms of their own so the
// browser's password manager does not treat a search box as a login name.
// Their buttons act through click handlers; the forms never navigate.
document.querySelectorAll('form.searchform, form.pmform').forEach((f) => f.addEventListener('submit', (e) => e.preventDefault()));

function show(view) {
  for (const v of views) $(v).hidden = v !== view;
}

// While a change is on its way to the server, every Save button is disabled
// and says so, and another submit is ignored. Without that a save that takes a
// moment looks like a button that did nothing, and pressing it again saved the
// same thing again.
let savesInFlight = 0;
function setSaving(delta) {
  savesInFlight += delta;
  const saving = savesInFlight > 0;
  document.body.classList.toggle('is-saving', saving);
  for (const b of document.querySelectorAll('button[type=submit]')) {
    if (saving && !b.disabled) {
      b.dataset.savingLabel = b.textContent;
      b.textContent = 'Saving...';
      b.disabled = true;
    } else if (!saving && b.dataset.savingLabel !== undefined) {
      b.textContent = b.dataset.savingLabel;
      delete b.dataset.savingLabel;
      b.disabled = false;
    }
  }
}
document.addEventListener('submit', (e) => {
  if (savesInFlight > 0) {
    e.preventDefault();
    e.stopImmediatePropagation();
  }
}, true);

async function api(method, path, body) {
  const changes = method !== 'GET';
  if (changes) setSaving(1);
  try {
    const res = await fetch(path, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = res.status === 204 ? {} : await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || res.statusText);
    return data;
  } finally {
    if (changes) setSaving(-1);
  }
}

// parsePool turns "scheme://host:port" lines into upstream objects.
function parsePool(text) {
  const out = [];
  for (const line of text.split('\n').map((s) => s.trim()).filter(Boolean)) {
    const m = line.match(/^(https?):\/\/([^:/\s]+):(\d+)$/);
    if (m) out.push({ scheme: m[1], host: m[2], port: parseInt(m[3], 10) });
  }
  return out;
}

function setError(id, err) {
  const el = $(id);
  el.hidden = !err;
  el.textContent = err ? String(err.message || err) : '';
}

/* ---- boot ---- */
async function boot() {
  api('GET', '/api/auth-methods').then((m) => {
    if (m.oidc) $('login-oidc').style.display = '';
  }).catch(() => {});
  try {
    const me = await api('GET', '/api/me');
    afterLogin(me);
  } catch {
    show('view-login');
  }
}

// showAccountEmail puts the signed-in address everywhere the page shows it.
function showAccountEmail(email) {
  // Password managers match a password field to the account through a
  // username field in the same form.
  document.querySelectorAll('.pm-user').forEach((el) => { el.value = email; });
  $('me-email').textContent = email;
  $('me-email-full').textContent = email;
  $('account-sub').textContent = email;
  $('me-avatar').textContent = initials(email);
  $('pe-email').value = email;
}

function afterLogin(me) {
  showAccountEmail(me.email);
  if (me.version) $('qg-version').textContent = 'quicgate ' + (/^v|^dev/.test(me.version) ? me.version : 'v' + me.version);
  if (me.mustChange) {
    show('view-password');
  } else {
    show('view-app');
    const r = routeFromHash();
    switchPage(r.page, r.section, { replace: true });
  }
}

/* ---- overview ----
   Traffic first: what went in and out, how requests were answered and what
   quicgate refused, over a chosen range. Then the ports, the busiest hosts and
   countries, and the configuration and its health. The engine samples every
   10 seconds and the page follows along while it is open. */
function plural(n, one, many) { return `${n} ${n === 1 ? one : many}`; }

const FMT = QGCharts.fmt;
// Points per line-chart point, per column and per sparkline point: the hour's
// 10-second samples are drawn as 30-second points, which reads calmer.
const OV_RANGES = {
  '1h': { poll: 10, line: 3, columns: 6, spark: 6 },
  '6h': { poll: 30, line: 1, columns: 1, spark: 2 },
  '24h': { poll: 60, line: 1, columns: 4, spark: 6 },
  '7d': { poll: 120, line: 1, columns: 2, spark: 3 },
};
const BLOCK_REASONS = {
  accessList: 'Access lists', banned: 'Auto-ban', rateLimit: 'Rate limits', exploit: 'Exploit filter',
  bot: 'Bad bots', clientCert: 'Client certificates', sso: 'Single sign-on', forwardAuth: 'Forward auth',
  streamSource: 'Stream source filters',
};
const ov = { range: '1h', charts: null, report: null, tables: {}, timer: null, stateAt: 0, startedAt: 0, version: '', error: '' };
try { if (OV_RANGES[localStorage.getItem('qg_ov_range')]) ov.range = localStorage.getItem('qg_ov_range'); } catch { /* private mode */ }

function ovCharts() {
  if (!ov.charts) {
    ov.charts = {
      tp: new QGCharts.LineChart($('ov-tp'), { label: 'Throughput, outbound and inbound', height: 260, format: FMT.bits, minMax: 8000, empty: 'No traffic recorded in this range yet.' }),
      rq: new QGCharts.ColumnChart($('ov-rq'), { label: 'Requests per minute by response status', height: 220, format: (v) => `${FMT.count(v)}/min`, axisFormat: FMT.count, minMax: 1, empty: 'No requests in this range yet.' }),
      lat: new QGCharts.LineChart($('ov-lat'), { label: 'Response time, 95th and 50th percentile', height: 220, format: FMT.ms, minMax: 10, empty: 'No responses in this range yet.' }),
    };
  }
  return ov.charts;
}

// ovSpan is the number of seconds of traffic point i holds: less than a step
// for the point still filling and for intervals quicgate was only partly up.
function ovSpan(rep, i) { return rep.series.secs[i] || 0; }

// ovRates turns per-point counts into rates per second, times mul, in groups
// of g points (g = 1 keeps every point).
function ovRates(rep, values, g, mul) {
  const out = [];
  for (let i = 0; i < values.length; i += g) {
    let sum = 0;
    let secs = 0;
    for (let j = i; j < Math.min(i + g, values.length); j++) {
      if (values[j] == null) continue;
      sum += values[j];
      secs += ovSpan(rep, j);
    }
    out.push(secs > 0 ? (sum / secs) * (mul || 1) : null);
  }
  return out;
}

// ovPeaks keeps the largest value of every group of g points, and ovMeans
// their average.
function ovPeaks(values, g) {
  const out = [];
  for (let i = 0; i < values.length; i += g) {
    const part = values.slice(i, i + g).filter((v) => v != null);
    out.push(part.length ? Math.max(...part) : null);
  }
  return out;
}
function ovMeans(values, g) {
  const out = [];
  for (let i = 0; i < values.length; i += g) {
    const part = values.slice(i, i + g).filter((v) => v != null);
    out.push(part.length ? part.reduce((a, b) => a + b, 0) / part.length : null);
  }
  return out;
}

function ovSetRange(range) {
  if (!OV_RANGES[range]) return;
  ov.range = range;
  try { localStorage.setItem('qg_ov_range', range); } catch { /* private mode */ }
  ovRangeButtons();
  ovLoadTraffic();
  ovSchedule();
}
function ovRangeButtons() {
  for (const b of $('ov-range').children) {
    const on = b.dataset.range === ov.range;
    b.classList.toggle('is-active', on);
    b.setAttribute('aria-pressed', String(on));
  }
}
$('ov-range').addEventListener('click', (e) => {
  const b = e.target.closest('[data-range]');
  if (b) ovSetRange(b.dataset.range);
});

async function refreshOverview() {
  ovRangeButtons();
  ovCharts();
  await Promise.all([ovLoadState(), ovLoadTraffic()]);
  ovSchedule();
}

function ovSchedule() {
  clearTimeout(ov.timer);
  ov.timer = setTimeout(async () => {
    if (!$('page-overview').hidden && !document.hidden) {
      const jobs = [ovLoadTraffic()];
      if (Date.now() - ov.stateAt > 30000) jobs.push(ovLoadState());
      await Promise.all(jobs);
    }
    ovSchedule();
  }, OV_RANGES[ov.range].poll * 1000);
}
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && !$('page-overview').hidden && !$('view-app').hidden) refreshOverview();
});

function ovSubtitle() {
  const parts = [];
  if (ov.version) parts.push(`quicgate ${/^v|^dev/.test(ov.version) ? ov.version : 'v' + ov.version}`);
  if (ov.startedAt) {
    const secs = Math.max(0, Date.now() / 1000 - ov.startedAt);
    const d = Math.floor(secs / 86400);
    const h = Math.floor((secs % 86400) / 3600);
    const m = Math.floor((secs % 3600) / 60);
    parts.push(`up ${d ? `${d} d ${h} h` : h ? `${h} h ${m} min` : `${m} min`}`);
  }
  if (ov.error) parts.push(`refresh failed: ${ov.error}`);
  else if (ov.report) parts.push(`updated ${new Date().toLocaleTimeString([], { hour12: false })}`);
  $('ov-sub').textContent = parts.join('  ·  ');
}

/* configuration, health and features */
async function ovLoadState() {
  let o, routes, streams;
  try {
    [o, routes, streams] = await Promise.all([
      api('GET', '/api/overview'),
      api('GET', '/api/config').catch(() => []),
      api('GET', '/api/streams').catch(() => []),
    ]);
  } catch (err) {
    ov.error = err.message;
    ovSubtitle();
    return;
  }
  ov.stateAt = Date.now();
  ov.version = o.version || '';
  ov.startedAt = o.startedAt || 0;
  const H = o.hosts || {}, S = o.streams || {}, C = o.certs || {}, U = o.upstreams || {}, F = o.features || {};
  const down = U.down || 0, up = U.up || 0;
  const failedCerts = C.failed || 0, pendingCerts = C.pending || 0;

  const attention = [];
  const attn = (level, text, page) => attention.push(
    `<div class="attn"><span class="sdot sdot--${level}"></span><span class="attn__text">${esc(text)}</span>` +
    (page ? `<button type="button" class="btn btn--ghost btn--sm" data-goto="${page}">View</button>` : '') + '</div>');
  if (o.secrets && o.secrets.locked) {
    attn('bad', `The secret store is locked: ${o.secrets.reason}. Stored secrets are kept untouched, and OIDC sign-in, DNS-01, custom certificates and two-factor logins do not work until the key is back.`, '');
  }
  if (down) attn('bad', `${plural(down, 'upstream is', 'upstreams are')} unreachable`, 'hosts');
  if (failedCerts) attn('bad', `${plural(failedCerts, 'certificate', 'certificates')} failed to issue or renew`, 'certs');
  const closed = (routes || []).filter((r) => (r.warnings || []).length).length;
  if (closed) attn('warn', `${plural(closed, 'route fails', 'routes fail')} closed because of a configuration problem`, 'hosts');
  const notRunning = (streams || []).filter((s) => (s.listeners || []).some((l) => l.state !== 'running')).length;
  if (notRunning) attn('bad', `${plural(notRunning, 'stream is', 'streams are')} not running`, 'streams');
  if (o.docker && o.docker.connected < o.docker.endpoints) {
    attn('warn', `${plural(o.docker.endpoints - o.docker.connected, 'Docker host is', 'Docker hosts are')} disconnected`, 'docker');
  }
  const V = o.vpn || {};
  if (V.enabled && !V.running) attn('bad', `The VPN is switched on but does not run: ${V.error || 'unknown error'}`, 'vpn');
  if (V.localAccessNoExpiry) attn('warn', `${plural(V.localAccessNoExpiry, 'VPN device reaches', 'VPN devices reach')} your local network without a login and without an end date: a lost setup file works until somebody removes the device`, 'vpn');
  else if (V.localAccessDevices) attn('info', `${plural(V.localAccessDevices, 'VPN device reaches', 'VPN devices reach')} your local network without a login`, 'vpn');
  if (V.flowLogError) attn('bad', `The VPN connection log cannot be written (${V.flowLogError}). Connections to the local network are refused until it can`, 'vpn');
  if (V.flowLogDropped) attn('warn', `${V.flowLogDropped} VPN flow records were dropped because the log could not keep up`, 'vpn');
  if (pendingCerts) attn('info', `${plural(pendingCerts, 'certificate is', 'certificates are')} waiting to be issued`, 'certs');
  if (!attention.length) attn('ok', 'Nothing needs attention.', '');
  $('ov-attention').innerHTML = attention.join('');

  const row = (page, label, value, sub, bad) =>
    `<button type="button" class="kv kv--link" data-goto="${page}"><span class="kv__k">${esc(label)}</span>` +
    `<span class="kv__v"><span class="kv__num">${esc(value)}</span><span class="kv__sub${bad ? ' is-bad' : ''}">${esc(sub)}</span></span></button>`;
  const rows = [
    row('hosts', 'Proxy hosts', String(H.total || 0), `${H.enabled || 0} enabled`),
    row('hosts', 'Upstreams', `${up}/${up + down}`, down ? `${down} unreachable` : 'all reachable', down > 0),
    row('certs', 'Certificates', String(C.issued || 0), failedCerts ? `${failedCerts} failed` : pendingCerts ? `${pendingCerts} pending` : 'issued', failedCerts > 0),
    row('streams', 'Streams', String(S.total || 0), `${S.enabled || 0} enabled`),
    row('access', 'Access lists', String(o.accessLists || 0), `${H.withAccessList || 0} hosts behind one`),
  ];
  if (o.docker) rows.push(row('docker', 'Docker containers', `${o.docker.routed}/${o.docker.containers}`, 'routed'));
  $('ov-config').innerHTML = rows.join('');

  const kv = (k, v) => `<div class="kv"><span class="kv__k">${esc(k)}</span><span class="kv__v">${v}</span></div>`;
  const feats = [['HTTP/3', 'http3'], ['UPnP port mapping', 'upnp'], ['Auto-ban', 'autoban'], ['GeoIP', 'geoip'],
    ['Forward authentication', 'forwardAuth'], ['Admin OIDC sign-in', 'oidc'], ['Admin LDAP sign-in', 'ldap'], ['Docker labels', 'docker']];
  $('ov-features').innerHTML = feats.map(([label, key]) =>
    kv(label, F[key] ? '<span class="sdot sdot--ok"></span>on' : '<span class="sdot sdot--off"></span><span class="hs-muted">off</span>')).join('');
  ovSubtitle();
}

/* traffic */
async function ovLoadTraffic() {
  const range = ov.range;
  let rep;
  try {
    rep = await api('GET', `/api/traffic?range=${range}`);
  } catch (err) {
    ov.error = err.message;
    ovSubtitle();
    return;
  }
  if (range !== ov.range) return; // the range changed while this was loading
  ov.error = '';
  ov.report = rep;
  ovRenderKPIs(rep);
  ovRenderCharts(rep);
  ovRenderPorts(rep);
  ovRenderLists(rep);
  ovSubtitle();
}

function ovRenderKPIs(rep) {
  const t = rep.totals, s = rep.series, g = OV_RANGES[ov.range].spark;
  let secs = 0;
  s.in.forEach((v, i) => { if (v != null) secs += ovSpan(rep, i); });
  const perSec = (n) => (secs > 0 ? n / secs : 0);
  const outRate = ovRates(rep, s.out, 1, 8), inRate = ovRates(rep, s.in, 1, 8);
  const peak = (vals) => Math.max(0, ...vals.filter((v) => v != null));
  const blocked = Object.values(t.blocked || {}).reduce((a, b) => a + b, 0);
  const errPct = t.requests ? (t.status['5xx'] / t.requests) * 100 : 0;
  const tiles = [
    { label: 'Outbound', value: FMT.bytes(t.out), sub: `avg ${FMT.bits(perSec(t.out * 8))}`, title: `peak ${FMT.bits(peak(outRate))}`,
      spark: ovRates(rep, s.out, g, 8), color: 'var(--c-series-1)' },
    { label: 'Inbound', value: FMT.bytes(t.in), sub: `avg ${FMT.bits(perSec(t.in * 8))}`, title: `peak ${FMT.bits(peak(inRate))}`,
      spark: ovRates(rep, s.in, g, 8), color: 'var(--c-series-2)' },
    { label: 'Requests', value: FMT.count(t.requests), sub: `${FMT.count(perSec(t.requests) * 60)} per minute`,
      spark: ovRates(rep, s.requests, g, 60) },
    { label: 'Server errors', value: t.requests ? FMT.pct(errPct) : '-', sub: `${FMT.count(t.status['5xx'])} responses`,
      title: `${FMT.int(t.status['4xx'])} client errors (4xx)`, spark: ovRates(rep, s['5xx'], g, 60), level: errPct >= 5 ? 'bad' : errPct >= 1 ? 'warn' : '' },
    { label: 'Blocked', value: FMT.count(blocked), sub: rep.banned ? `${FMT.int(rep.banned)} banned now` : 'none banned now',
      spark: ovRates(rep, s.blocked, g, 60), goto: 'access', title: 'See the banned addresses and why' },
    { label: 'Response p95', value: t.p95 >= 0 ? FMT.ms(t.p95) : '-', sub: t.p50 >= 0 ? `p50 ${FMT.ms(t.p50)}` : 'no responses yet',
      title: t.p99 >= 0 ? `p99 ${FMT.ms(t.p99)}` : '', spark: ovPeaks(s.p95, g) },
    { label: 'Connections', value: FMT.int(rep.open), sub: `open now, peak ${FMT.int(t.peakOpen)}`,
      title: `${FMT.int(t.connections)} opened in this range`, spark: ovPeaks(s.open, g) },
  ];
  const host = $('ov-kpis');
  host.replaceChildren();
  for (const k of tiles) {
    const tile = document.createElement(k.goto ? 'button' : 'div');
    tile.className = k.goto ? 'kpi kpi--link' : 'kpi';
    if (k.goto) {
      tile.type = 'button';
      tile.dataset.goto = k.goto;
    }
    if (k.title) tile.title = k.title;
    const head = document.createElement('div');
    head.className = 'kpi__label';
    if (k.level) {
      const dot = document.createElement('span');
      dot.className = `sdot sdot--${k.level}`;
      head.appendChild(dot);
    }
    head.appendChild(document.createTextNode(k.label));
    const value = document.createElement('div');
    value.className = 'kpi__value';
    value.textContent = k.value;
    const sub = document.createElement('div');
    sub.className = 'kpi__sub';
    sub.textContent = k.sub;
    const spark = QGCharts.sparkline(k.spark, { width: 160, height: 34 });
    if (k.color) spark.style.color = k.color;
    tile.append(head, value, sub, spark);
    host.appendChild(tile);
  }
}

function ovRenderCharts(rep) {
  const c = ovCharts(), s = rep.series;
  const { line, columns: cols } = OV_RANGES[ov.range];
  const tp = [
    { label: 'Outbound', color: 'var(--c-series-1)', values: ovRates(rep, s.out, line, 8), area: true },
    { label: 'Inbound', color: 'var(--c-series-2)', values: ovRates(rep, s.in, line, 8), area: true },
  ];
  const statuses = [['2xx', '--c-chart-2xx'], ['3xx', '--c-chart-3xx'], ['4xx', '--c-chart-4xx'], ['5xx', '--c-chart-5xx']];
  const rq = statuses.map(([k, color]) => ({ label: k, color: `var(${color})`, values: ovRates(rep, s[k], cols, 60) }));
  const lat = [
    { label: 'p95', color: 'var(--c-series-1)', values: ovMeans(s.p95, line) },
    { label: 'p50', color: 'var(--c-series-2)', values: ovMeans(s.p50, line) },
  ];
  const tables = {
    tp: [['Time', 'Outbound', 'Inbound'], tp, FMT.bits, line],
    rq: [['Time', ...statuses.map(([k]) => `${k} per minute`)], rq, FMT.count, cols],
    lat: [['Time', 'p95', 'p50'], lat, FMT.ms, line],
  };
  const charts = {
    tp: [c.tp, { start: rep.start, step: rep.step * line, points: tp[0].values.length, series: tp }],
    rq: [c.rq, { start: rep.start, step: rep.step * cols, points: rq[0].values.length, series: rq,
      rows: (i) => rq.slice().reverse().map((x) => ({ label: x.label, value: x.values[i] == null ? 'no data' : `${FMT.count(x.values[i])}/min`, color: x.color, shape: 'box' })) }],
    lat: [c.lat, { start: rep.start, step: rep.step * line, points: lat[0].values.length, series: lat }],
  };
  QGCharts.legend($('ov-tp-legend'), tp.map((x) => ({ label: x.label, color: x.color, shape: 'box' })));
  QGCharts.legend($('ov-rq-legend'), rq.map((x) => ({ label: x.label, color: x.color, shape: 'box' })));
  QGCharts.legend($('ov-lat-legend'), lat.map((x) => ({ label: x.label, color: x.color, shape: 'line' })));
  for (const [id, [chart, data]] of Object.entries(charts)) {
    // The table view is the chart's accessible twin: the same numbers as rows.
    let box = chart.host.nextElementSibling;
    if (!box || !box.classList.contains('chartbox--table')) {
      box = document.createElement('div');
      box.className = 'chartbox chartbox--table';
      chart.host.after(box);
    }
    box.hidden = !ov.tables[id];
    chart.host.hidden = !!ov.tables[id];
    if (ov.tables[id]) {
      const [head, series, format, group] = tables[id];
      const rows = [];
      for (let i = series[0].values.length - 1; i >= 0; i--) {
        if (series.every((x) => x.values[i] == null)) continue;
        rows.push([QGCharts.spanLabel(rep.start + i * rep.step * group, rep.step * group),
          ...series.map((x) => (x.values[i] == null ? '-' : format(x.values[i])))]);
      }
      QGCharts.table(box, head, rows.length ? rows : [['No data in this range yet.', ...head.slice(1).map(() => '')]]);
    }
    chart.update(data);
  }
}
document.querySelectorAll('[data-chart-table]').forEach((b) => b.addEventListener('click', () => {
  const id = b.dataset.chartTable;
  ov.tables[id] = !ov.tables[id];
  b.setAttribute('aria-pressed', String(ov.tables[id]));
  b.textContent = ov.tables[id] ? 'Chart' : 'Table';
  if (ov.report) ovRenderCharts(ov.report);
}));

function ovRenderPorts(rep) {
  const ports = rep.ports || [];
  const showExposure = ports.some((p) => p.exposed != null);
  const table = $('ov-ports');
  table.replaceChildren();
  const head = table.createTHead().insertRow();
  const cols = [['Port', ''], ['Service', ''], ['Details', ''], ...(showExposure ? [['Router', '']] : []),
    ['State', ''], ['Inbound', 'num'], ['Outbound', 'num'], ['Connections', 'num'], ['Open', 'num'], ['Traffic', 'ports__sparkcol']];
  for (const [label, cls] of cols) {
    const th = document.createElement('th');
    th.textContent = label;
    if (cls) th.className = cls;
    head.appendChild(th);
  }
  const body = table.createTBody();
  if (!ports.length) {
    const td = body.insertRow().insertCell();
    td.colSpan = cols.length;
    td.className = 'hs-muted';
    td.textContent = 'No listeners.';
    return;
  }
  const cell = (tr, text, cls) => {
    const td = tr.insertCell();
    if (cls) td.className = cls;
    if (text != null) td.textContent = text;
    return td;
  };
  const dot = (td, level, text) => {
    const d = document.createElement('span');
    d.className = `sdot sdot--${level}`;
    td.append(d, document.createTextNode(` ${text}`));
  };
  for (const p of ports) {
    const tr = body.insertRow();
    cell(tr, `${p.port}${p.portEnd ? '-' + p.portEnd : ''}/${p.proto}`, 'mono nowrap');
    const svc = cell(tr, p.service, 'nowrap');
    if (p.docker) {
      const b = document.createElement('span');
      b.className = 'badge badge--muted';
      b.textContent = 'docker';
      svc.append(' ', b);
    }
    cell(tr, p.detail, 'ports__detail');
    if (showExposure) {
      const td = cell(tr, null, 'nowrap');
      if (p.exposed == null) td.textContent = '-';
      else dot(td, p.exposed ? 'info' : 'off', p.exposed ? 'mapped' : 'not mapped');
    }
    const st = cell(tr, null, 'nowrap');
    dot(st, p.state === 'listening' ? 'ok' : 'bad', p.state);
    if (p.error) st.title = p.error;
    cell(tr, FMT.bytes(p.in), 'num nowrap');
    cell(tr, FMT.bytes(p.out), 'num nowrap');
    cell(tr, FMT.count(p.connections), 'num nowrap');
    cell(tr, FMT.int(p.open), 'num nowrap');
    const sp = cell(tr, null, 'ports__sparkcol');
    const svg = QGCharts.sparkline((p.spark || []).map((v) => (v == null ? null : v * 8)), { width: 140, height: 26 });
    const peak = Math.max(0, ...(p.spark || []).filter((v) => v != null)) * 8;
    sp.title = `peak ${FMT.bits(peak)}`;
    sp.appendChild(svg);
  }
  const listening = ports.filter((p) => p.state === 'listening').length;
  const exposed = ports.filter((p) => p.exposed).length;
  $('ov-ports-sub').textContent = `${plural(listening, 'listener', 'listeners')} running` +
    (showExposure ? `, ${exposed} mapped on the router by UPnP` : '') + '. Traffic is what went through each port in this range.';
}

function ovRenderLists(rep) {
  const t = rep.totals;
  QGCharts.barList($('ov-hosts'), (rep.hosts || []).map((h) => ({
    label: h.name === '_unmatched' ? 'No matching host' : h.name,
    value: h.requests,
    note: h.errors ? `${FMT.pct((h.errors / h.requests) * 100)} 5xx` : '',
    title: `${FMT.int(h.requests)} requests, ${FMT.bytes(h.out)} sent, ${FMT.int(h.errors)} server errors`,
  })), { empty: 'No requests in this range yet.' });

  if (!rep.geoip) {
    const box = $('ov-countries');
    box.replaceChildren();
    const p = document.createElement('div');
    p.className = 'barlist__empty';
    p.textContent = 'Needs a GeoIP database. ';
    const a = document.createElement('button');
    a.type = 'button';
    a.className = 'linkbtn';
    a.textContent = 'Set one up';
    a.addEventListener('click', () => switchPage('settings', 'network'));
    p.appendChild(a);
    box.appendChild(p);
  } else {
    const names = typeof Intl.DisplayNames === 'function' ? new Intl.DisplayNames(['en'], { type: 'region' }) : null;
    const country = (code) => {
      if (code === 'LAN') return 'Local network';
      if (code === 'unknown') return 'Unknown';
      try { return names ? `${names.of(code)}` : code; } catch { return code; }
    };
    QGCharts.barList($('ov-countries'), (rep.countries || []).map((c) => ({
      label: country(c.code), value: c.requests, note: /^[A-Z]{2}$/.test(c.code) ? c.code : '',
      title: `${FMT.int(c.requests)} requests`,
    })), { empty: 'No requests in this range yet.' });
  }

  QGCharts.shareBar($('ov-protocols'), [
    { label: 'HTTP/3', value: t.protocols['HTTP/3'] || 0, color: 'var(--c-series-1)' },
    { label: 'HTTP/2', value: t.protocols['HTTP/2'] || 0, color: 'var(--c-series-2)' },
    { label: 'HTTP/1.1', value: t.protocols['HTTP/1.1'] || 0, color: 'var(--c-series-3)' },
  ], { empty: 'No requests in this range yet.' });

  const blocked = Object.entries(t.blocked || {}).filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]);
  const total = blocked.reduce((a, [, n]) => a + n, 0);
  const sub = $('ov-blocked-sub');
  sub.textContent = total
    ? `${FMT.int(total)} refused in this range${rep.banned ? `, ${plural(rep.banned, 'address', 'addresses')} banned now` : ''}. `
    : 'Requests and stream clients quicgate refused. ';
  if (rep.banned) {
    const link = document.createElement('button');
    link.type = 'button';
    link.className = 'linkbtn';
    link.dataset.goto = 'access';
    link.textContent = 'See who and why';
    sub.appendChild(link);
  }
  QGCharts.barList($('ov-blocked'), blocked.map(([k, n]) => ({ label: BLOCK_REASONS[k] || k, value: n, title: `${FMT.int(n)} refused` })),
    { empty: 'Nothing refused in this range.' });
}

$('page-overview').addEventListener('click', (e) => {
  const target = e.target.closest('[data-goto]');
  if (target) switchPage(target.dataset.goto);
});
$('btn-ov-refresh').addEventListener('click', refreshOverview);

/* ---- auth ---- */
$('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  setError('login-error', null);
  try {
    const code = $('login-totp') ? $('login-totp').value.trim() : '';
    const me = await api('POST', '/api/login', {
      email: $('login-email').value,
      password: $('login-password').value,
      code,
    });
    if (me.totpRequired) {
      if (!$('login-totp')) {
        const label = document.createElement('label');
        label.className = 'field';
        label.innerHTML = '<span>Authentication code</span><input id="login-totp" class="mono" placeholder="123456" autocomplete="one-time-code">';
        $('login-error').before(label);
      }
      setError('login-error', new Error('Enter your 2FA code.'));
      $('login-totp').focus();
      return;
    }
    afterLogin(me);
  } catch (err) {
    setError('login-error', err);
  }
});

$('password-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  setError('pw-error', null);
  try {
    await api('POST', '/api/password', { current: $('pw-current').value, new: $('pw-new').value });
    show('view-app');
    switchPage('overview');
  } catch (err) {
    setError('pw-error', err);
  }
});

$('btn-logout').addEventListener('click', async () => {
  closeUserMenu();
  await api('POST', '/api/logout').catch(() => {});
  show('view-login');
});

/* ---- hosts table ---- */
function hostMatches(h, q) {
  if (!q) return true;
  const acl = accessLists.find((a) => a.id === h.accessListId);
  const hay = h.domains.join(' ') + ' ' + `${h.upstream.host}:${h.upstream.port}` + ' ' + (acl ? acl.name : 'public');
  return hay.toLowerCase().includes(q);
}

$('host-search').addEventListener('input', () => renderHosts());

let healthMap = {};
// routeWarnings maps a domain to the parts of its route that fail closed (an
// unresolvable hostname rule, a missing reference), from the effective config.
let routeWarnings = {};
async function refresh() {
  let health, routes;
  // Providers load here too: the host modal's OIDC pickers would otherwise be
  // empty until the Access Lists page had been opened once, and saving a host
  // from an empty picker drops the provider it was using.
  [hosts, accessLists, customCerts, health, oidcProviders, routes] = await Promise.all([
    api('GET', '/api/hosts'), api('GET', '/api/access-lists'), api('GET', '/api/custom-certs'),
    api('GET', '/api/health').catch(() => []),
    api('GET', '/api/oidc-providers').catch(() => []),
    api('GET', '/api/config').catch(() => []),
  ]);
  await loadWGSites();
  healthMap = {};
  for (const t of health) healthMap[t.target] = t.up;
  routeWarnings = {};
  for (const r of routes || []) {
    if ((r.warnings || []).length) routeWarnings[r.domain.toLowerCase()] = r.warnings;
  }
  const enabled = hosts.filter((h) => h.enabled).length;
  const gated = hosts.filter((h) => h.accessListId != null).length;
  $('hosts-sub').textContent = hosts.length
    ? `${hosts.length} hosts, ${enabled} enabled, ${gated} behind an access list.`
    : 'HTTP and HTTPS services behind quicgate.';
  renderHosts();
  refreshCerts();
}

// A host's domains link to the site itself, opened in a new tab. Wildcards have
// no single address to visit, so they stay plain text.
function domainLink(h, domain) {
  if (domain.includes('*')) return document.createTextNode(domain);
  const scheme = h.certMode === 'auto' || h.certMode === 'custom' ? 'https' : 'http';
  const a = document.createElement('a');
  a.href = `${scheme}://${domain}/`;
  a.target = '_blank';
  a.rel = 'noopener noreferrer';
  a.textContent = domain;
  a.title = `Open ${a.href} in a new tab`;
  return a;
}

function renderHosts() {
  const q = $('host-search').value.trim().toLowerCase();
  const shown = hosts.filter((h) => hostMatches(h, q));
  const body = $('hosts-body');
  body.innerHTML = '';
  $('hosts-empty').hidden = shown.length > 0;
  $('hosts-empty').textContent = hosts.length === 0
    ? 'No proxy hosts yet. Add the first one.'
    : 'No hosts match the filter.';
  for (const h of shown) {
    const tr = document.createElement('tr');

    const tdDomains = document.createElement('td');
    tdDomains.className = 'domain';
    for (const d of h.domains) {
      const line = document.createElement('div');
      line.append(domainLink(h, d));
      tdDomains.append(line);
    }
    const warnings = [...new Set(h.domains.flatMap((d) => routeWarnings[d.toLowerCase()] || []))];
    for (const w of warnings) {
      const line = document.createElement('div');
      line.className = 'rowwarn';
      line.textContent = w;
      line.title = w;
      tdDomains.append(line);
      tr.classList.add('row--warn');
    }

    const tdUpstream = document.createElement('td');
    tdUpstream.className = 'domain';
    if (h.type === 'redirect' && h.redirect) {
      tdUpstream.innerHTML = `<span class="badge badge--muted">${esc(h.redirect.httpCode)} redirect</span> ${esc(h.redirect.targetHost)}`;
    } else if (h.type === 'dead') {
      tdUpstream.innerHTML = '<span class="badge badge--danger">404 host</span>';
    } else if (h.type === 'static') {
      tdUpstream.innerHTML = `<span class="badge badge--muted">static</span> ${esc(h.staticRoot)}`;
    } else if (h.type === 'vpn-portal') {
      const po = (h.options && h.options.portal) || {};
      const pv = oidcProviders.find((x) => x.id === po.providerId);
      tdUpstream.innerHTML = `<span class="badge badge--muted">VPN portal</span> ${esc(pv ? 'login through ' + pv.name : '')}`;
    } else {
      const pool = [h.upstream, ...(h.upstreams || [])];
      // A backend behind a WireGuard site is another machine than the same
      // address on the local network, and the health check keys it so.
      const healthKey = (u) => `${u.scheme}://${u.host}:${u.port}${u.via ? '|site=' + u.via : ''}`;
      const primary = `${h.upstream.scheme}://${h.upstream.host}:${h.upstream.port}${h.upstream.via ? ' via ' + wgSiteName(h.upstream.via) : ''}`;
      const up = pool.filter((u) => healthMap[healthKey(u)] !== false).length;
      if (up < pool.length) tr.classList.add('row--down');
      if (pool.length > 1) {
        tdUpstream.innerHTML = `${esc(primary)} <span class="badge ${up === pool.length ? 'badge--success' : 'badge--danger'}">${up}/${pool.length} up</span>`;
      } else if (up === 0) {
        tdUpstream.innerHTML = `${esc(primary)} <span class="badge badge--danger">down</span>`;
      } else {
        tdUpstream.textContent = primary;
      }
    }

    const tdTLS = document.createElement('td');
    const badge = document.createElement('span');
    const cm = h.certMode;
    badge.className = 'badge ' + (cm === 'auto' || cm === 'custom' ? 'badge--success' : 'badge--muted');
    badge.textContent = cm === 'auto' ? (h.forceSsl ? 'auto + force ssl' : 'auto')
      : cm === 'custom' ? 'custom cert' : 'http only';
    tdTLS.appendChild(badge);

    const tdAccess = document.createElement('td');
    const acl = accessLists.find((a) => a.id === h.accessListId);
    tdAccess.innerHTML = acl
      ? `<span class="badge">${esc(acl.name)}</span>`
      : (h.options && h.options.vpnOnly ? '' : '<span class="badge badge--muted">public</span>');
    if (h.options && h.options.vpnOnly) tdAccess.innerHTML += ' <span class="badge badge--success" title="Served inside the WireGuard tunnel only">VPN only</span>';

    const tdCert = document.createElement('td');
    tdCert.className = 'domain';
    if (h.certMode === 'auto') {
      const c = h.domains.map((d) => certByDomain[d.toLowerCase()]).find(Boolean);
      if (c) {
        const cls = c.status === 'issued' ? 'badge--success' : c.status === 'failed' ? 'badge--danger' : '';
        const exp = c.notAfter ? ' ' + new Date(c.notAfter).toLocaleDateString() : '';
        tdCert.innerHTML = `<span class="badge ${cls}">${esc(c.status)}</span>${esc(exp)}`;
      } else {
        tdCert.innerHTML = '<span class="badge badge--muted">pending</span>';
      }
    } else if (h.certMode === 'custom') {
      tdCert.innerHTML = '<span class="badge badge--muted">custom</span>';
    } else {
      tdCert.textContent = '-';
    }

    const tdEnabled = document.createElement('td');
    const sw = document.createElement('label');
    sw.className = 'switch';
    sw.innerHTML = '<input type="checkbox"><span class="switch__slot"></span><span class="switch__knob"></span>';
    const cb = sw.querySelector('input');
    cb.checked = h.enabled;
    cb.addEventListener('change', async () => {
      try {
        await api('PUT', `/api/hosts/${h.id}`, { ...h, enabled: cb.checked });
        refresh();
        refreshCerts();
      } catch (err) {
        alert(err.message);
        cb.checked = !cb.checked;
      }
    });
    tdEnabled.appendChild(sw);

    const tdActions = document.createElement('td');
    tdActions.style.textAlign = 'right';
    const btnLogs = document.createElement('button');
    btnLogs.className = 'btn btn--ghost btn--sm';
    btnLogs.textContent = 'Logs';
    btnLogs.addEventListener('click', () => openHostLogs(h));
    const btnEdit = document.createElement('button');
    btnEdit.className = 'btn btn--secondary btn--sm';
    btnEdit.textContent = 'Edit';
    btnEdit.addEventListener('click', () => openModal(h));
    const btnDel = document.createElement('button');
    btnDel.className = 'btn btn--danger btn--sm';
    btnDel.textContent = 'Delete';
    btnDel.style.marginLeft = '8px';
    btnDel.addEventListener('click', async () => {
      if (!confirm(`Delete host for ${h.domains[0]}?`)) return;
      await api('DELETE', `/api/hosts/${h.id}`);
      refresh();
      refreshCerts();
    });
    btnEdit.style.marginLeft = '8px';
    tdActions.append(btnLogs, btnEdit, btnDel);

    tr.append(tdDomains, tdUpstream, tdTLS, tdAccess, tdCert, tdEnabled, tdActions);
    body.appendChild(tr);
  }
}

let certByDomain = {};
async function refreshCerts() {
  const certs = await api('GET', '/api/certs').catch(() => []);
  certByDomain = {};
  for (const c of certs) certByDomain[c.domain.toLowerCase()] = c;
  renderHosts(); // fill the Certificate column in the hosts table
  const body = $('certs-body');
  body.innerHTML = '';
  $('certs-empty').hidden = certs.length > 0;
  certs.sort((a, b) => a.domain.localeCompare(b.domain));
  for (const c of certs) {
    const tr = document.createElement('tr');
    const badgeClass = c.status === 'issued' ? 'badge badge--success'
      : c.status === 'failed' ? 'badge badge--danger' : 'badge';
    const detail = c.lastError
      ? `<div class="hs-muted" style="font-size:var(--fs-xs)" title="${esc(c.lastError)}">last error: ${esc(c.lastError.slice(0, 90))}</div>`
      : '';
    tr.innerHTML = `<td class="domain">${esc(c.domain)}</td>` +
      `<td><span class="${badgeClass}">${esc(c.status)}</span>${detail}</td>` +
      `<td class="domain">${esc(c.notAfter ? new Date(c.notAfter).toLocaleString() : '-')}</td>`;
    body.appendChild(tr);
  }
}

$('btn-certs-refresh').addEventListener('click', refreshCerts);

/* ---- header rule editors ---- */
function addHdrRow(containerId, rule) {
  const row = document.createElement('div');
  row.className = 'hdr-rule';
  row.innerHTML =
    '<select><option value="set">set</option><option value="add">add</option><option value="remove">remove</option></select>' +
    '<input placeholder="Header-Name">' +
    '<input placeholder="value">' +
    '<button type="button" class="btn btn--ghost btn--sm">&times;</button>';
  const [op, name, value] = [row.children[0], row.children[1], row.children[2]];
  if (rule) {
    op.value = rule.op;
    name.value = rule.name;
    value.value = rule.value || '';
  }
  op.addEventListener('change', () => { value.disabled = op.value === 'remove'; });
  value.disabled = op.value === 'remove';
  row.children[3].addEventListener('click', () => row.remove());
  $(containerId).appendChild(row);
}

function readHdrRows(containerId) {
  const out = [];
  for (const row of $(containerId).children) {
    const [op, name, value] = [row.children[0].value, row.children[1].value.trim(), row.children[2].value];
    if (!name) continue;
    out.push(op === 'remove' ? { op, name } : { op, name, value });
  }
  return out;
}

$('btn-add-reqhdr').addEventListener('click', () => addHdrRow('req-headers'));
$('btn-add-resphdr').addEventListener('click', () => addHdrRow('resp-headers'));

/* ---- path authentication rows ---- */
// One row = one path-scoped override of the host's access list / forward auth.
// The access-list picker only appears for mode=accessList, so a row never
// carries a reference the server would reject.
function addAuthRuleRow(rule) {
  const row = document.createElement('div');
  row.className = 'hdr-rule';
  const verbs = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'];
  const chips = verbs.map((v) => `<span class="mchip" data-m="${v}" tabindex="0">${v}</span>`).join('');
  row.innerHTML =
    '<input class="a-path mono" placeholder="/manage/" style="flex:0 0 130px">' +
    '<select class="a-match" style="flex:0 0 90px"><option value="prefix">prefix</option><option value="exact">exact</option></select>' +
    '<select class="a-mode" style="flex:0 0 130px">' +
      '<option value="public">Public</option>' +
      '<option value="accessList">Access list</option>' +
      '<option value="forwardAuth">Forward auth</option>' +
      '<option value="oidc">OIDC SSO</option>' +
    '</select>' +
    '<select class="a-acl" style="flex:1" hidden></select>' +
    '<select class="a-prov" style="flex:0 0 150px" hidden title="Which identity provider gates this path"></select>' +
    '<input class="a-groups mono" style="flex:1" hidden placeholder="allowed groups (optional)" title="Comma-separated. Empty = any user this provider authenticates.">' +
    '<span class="r-methods" title="Click the verbs this rule applies to. None selected = all methods.">' + chips + '</span>' +
    '<button type="button" class="btn btn--ghost btn--sm a-del">&times;</button>';
  const mode = row.querySelector('.a-mode');
  const acl = row.querySelector('.a-acl');
  for (const a of accessLists) {
    const opt = document.createElement('option');
    opt.value = String(a.id);
    opt.textContent = a.name;
    acl.appendChild(opt);
  }
  const prov = row.querySelector('.a-prov');
  const groups = row.querySelector('.a-groups');
  const hostOpt = document.createElement('option');
  hostOpt.value = '';
  hostOpt.textContent = "host's provider";
  prov.appendChild(hostOpt);
  for (const pv of oidcProviders) {
    const opt = document.createElement('option');
    opt.value = String(pv.id);
    opt.textContent = pv.name;
    prov.appendChild(opt);
  }
  const syncMode = () => {
    acl.hidden = mode.value !== 'accessList';
    prov.hidden = mode.value !== 'oidc';
    // Per-rule policy only applies when the rule has its own provider; with
    // the host's provider it also keeps the host's allow-lists.
    groups.hidden = mode.value !== 'oidc' || !prov.value;
  };
  prov.addEventListener('change', syncMode);
  mode.addEventListener('change', syncMode);
  const toggle = (ch) => ch.classList.toggle('on');
  row.querySelectorAll('.mchip').forEach((ch) => {
    ch.addEventListener('click', () => toggle(ch));
    ch.addEventListener('keydown', (e) => { if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); toggle(ch); } });
  });
  if (rule) {
    row.querySelector('.a-path').value = rule.path || '';
    row.querySelector('.a-match').value = rule.exact ? 'exact' : 'prefix';
    mode.value = rule.mode || 'public';
    if (rule.accessListId) acl.value = String(rule.accessListId);
    if (rule.oidc) {
      prov.value = String(rule.oidc.providerId);
      groups.value = (rule.oidc.allowedGroups || []).join(', ');
    }
    for (const m of rule.methods || []) {
      const c = row.querySelector(`.mchip[data-m="${m}"]`);
      if (c) c.classList.add('on');
    }
  }
  syncMode();
  row.querySelector('.a-del').addEventListener('click', () => row.remove());
  $('f-auth-rules').appendChild(row);
}
$('btn-add-authrule').addEventListener('click', () => addAuthRuleRow());

function readAuthRules() {
  const out = [];
  for (const row of $('f-auth-rules').children) {
    const path = row.querySelector('.a-path').value.trim();
    if (!path) continue;
    const rule = { path, mode: row.querySelector('.a-mode').value };
    if (row.querySelector('.a-match').value === 'exact') rule.exact = true;
    if (rule.mode === 'accessList') {
      const id = row.querySelector('.a-acl').value;
      if (!id) continue;
      rule.accessListId = parseInt(id, 10);
    }
    if (rule.mode === 'oidc') {
      const pid = row.querySelector('.a-prov').value;
      if (pid) {
        rule.oidc = {
          providerId: parseInt(pid, 10),
          allowedGroups: row.querySelector('.a-groups').value.split(',').map((s) => s.trim()).filter(Boolean),
          passIdentity: true,
        };
      }
    }
    const methods = [...row.querySelectorAll('.r-methods .mchip.on')].map((c) => c.dataset.m);
    if (methods.length) rule.methods = methods;
    out.push(rule);
  }
  return out;
}

/* ---- custom location rows ---- */
function addLocationRow(loc) {
  const row = document.createElement('div');
  row.className = 'hdr-rule';
  row.innerHTML =
    '<input class="l-path" placeholder="/api" style="flex:0 0 90px">' +
    '<input class="l-up" placeholder="http://10.0.0.2:8080" style="flex:1">' +
    '<input class="l-strip" placeholder="strip /api" style="flex:0 0 110px">' +
    '<button type="button" class="btn btn--ghost btn--sm">&times;</button>';
  if (loc) {
    row.querySelector('.l-path').value = loc.path || '';
    if (loc.upstream) row.querySelector('.l-up').value = `${loc.upstream.scheme}://${loc.upstream.host}:${loc.upstream.port}`;
    if (loc.pathRewrite && loc.pathRewrite.stripPrefix) row.querySelector('.l-strip').value = loc.pathRewrite.stripPrefix;
  }
  row.children[3].addEventListener('click', () => row.remove());
  $('f-locations').appendChild(row);
}
$('btn-add-location').addEventListener('click', () => addLocationRow());

function readLocations() {
  const out = [];
  for (const row of $('f-locations').children) {
    const path = row.querySelector('.l-path').value.trim();
    const up = row.querySelector('.l-up').value.trim();
    const strip = row.querySelector('.l-strip').value.trim();
    const m = up.match(/^(https?):\/\/([^:/\s]+):(\d+)$/);
    if (!path || !m) continue;
    const loc = { path, upstream: { scheme: m[1], host: m[2], port: parseInt(m[3], 10) } };
    if (strip) loc.pathRewrite = { stripPrefix: strip };
    out.push(loc);
  }
  return out;
}

/* ---- modal ---- */
function switchTab(name) {
  for (const t of $('modal-tabs').children) t.classList.toggle('is-active', t.dataset.tab === name);
  for (const p of document.querySelectorAll('.tabpane')) p.hidden = p.dataset.pane !== name;
}
$('modal-tabs').addEventListener('click', (e) => {
  if (e.target.dataset.tab) switchTab(e.target.dataset.tab);
});

function syncHostType() {
  const t = $('f-type').value;
  $('f-upstream-row').hidden = t !== 'proxy';
  $('f-redirect-block').hidden = t !== 'redirect';
  $('f-static-block').hidden = t !== 'static';
  $('f-portal-block').hidden = t !== 'vpn-portal';
  $('f-via-row').style.display = t === 'proxy' ? '' : 'none'; // only a proxy host has an upstream to reach
  // The portal is where people get the VPN back: it cannot be VPN only.
  $('f-vpnonly-row').hidden = t === 'vpn-portal';
  for (const el of document.querySelectorAll('#modal [data-proxyonly]')) {
    el.style.display = t === 'proxy' ? '' : 'none';
  }
}
$('f-type').addEventListener('change', syncHostType);

function syncCertMode() {
  $('f-certid-field').hidden = $('f-certmode').value !== 'custom';
}
$('f-certmode').addEventListener('change', syncCertMode);
$('f-mtls-mode').addEventListener('change', () => { $('f-mtls-ca-field').hidden = !$('f-mtls-mode').value; });
$('f-maintenance').addEventListener('change', () => { $('f-maintenance-html-field').hidden = !$('f-maintenance').checked; });
$('f-oidc').addEventListener('change', () => { $('f-oidc-fields').hidden = !$('f-oidc').checked; });

function openModal(h) {
  editingId = h ? h.id : null;
  $('modal-title').textContent = h ? 'Edit host' : 'Add host';
  setError('host-error', null);
  const o = (h && h.options) || {};
  $('f-type').value = h ? h.type : 'proxy';
  $('f-domains').value = h ? h.domains.join('\n') : '';
  $('f-scheme').value = h && h.upstream ? h.upstream.scheme : 'http';
  $('f-uhost').value = h && h.upstream ? h.upstream.host : '';
  $('f-uport').value = h && h.upstream && h.upstream.port ? h.upstream.port : '';
  fillViaSelect('f-via', 'f-via-row', h && h.upstream ? h.upstream.via : 0);
  const rd = (h && h.redirect) || {};
  $('f-rcode').value = rd.httpCode || 301;
  $('f-rscheme').value = rd.targetScheme || 'auto';
  $('f-rhost').value = rd.targetHost || '';
  $('f-rpath').checked = rd.preservePath !== false;
  $('f-staticroot').value = h ? (h.staticRoot || '') : '';
  $('f-pool').value = h && h.upstreams ? h.upstreams.map((u) => `${u.scheme}://${u.host}:${u.port}`).join('\n') : '';
  const prw = o.pathRewrite || {};
  $('f-rw-strip').value = prw.stripPrefix || '';
  $('f-rw-add').value = prw.addPrefix || '';
  $('f-rw-regex').value = prw.regex || '';
  $('f-rw-repl').value = prw.replacement || '';
  $('f-locations').innerHTML = '';
  for (const l of (h && h.locations) || []) addLocationRow(l);
  $('f-badbots').checked = !!o.blockBadBots;
  $('f-badgateway').value = o.badGatewayHtml || '';
  $('f-enabled').checked = h ? h.enabled : true;
  const sel = $('f-accesslist');
  sel.innerHTML = '<option value="">Publicly accessible</option>';
  for (const a of accessLists) {
    const opt = document.createElement('option');
    opt.value = a.id;
    opt.textContent = a.name;
    sel.appendChild(opt);
  }
  sel.value = h && h.accessListId ? String(h.accessListId) : '';
  $('f-certmode').value = h ? h.certMode : 'auto';
  const csel = $('f-certid');
  csel.innerHTML = '';
  for (const c of customCerts) {
    const opt = document.createElement('option');
    opt.value = c.id;
    opt.textContent = `${c.name} (${(c.domains || []).join(', ')})`;
    csel.appendChild(opt);
  }
  csel.value = h && h.certId ? String(h.certId) : '';
  $('f-forcessl').checked = h ? h.forceSsl : true;
  $('f-http3').checked = o.http3 !== false;
  $('f-mintls').value = o.minTlsVersion || '';
  $('f-hsts').checked = !!(o.hsts && o.hsts.enabled);
  $('f-hsts-age').value = (o.hsts && o.hsts.maxAge) || 15552000;
  $('f-hsts-sub').checked = !!(o.hsts && o.hsts.includeSubdomains);
  $('f-hsts-preload').checked = !!(o.hsts && o.hsts.preload);
  $('f-noindex').checked = !!o.blockIndexing;
  $('f-exploits').checked = !!o.blockExploits;
  $('f-compress').checked = !!o.compression;
  $('f-sticky').checked = !!o.stickySessions;
  $('f-cachesec').value = o.cacheSec || '';
  $('f-maintenance').checked = !!o.maintenance;
  $('f-maintenance-html').value = o.maintenanceHtml || '';
  $('f-maintenance-html-field').hidden = !o.maintenance;
  $('f-ratelimit').checked = !!o.rateLimit;
  $('f-rate-rps').value = o.rateLimit ? o.rateLimit.rps : '';
  $('f-rate-burst').value = o.rateLimit ? o.rateLimit.burst : '';
  const fa = o.forwardAuth || {};
  $('f-fauth').checked = !!o.forwardAuth;
  $('f-fauth-url').value = fa.url || '';
  $('f-fauth-headers').value = (fa.responseHeaders || []).join(',');
  $('f-fauth-skipverify').checked = !!fa.skipTlsVerify;
  $('f-vpnonly').checked = !!o.vpnOnly;
  const vpnOnlyText = '(served inside the WireGuard tunnel and nowhere else; to everyone outside, this name does not exist)';
  $('f-vpnonly-hint').textContent = vpnOnlyText;
  api('GET', '/api/wg/status').then((st) => {
    // Without the endpoint a VPN-only host would be reachable by nobody.
    $('f-vpnonly').disabled = !st.enabled && !$('f-vpnonly').checked;
    if (!st.enabled) $('f-vpnonly-hint').textContent = '(a host served inside the WireGuard tunnel only. Switch WireGuard on first, on the VPN page)';
  }).catch(() => {});
  fillPortalBlock(h);
  const oi = o.oidc || {};
  $('f-oidc').checked = !!o.oidc;
  $('f-oidc-fields').hidden = !o.oidc;
  const provSel = $('f-oidc-provider');
  provSel.innerHTML = '';
  for (const pv of oidcProviders) {
    const opt = document.createElement('option');
    opt.value = String(pv.id);
    opt.textContent = pv.name;
    provSel.appendChild(opt);
  }
  if (oi.providerId) provSel.value = String(oi.providerId);
  $('f-oidc-warn').hidden = oidcProviders.length > 0;
  $('f-oidc-pass').checked = o.oidc ? !!oi.passIdentity : true;
  $('f-oidc-emails').value = (oi.allowedEmails || []).join(', ');
  $('f-oidc-domains').value = (oi.allowedDomains || []).join(', ');
  $('f-oidc-groups').value = (oi.allowedGroups || []).join(', ');
  const firstDomain = (h && h.domains && h.domains[0]) || '<host>';
  $('f-oidc-redirect-hint').textContent = `https://${firstDomain.replace('*.', 'www.')}/.qg/oidc/callback`;
  $('f-auth-rules').innerHTML = '';
  for (const r of o.authRules || []) addAuthRuleRow(r);
  const cc = o.clientCert || {};
  $('f-mtls-mode').value = cc.mode || '';
  $('f-mtls-ca').value = cc.caPem || '';
  $('f-mtls-ca-field').hidden = !cc.mode;
  $('f-preservehost').checked = !!o.preserveHost;
  $('f-hostoverride').value = o.hostOverride || '';
  $('f-skipverify').checked = !!o.skipTlsVerify;
  $('f-sni').value = o.upstreamSni || '';
  $('f-dialto').value = o.dialTimeoutSec || '';
  $('f-respto').value = o.responseHeaderTimeoutSec || '';
  $('f-idleto').value = o.idleTimeoutSec || '';
  $('f-maxidle').value = o.maxIdleConnsPerHost || '';
  $('f-maxbody').value = o.maxBodyMb || '';
  $('f-buffering').checked = o.buffering !== false;
  $('req-headers').innerHTML = '';
  $('resp-headers').innerHTML = '';
  for (const r of o.requestHeaders || []) addHdrRow('req-headers', r);
  for (const r of o.responseHeaders || []) addHdrRow('resp-headers', r);
  syncHostType();
  syncCertMode();
  switchTab('general');
  $('modal').hidden = false;
}

function closeModal() {
  $('modal').hidden = true;
}
$('btn-add').addEventListener('click', () => openModal(null));
$('modal-close').addEventListener('click', closeModal);
$('btn-cancel').addEventListener('click', closeModal);

$('host-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  setError('host-error', null);
  const type = $('f-type').value;
  const certMode = $('f-certmode').value;
  const host = {
    type,
    domains: $('f-domains').value.split('\n').map((s) => s.trim()).filter(Boolean),
    upstream: type === 'proxy' ? viaOn({
      scheme: $('f-scheme').value,
      host: $('f-uhost').value.trim(),
      port: parseInt($('f-uport').value, 10),
    }) : { scheme: 'http', host: '', port: 0 },
    upstreams: type === 'proxy' ? parsePool($('f-pool').value).map(viaOn) : [],
    locations: type === 'proxy' ? readLocations().map((l) => ({ ...l, upstream: viaOn(l.upstream) })) : [],
    staticRoot: type === 'static' ? $('f-staticroot').value.trim() : '',
    redirect: type === 'redirect' ? {
      httpCode: parseInt($('f-rcode').value, 10),
      targetScheme: $('f-rscheme').value,
      targetHost: $('f-rhost').value.trim(),
      preservePath: $('f-rpath').checked,
    } : null,
    certMode,
    certId: certMode === 'custom' && $('f-certid').value ? parseInt($('f-certid').value, 10) : null,
    forceSsl: (certMode === 'auto' || certMode === 'custom') && $('f-forcessl').checked,
    enabled: $('f-enabled').checked,
    accessListId: $('f-accesslist').value ? parseInt($('f-accesslist').value, 10) : null,
    options: {
      vpnOnly: type !== 'vpn-portal' && $('f-vpnonly').checked,
      portal: type === 'vpn-portal' ? readPortalOptions() : null,
      preserveHost: $('f-preservehost').checked,
      hostOverride: $('f-hostoverride').value.trim(),
      skipTlsVerify: $('f-skipverify').checked,
      upstreamSni: $('f-sni').value.trim(),
      dialTimeoutSec: parseInt($('f-dialto').value, 10) || 0,
      responseHeaderTimeoutSec: parseInt($('f-respto').value, 10) || 0,
      idleTimeoutSec: parseInt($('f-idleto').value, 10) || 0,
      maxIdleConnsPerHost: parseInt($('f-maxidle').value, 10) || 0,
      maxBodyMb: parseInt($('f-maxbody').value, 10) || 0,
      buffering: $('f-buffering').checked ? undefined : false,
      blockIndexing: $('f-noindex').checked,
      blockExploits: $('f-exploits').checked,
      blockBadBots: $('f-badbots').checked,
      compression: $('f-compress').checked,
      stickySessions: $('f-sticky').checked,
      cacheSec: parseInt($('f-cachesec').value, 10) || 0,
      maintenance: $('f-maintenance').checked,
      maintenanceHtml: $('f-maintenance-html').value,
      badGatewayHtml: $('f-badgateway').value,
      pathRewrite: ($('f-rw-strip').value.trim() || $('f-rw-add').value.trim() || $('f-rw-regex').value.trim())
        ? {
            stripPrefix: $('f-rw-strip').value.trim(),
            addPrefix: $('f-rw-add').value.trim(),
            regex: $('f-rw-regex').value.trim(),
            replacement: $('f-rw-repl').value,
          }
        : null,
      rateLimit: $('f-ratelimit').checked
        ? { rps: parseFloat($('f-rate-rps').value) || 10, burst: parseInt($('f-rate-burst').value, 10) || 20 }
        : null,
      forwardAuth: $('f-fauth').checked && $('f-fauth-url').value.trim()
        ? {
            url: $('f-fauth-url').value.trim(),
            responseHeaders: $('f-fauth-headers').value.split(',').map((s) => s.trim()).filter(Boolean),
            skipTlsVerify: $('f-fauth-skipverify').checked,
          }
        : null,
      oidc: type === 'proxy' && $('f-oidc').checked && $('f-oidc-provider').value
        ? {
            providerId: parseInt($('f-oidc-provider').value, 10),
            allowedEmails: $('f-oidc-emails').value.split(',').map((s) => s.trim()).filter(Boolean),
            allowedDomains: $('f-oidc-domains').value.split(',').map((s) => s.trim()).filter(Boolean),
            allowedGroups: $('f-oidc-groups').value.split(',').map((s) => s.trim()).filter(Boolean),
            passIdentity: $('f-oidc-pass').checked,
          }
        : null,
      authRules: type === 'proxy' ? readAuthRules() : [],
      clientCert: $('f-mtls-mode').value
        ? { mode: $('f-mtls-mode').value, caPem: $('f-mtls-ca').value }
        : null,
      requestHeaders: readHdrRows('req-headers'),
      responseHeaders: readHdrRows('resp-headers'),
      hsts: {
        enabled: $('f-hsts').checked,
        maxAge: parseInt($('f-hsts-age').value, 10) || 15552000,
        includeSubdomains: $('f-hsts-sub').checked,
        preload: $('f-hsts-preload').checked,
      },
      minTlsVersion: $('f-mintls').value,
      http3: $('f-http3').checked ? undefined : false,
    },
  };
  try {
    if (editingId) await api('PUT', `/api/hosts/${editingId}`, host);
    else await api('POST', '/api/hosts', host);
    closeModal();
    refresh();
  } catch (err) {
    setError('host-error', err);
  }
});

/* ---- access lists page ---- */
/* ---- banned addresses ----
   Who auto-ban has turned away right now, for which host and why, with a way
   to lift a ban by hand. */
function relTime(iso) {
  const secs = Math.round((new Date(iso).getTime() - Date.now()) / 1000);
  const abs = Math.abs(secs);
  const text = abs < 60 ? `${abs} s` : abs < 3600 ? `${Math.round(abs / 60)} min` : abs < 86400 ? `${Math.round(abs / 3600)} h` : `${Math.round(abs / 86400)} d`;
  return secs < 0 ? `${text} ago` : `in ${text}`;
}

async function loadBans() {
  let bans, settings;
  try {
    [bans, settings] = await Promise.all([api('GET', '/api/bans'), api('GET', '/api/settings').catch(() => ({}))]);
  } catch (err) {
    $('bans-empty').hidden = false;
    $('bans-empty').textContent = err.message;
    $('bans-table').hidden = true;
    return;
  }
  const on = settings.ban_enabled === '1';
  const mins = (s) => Math.round((parseInt(s, 10) || 0) / 60);
  $('bans-hint').textContent = on
    ? `after ${settings.ban_threshold || 5} refusals within ${mins(settings.ban_window_sec || 300)} min, for ${mins(settings.ban_duration_sec || 3600)} min`
    : 'auto-ban is off';
  $('bans-table').hidden = bans.length === 0;
  $('bans-empty').hidden = bans.length > 0;
  $('bans-empty').textContent = on ? 'No addresses are banned right now.' : 'Auto-ban is off, so nobody is banned. Turn it on under Settings, Auto-ban.';
  const names = typeof Intl.DisplayNames === 'function' ? new Intl.DisplayNames(['en'], { type: 'region' }) : null;
  const countryName = (code) => {
    if (!code) return '-';
    if (code === 'LAN') return 'Local network';
    if (code === 'unknown') return 'Unknown';
    try { return names ? names.of(code) : code; } catch { return code; }
  };
  const body = $('bans-body');
  body.replaceChildren();
  for (const b of bans) {
    const tr = body.insertRow();
    const cell = (text, cls, title) => {
      const td = tr.insertCell();
      if (cls) td.className = cls;
      td.textContent = text;
      if (title) td.title = title;
      return td;
    };
    cell(b.ip, 'mono nowrap');
    cell(countryName(b.country), 'nowrap');
    cell(b.reason || '-', 'bans__why');
    cell(b.host || '-', 'mono');
    cell(String(b.failures), 'num');
    cell(relTime(b.since), 'nowrap', new Date(b.since).toLocaleString());
    cell(relTime(b.until), 'nowrap', new Date(b.until).toLocaleString());
    const td = tr.insertCell();
    const btn = document.createElement('button');
    btn.className = 'btn btn--secondary btn--sm';
    btn.textContent = 'Unban';
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      try {
        await api('DELETE', `/api/bans/${encodeURIComponent(b.ip)}`);
        await loadBans();
      } catch (err) {
        btn.disabled = false;
        $('bans-hint').textContent = `could not unban ${b.ip}: ${err.message}`;
      }
    });
    td.appendChild(btn);
  }
}
$('btn-bans-refresh').addEventListener('click', loadBans);

async function refreshAcls() {
  loadBans();
  [accessLists, oidcProviders] = await Promise.all([
    api('GET', '/api/access-lists'), api('GET', '/api/oidc-providers').catch(() => []),
    loadWGSites(), loadVPNPeople(), // a VPN rule names sites, devices and people
  ]);
  renderIdps();
  const body = $('acl-body');
  body.innerHTML = '';
  $('acl-empty').hidden = accessLists.length > 0;
  for (const a of accessLists) {
    const tr = document.createElement('tr');
    const tdName = document.createElement('td');
    tdName.textContent = a.name;
    const tdSatisfy = document.createElement('td');
    tdSatisfy.innerHTML = `<span class="badge badge--muted">${esc(a.satisfy)}</span>`;
    const tdRules = document.createElement('td');
    tdRules.className = 'domain';
    tdRules.textContent = (a.rules || []).map((r) => `${r.action} ${r.vpn ? 'VPN: ' + describeSubject(r.vpn) : (r.cidr || r.host || ('country:' + r.country))}`).join('\n') || '-';
    tdRules.style.whiteSpace = 'pre';
    const tdUsers = document.createElement('td');
    tdUsers.className = 'domain';
    tdUsers.textContent = (a.users || []).map((u) => u.username).join(', ') || '-';
    const tdActions = document.createElement('td');
    tdActions.style.textAlign = 'right';
    const btnEdit = document.createElement('button');
    btnEdit.className = 'btn btn--secondary btn--sm';
    btnEdit.textContent = 'Edit';
    btnEdit.addEventListener('click', () => openAclModal(a));
    const btnDel = document.createElement('button');
    btnDel.className = 'btn btn--danger btn--sm';
    btnDel.textContent = 'Delete';
    btnDel.style.marginLeft = '8px';
    btnDel.addEventListener('click', async () => {
      if (!confirm(`Delete access list "${a.name}"?`)) return;
      try {
        await api('DELETE', `/api/access-lists/${a.id}`);
        refreshAcls();
      } catch (err) {
        alert(err.message);
      }
    });
    tdActions.append(btnEdit, btnDel);
    tr.append(tdName, tdSatisfy, tdRules, tdUsers, tdActions);
    body.appendChild(tr);
  }
}

// ISO 3166-1 alpha-2 codes; display names come from the browser's Intl API
// (falling back to the raw code), so a country rule is picked, never typed.
const COUNTRY_CODES = ['AD','AE','AF','AG','AI','AL','AM','AO','AQ','AR','AS','AT','AU','AW','AX','AZ','BA','BB','BD','BE','BF','BG','BH','BI','BJ','BL','BM','BN','BO','BQ','BR','BS','BT','BV','BW','BY','BZ','CA','CC','CD','CF','CG','CH','CI','CK','CL','CM','CN','CO','CR','CU','CV','CW','CX','CY','CZ','DE','DJ','DK','DM','DO','DZ','EC','EE','EG','EH','ER','ES','ET','FI','FJ','FK','FM','FO','FR','GA','GB','GD','GE','GF','GG','GH','GI','GL','GM','GN','GP','GQ','GR','GS','GT','GU','GW','GY','HK','HM','HN','HR','HT','HU','ID','IE','IL','IM','IN','IO','IQ','IR','IS','IT','JE','JM','JO','JP','KE','KG','KH','KI','KM','KN','KP','KR','KW','KY','KZ','LA','LB','LC','LI','LK','LR','LS','LT','LU','LV','LY','MA','MC','MD','ME','MF','MG','MH','MK','ML','MM','MN','MO','MP','MQ','MR','MS','MT','MU','MV','MW','MX','MY','MZ','NA','NC','NE','NF','NG','NI','NL','NO','NP','NR','NU','NZ','OM','PA','PE','PF','PG','PH','PK','PL','PM','PN','PR','PS','PT','PW','PY','QA','RE','RO','RS','RU','RW','SA','SB','SC','SD','SE','SG','SH','SI','SJ','SK','SL','SM','SN','SO','SR','SS','ST','SV','SX','SY','SZ','TC','TD','TF','TG','TH','TJ','TK','TL','TM','TN','TO','TR','TT','TV','TW','TZ','UA','UG','UM','US','UY','UZ','VA','VC','VE','VG','VI','VN','VU','WF','WS','YE','YT','ZA','ZM','ZW'];
let _regionNames = null;
function countryName(code) {
  try {
    if (!_regionNames) _regionNames = new Intl.DisplayNames([navigator.language || 'en'], { type: 'region' });
    return _regionNames.of(code) || code;
  } catch { return code; }
}
function makeCountrySelect(current) {
  const sel = document.createElement('select');
  sel.className = 'r-value';
  const opts = COUNTRY_CODES.map((c) => ({ c, n: countryName(c) })).sort((a, b) => a.n.localeCompare(b.n));
  sel.innerHTML = '<option value="">Select a country...</option>' +
    opts.map((o) => `<option value="${o.c}">${esc(o.n)} (${o.c})</option>`).join('');
  if (current) sel.value = current;
  return sel;
}
function makeTextField(placeholder, current) {
  const inp = document.createElement('input');
  inp.className = 'r-value';
  inp.placeholder = placeholder;
  if (current) inp.value = current;
  return inp;
}
// Warn in the modal when a country rule is present but GeoIP is not loaded.
function updateGeoWarn() {
  const warn = $('acl-geo-warn');
  if (!warn) return;
  const hasCountry = [...document.querySelectorAll('#acl-rules .r-kind')].some((k) => k.value === 'country');
  warn.hidden = !(hasCountry && window.__geoLoaded === false);
}

function addAclRuleRow(rule) {
  const row = document.createElement('div');
  row.className = 'hdr-rule';
  const verbs = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'];
  const chips = verbs.map((v) => `<span class="mchip" data-m="${v}" tabindex="0">${v}</span>`).join('');
  row.innerHTML =
    '<select class="r-action"><option value="allow">allow</option><option value="deny">deny</option></select>' +
    '<select class="r-kind"><option value="cidr">IP/CIDR</option><option value="host">Hostname (DDNS)</option><option value="country">Country</option><option value="vpn">On the VPN</option></select>' +
    '<span class="r-value-slot"></span>' +
    '<span class="r-methods" title="Click the verbs this rule applies to. None selected = all methods.">' + chips + '</span>' +
    '<button type="button" class="btn btn--ghost btn--sm r-del">&times;</button>';
  const action = row.querySelector('.r-action');
  const kind = row.querySelector('.r-kind');
  const slot = row.querySelector('.r-value-slot');
  const hints = { cidr: '192.168.1.0/24 or single IP', host: 'home.duckdns.org' };
  const setField = (current) => {
    slot.innerHTML = '';
    row._subject = null;
    if (kind.value === 'vpn') row._subject = makeSubjectPicker(slot, current || null, false);
    else slot.appendChild(kind.value === 'country' ? makeCountrySelect(current) : makeTextField(hints[kind.value], current));
    updateGeoWarn();
  };
  kind.addEventListener('change', () => setField(''));
  const toggle = (ch) => ch.classList.toggle('on');
  row.querySelectorAll('.mchip').forEach((ch) => {
    ch.addEventListener('click', () => toggle(ch));
    ch.addEventListener('keydown', (e) => { if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); toggle(ch); } });
  });
  if (rule) {
    action.value = rule.action;
    if (rule.vpn) kind.value = 'vpn';
    else if (rule.host) kind.value = 'host';
    else if (rule.country) kind.value = 'country';
    else kind.value = 'cidr';
    setField(rule.vpn || rule.host || rule.country || rule.cidr || '');
    for (const m of rule.methods || []) {
      const c = row.querySelector(`.mchip[data-m="${m}"]`);
      if (c) c.classList.add('on');
    }
  } else {
    setField('');
  }
  row.querySelector('.r-del').addEventListener('click', () => { row.remove(); updateGeoWarn(); });
  $('acl-rules').appendChild(row);
}

function addAclUserRow(user) {
  const row = document.createElement('div');
  row.className = 'hdr-rule';
  row.innerHTML =
    // Credentials for someone else: keep the browser's saved admin login out.
    '<input placeholder="username" autocomplete="off" data-1p-ignore data-lpignore="true" data-bwignore>' +
    '<input type="password" placeholder="password" autocomplete="new-password" data-1p-ignore data-lpignore="true" data-bwignore>' +
    '<button type="button" class="btn btn--ghost btn--sm">&times;</button>';
  if (user) {
    row.children[0].value = user.username;
    row.children[1].placeholder = 'unchanged';
  }
  row.children[2].addEventListener('click', () => row.remove());
  $('acl-users').appendChild(row);
}

async function openAclModal(a) {
  editingAclId = a ? a.id : null;
  $('acl-modal-title').textContent = a ? 'Edit access list' : 'Add access list';
  setError('acl-error', null);
  $('a-name').value = a ? a.name : '';
  $('a-satisfy').value = a ? a.satisfy : 'any';
  $('a-passauth').checked = a ? a.passAuth : false;
  $('acl-rules').innerHTML = '';
  $('acl-users').innerHTML = '';
  try { window.__geoLoaded = !!(await api('GET', '/api/geoip/status')).loaded; } catch { window.__geoLoaded = undefined; }
  await Promise.all([loadWGSites(), loadVPNPeople()]); // what a VPN rule can name
  for (const r of (a && a.rules) || []) addAclRuleRow(r);
  for (const u of (a && a.users) || []) addAclUserRow(u);
  updateGeoWarn();
  $('acl-modal').hidden = false;
}

$('btn-add-acl').addEventListener('click', () => openAclModal(null));
$('btn-add-aclrule').addEventListener('click', () => addAclRuleRow());
$('btn-add-acluser').addEventListener('click', () => addAclUserRow());
$('acl-modal-close').addEventListener('click', () => { $('acl-modal').hidden = true; });
$('acl-btn-cancel').addEventListener('click', () => { $('acl-modal').hidden = true; });

$('acl-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  setError('acl-error', null);
  const rules = [];
  for (const row of $('acl-rules').children) {
    const action = row.querySelector('.r-action').value;
    const kind = row.querySelector('.r-kind').value;
    let rule;
    if (kind === 'vpn') {
      rule = { action, vpn: row._subject() };
    } else {
      const val = row.querySelector('.r-value').value.trim();
      if (!val) continue;
      rule = { action, [kind]: val };
    }
    const methods = [...row.querySelectorAll('.r-methods .mchip.on')].map((c) => c.dataset.m);
    if (methods.length) rule.methods = methods;
    rules.push(rule);
  }
  const users = [];
  for (const row of $('acl-users').children) {
    const username = row.children[0].value.trim();
    if (!username) continue;
    const u = { username };
    if (row.children[1].value) u.password = row.children[1].value;
    users.push(u);
  }
  const list = {
    name: $('a-name').value.trim(),
    satisfy: $('a-satisfy').value,
    passAuth: $('a-passauth').checked,
    rules,
    users,
  };
  try {
    if (editingAclId) await api('PUT', `/api/access-lists/${editingAclId}`, list);
    else await api('POST', '/api/access-lists', list);
    $('acl-modal').hidden = true;
    refreshAcls();
  } catch (err) {
    setError('acl-error', err);
  }
});

/* ---- identity providers (OIDC) ---- */
function renderIdps() {
  const body = $('idp-body');
  body.innerHTML = '';
  $('idp-empty').hidden = oidcProviders.length > 0;
  for (const p of oidcProviders) {
    const tr = document.createElement('tr');
    const tdName = document.createElement('td');
    tdName.textContent = p.name;
    const tdIssuer = document.createElement('td');
    tdIssuer.className = 'domain';
    tdIssuer.textContent = p.issuer;
    const tdClient = document.createElement('td');
    tdClient.className = 'domain';
    tdClient.textContent = p.clientId;
    const tdSession = document.createElement('td');
    tdSession.innerHTML = `<span class="badge badge--muted">${esc(p.sessionHours || 12)}h</span>`;
    const tdActions = document.createElement('td');
    tdActions.style.textAlign = 'right';
    const btnEdit = document.createElement('button');
    btnEdit.className = 'btn btn--secondary btn--sm';
    btnEdit.textContent = 'Edit';
    btnEdit.addEventListener('click', () => openIdpModal(p));
    const btnDel = document.createElement('button');
    btnDel.className = 'btn btn--danger btn--sm';
    btnDel.textContent = 'Delete';
    btnDel.style.marginLeft = '8px';
    btnDel.addEventListener('click', async () => {
      if (!confirm(`Delete identity provider "${p.name}"?`)) return;
      try {
        await api('DELETE', `/api/oidc-providers/${p.id}`);
        refreshAcls();
      } catch (err) {
        alert(err.message);
      }
    });
    tdActions.append(btnEdit, btnDel);
    tr.append(tdName, tdIssuer, tdClient, tdSession, tdActions);
    body.appendChild(tr);
  }
}

let editingIdpId = null;
function openIdpModal(p) {
  editingIdpId = p ? p.id : null;
  $('idp-modal-title').textContent = p ? 'Edit identity provider' : 'Add identity provider';
  setError('idp-error', null);
  $('i-name').value = p ? p.name : '';
  $('i-issuer').value = p ? p.issuer : '';
  $('i-client').value = p ? p.clientId : '';
  $('i-secret').value = '';
  $('i-groups-claim').value = p ? (p.groupsClaim || '') : '';
  $('i-session').value = p ? (p.sessionHours || '') : '';
  $('i-skipverify').checked = p ? !!p.skipTlsVerify : false;
  $('i-scopes').value = p && p.scopes ? p.scopes.join(', ') : '';
  $('idp-modal').hidden = false;
}
$('btn-add-idp').addEventListener('click', () => openIdpModal(null));
$('idp-modal-close').addEventListener('click', () => { $('idp-modal').hidden = true; });
$('idp-btn-cancel').addEventListener('click', () => { $('idp-modal').hidden = true; });

$('idp-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  setError('idp-error', null);
  const p = {
    name: $('i-name').value.trim(),
    issuer: $('i-issuer').value.trim(),
    clientId: $('i-client').value.trim(),
    clientSecret: $('i-secret').value,
    groupsClaim: $('i-groups-claim').value.trim(),
    skipTlsVerify: $('i-skipverify').checked,
    scopes: $('i-scopes').value.split(',').map((s) => s.trim()).filter(Boolean),
  };
  const hours = parseInt($('i-session').value, 10);
  if (hours > 0) p.sessionHours = hours;
  try {
    if (editingIdpId) await api('PUT', `/api/oidc-providers/${editingIdpId}`, p);
    else await api('POST', '/api/oidc-providers', p);
    $('idp-modal').hidden = true;
    refreshAcls();
  } catch (err) {
    setError('idp-error', err);
  }
});

/* ---- streams page ---- */
async function refreshStreams() {
  let streams;
  [streams, customCerts, accessLists] = await Promise.all([api('GET', '/api/streams'), api('GET', '/api/custom-certs'), api('GET', '/api/access-lists'), loadWGSites()]);
  const body = $('streams-body');
  body.innerHTML = '';
  $('streams-empty').hidden = streams.length > 0;
  for (const s of streams) {
    const tr = document.createElement('tr');
    const tdListen = document.createElement('td');
    tdListen.className = 'domain';
    tdListen.textContent = s.listenPortEnd ? `:${s.listenPort}-${s.listenPortEnd}` : `:${s.listenPort}`;
    const badges = [];
    if (s.sendProxyProtocol) badges.push('proxy-' + s.sendProxyProtocol);
    if (s.terminateTls) badges.push('tls-term');
    if (s.sniRoutes && s.sniRoutes.length) badges.push('sni');
    if (badges.length) tdListen.innerHTML += ' ' + badges.map((b) => `<span class="badge badge--muted">${esc(b)}</span>`).join(' ');
    const failed = (s.listeners || []).filter((l) => l.state === 'failed');
    if (failed.length) {
      const b = document.createElement('span');
      b.className = 'badge badge--danger';
      b.textContent = 'not running';
      b.title = failed.map((l) => `${l.key}: ${l.error}`).join('\n');
      tdListen.append(' ', b);
    }
    const tdProto = document.createElement('td');
    tdProto.innerHTML = `<span class="badge badge--muted">${esc(s.protocol === 'both' ? 'tcp + udp' : s.protocol)}</span>`;
    const tdFwd = document.createElement('td');
    tdFwd.className = 'domain';
    tdFwd.textContent = `${s.forwardHost}:${s.forwardPort}${s.via ? ' via ' + wgSiteName(s.via) : ''}`;
    const tdSources = document.createElement('td');
    const nCidrs = (s.allowedCidrs || []).length;
    if (s.accessListId) {
      const acl = accessLists.find((a) => a.id === s.accessListId);
      tdSources.innerHTML = `<span class="badge">${esc(acl ? acl.name : 'access list')}</span>`;
    } else if (nCidrs) {
      tdSources.innerHTML = `<span class="badge">${nCidrs} CIDR${nCidrs > 1 ? 's' : ''}</span>`;
    } else {
      tdSources.innerHTML = '<span class="badge badge--warn" title="No source restriction: anyone who can reach the port">anyone</span>';
    }
    const tdEnabled = document.createElement('td');
    const sw = document.createElement('label');
    sw.className = 'switch';
    sw.innerHTML = '<input type="checkbox"><span class="switch__slot"></span><span class="switch__knob"></span>';
    const cb = sw.querySelector('input');
    cb.checked = s.enabled;
    cb.addEventListener('change', async () => {
      try {
        const { listeners, ...stored } = s;
        await api('PUT', `/api/streams/${s.id}`, { ...stored, enabled: cb.checked });
        refreshStreams();
      } catch (err) {
        alert(err.message);
        cb.checked = !cb.checked;
      }
    });
    tdEnabled.appendChild(sw);
    const tdActions = document.createElement('td');
    tdActions.style.textAlign = 'right';
    const btnEdit = document.createElement('button');
    btnEdit.className = 'btn btn--secondary btn--sm';
    btnEdit.textContent = 'Edit';
    btnEdit.addEventListener('click', () => openStreamModal(s));
    const btnDel = document.createElement('button');
    btnDel.className = 'btn btn--danger btn--sm';
    btnDel.textContent = 'Delete';
    btnDel.style.marginLeft = '8px';
    btnDel.addEventListener('click', async () => {
      if (!confirm(`Delete stream :${s.listenPort}?`)) return;
      await api('DELETE', `/api/streams/${s.id}`);
      refreshStreams();
    });
    tdActions.append(btnEdit, btnDel);
    tr.append(tdListen, tdProto, tdFwd, tdSources, tdEnabled, tdActions);
    body.appendChild(tr);
  }
}

function openStreamModal(s) {
  editingStreamId = s ? s.id : null;
  $('stream-modal-title').textContent = s ? 'Edit stream' : 'Add stream';
  setError('stream-error', null);
  $('s-port').value = s ? s.listenPort : '';
  $('s-port-end').value = s && s.listenPortEnd ? s.listenPortEnd : '';
  $('s-proto').value = s ? s.protocol : 'tcp';
  $('s-fhost').value = s ? s.forwardHost : '';
  $('s-fport').value = s ? s.forwardPort : '';
  fillViaSelect('s-via', 's-via-row', s ? s.via : 0);
  $('s-cidrs').value = s && s.allowedCidrs ? s.allowedCidrs.join('\n') : '';
  const src = $('s-source');
  src.innerHTML = '<option value="">Inline CIDR list</option>';
  for (const a of accessLists) {
    const opt = document.createElement('option');
    opt.value = String(a.id); opt.textContent = 'Access list: ' + a.name;
    src.appendChild(opt);
  }
  src.value = s && s.accessListId ? String(s.accessListId) : '';
  $('s-cidrs-field').hidden = !!src.value;
  $('s-sendproxy').value = s ? (s.sendProxyProtocol || '') : '';
  $('s-acceptproxy').checked = s ? !!s.acceptProxyProtocol : false;
  $('s-trusted').value = s && s.trustedProxies ? s.trustedProxies.join('\n') : '';
  $('s-trusted-field').hidden = !$('s-acceptproxy').checked;
  $('s-terminatetls').checked = s ? !!s.terminateTls : false;
  const csel = $('s-certid');
  csel.innerHTML = '';
  for (const c of customCerts) {
    const opt = document.createElement('option');
    opt.value = c.id; opt.textContent = c.name;
    csel.appendChild(opt);
  }
  csel.value = s && s.certId ? String(s.certId) : '';
  $('s-cert-field').hidden = !(s && s.terminateTls);
  $('s-sni').value = s && s.sniRoutes ? s.sniRoutes.map((r) => `${r.host} = ${r.forwardHost}:${r.forwardPort}`).join('\n') : '';
  $('s-enabled').checked = s ? s.enabled : true;
  $('stream-modal').hidden = false;
}
$('s-terminatetls').addEventListener('change', () => { $('s-cert-field').hidden = !$('s-terminatetls').checked; });
$('s-acceptproxy').addEventListener('change', () => { $('s-trusted-field').hidden = !$('s-acceptproxy').checked; });
$('s-source').addEventListener('change', () => { $('s-cidrs-field').hidden = !!$('s-source').value; });

$('btn-add-stream').addEventListener('click', () => openStreamModal(null));
$('stream-modal-close').addEventListener('click', () => { $('stream-modal').hidden = true; });
$('stream-btn-cancel').addEventListener('click', () => { $('stream-modal').hidden = true; });

$('stream-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  setError('stream-error', null);
  const sniRoutes = [];
  for (const line of $('s-sni').value.split('\n').map((v) => v.trim()).filter(Boolean)) {
    const m = line.match(/^(\S+)\s*=\s*(\S+):(\d+)$/);
    if (m) sniRoutes.push({ host: m[1], forwardHost: m[2], forwardPort: parseInt(m[3], 10) });
  }
  const s = {
    listenPort: parseInt($('s-port').value, 10),
    listenPortEnd: parseInt($('s-port-end').value, 10) || 0,
    protocol: $('s-proto').value,
    forwardHost: $('s-fhost').value.trim(),
    forwardPort: parseInt($('s-fport').value, 10) || 0,
    via: parseInt($('s-via').value, 10) || 0,
    allowedCidrs: $('s-source').value ? [] : $('s-cidrs').value.split('\n').map((v) => v.trim()).filter(Boolean),
    accessListId: $('s-source').value ? parseInt($('s-source').value, 10) : null,
    sendProxyProtocol: $('s-sendproxy').value,
    acceptProxyProtocol: $('s-acceptproxy').checked,
    trustedProxies: $('s-acceptproxy').checked ? $('s-trusted').value.split('\n').map((v) => v.trim()).filter(Boolean) : [],
    terminateTls: $('s-terminatetls').checked,
    certId: $('s-terminatetls').checked && $('s-certid').value ? parseInt($('s-certid').value, 10) : null,
    sniRoutes,
    enabled: $('s-enabled').checked,
  };
  try {
    const saved = editingStreamId ? await api('PUT', `/api/streams/${editingStreamId}`, s) : await api('POST', '/api/streams', s);
    // Saved is not the same as running: say so, and keep editing the stored
    // stream (a second Save must update it, not create a duplicate).
    editingStreamId = saved.id;
    refreshStreams();
    const failed = (saved.listeners || []).filter((l) => l.state === 'failed');
    if (failed.length) {
      setError('stream-error', new Error('Saved, but not running: ' + failed.map((l) => `${l.key}: ${l.error}`).join('; ')));
      return;
    }
    $('stream-modal').hidden = true;
  } catch (err) {
    setError('stream-error', err);
  }
});

/* ---- custom certificates page ---- */
async function refreshCustomCerts() {
  customCerts = await api('GET', '/api/custom-certs');
  const body = $('ccerts-body');
  body.innerHTML = '';
  $('ccerts-empty').hidden = customCerts.length > 0;
  for (const c of customCerts) {
    const tr = document.createElement('tr');
    const expired = c.notAfter && new Date(c.notAfter) < new Date();
    tr.innerHTML =
      `<td>${esc(c.name)}</td>` +
      `<td class="domain">${esc((c.domains || []).join(', '))}</td>` +
      `<td class="domain"><span class="badge ${expired ? 'badge--danger' : 'badge--success'}">${esc(c.notAfter ? new Date(c.notAfter).toLocaleDateString() : '-')}</span></td>`;
    const tdActions = document.createElement('td');
    tdActions.style.textAlign = 'right';
    const btnEdit = document.createElement('button');
    btnEdit.className = 'btn btn--secondary btn--sm';
    btnEdit.textContent = 'Replace';
    btnEdit.addEventListener('click', () => openCertModal(c));
    const btnDel = document.createElement('button');
    btnDel.className = 'btn btn--danger btn--sm';
    btnDel.textContent = 'Delete';
    btnDel.style.marginLeft = '8px';
    btnDel.addEventListener('click', async () => {
      if (!confirm(`Delete certificate "${c.name}"?`)) return;
      try {
        await api('DELETE', `/api/custom-certs/${c.id}`);
        refreshCustomCerts();
      } catch (err) {
        alert(err.message);
      }
    });
    tdActions.append(btnEdit, btnDel);
    tr.appendChild(tdActions);
    body.appendChild(tr);
  }
}

function openCertModal(c) {
  editingCertId = c ? c.id : null;
  $('cert-modal-title').textContent = c ? 'Replace certificate' : 'Upload certificate';
  setError('cert-error', null);
  $('c-name').value = c ? c.name : '';
  $('c-cert').value = '';
  $('c-key').value = '';
  $('c-key-hint').textContent = c ? '(re-paste both cert and key to replace)' : '';
  $('cert-modal').hidden = false;
}
$('btn-add-cert').addEventListener('click', () => openCertModal(null));
$('cert-modal-close').addEventListener('click', () => { $('cert-modal').hidden = true; });
$('cert-btn-cancel').addEventListener('click', () => { $('cert-modal').hidden = true; });

$('cert-tabs').addEventListener('click', (e) => {
  const t = e.target.dataset.ctab;
  if (!t) return;
  for (const b of $('cert-tabs').children) b.classList.toggle('is-active', b.dataset.ctab === t);
  $('cert-form').hidden = t !== 'upload';
  $('cert-selfsigned-form').hidden = t !== 'selfsigned';
});

$('cert-selfsigned-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  setError('ss-error', null);
  try {
    await api('POST', '/api/custom-certs/self-signed', {
      name: $('ss-name').value.trim(),
      domains: $('ss-domains').value.split('\n').map((s) => s.trim()).filter(Boolean),
      days: parseInt($('ss-days').value, 10) || 825,
    });
    $('cert-modal').hidden = true;
    refreshCustomCerts();
  } catch (err) { setError('ss-error', err); }
});

$('import-file').addEventListener('change', async () => {
  const file = $('import-file').files[0];
  if (!file) return;
  const el = $('restore-status');
  el.hidden = false;
  el.textContent = 'Importing...';
  try {
    const text = await file.text();
    const res = await fetch('/api/import', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: text });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.statusText);
    const up = data.updated || {};
    el.textContent = `Imported: created ${data.hosts || 0} hosts, ${data.accessLists || 0} access lists, ${data.streams || 0} streams; updated ${up.hosts || 0} hosts, ${up.accessLists || 0} access lists, ${up.streams || 0} streams.`;
  } catch (err) {
    el.textContent = 'Import failed: ' + err.message;
  }
  $('import-file').value = '';
});

$('cert-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  setError('cert-error', null);
  const c = { name: $('c-name').value.trim(), certPem: $('c-cert').value, keyPem: $('c-key').value };
  try {
    if (editingCertId) await api('PUT', `/api/custom-certs/${editingCertId}`, c);
    else await api('POST', '/api/custom-certs', c);
    $('cert-modal').hidden = true;
    refreshCustomCerts();
  } catch (err) {
    setError('cert-error', err);
  }
});

/* ---- profile page ---- */
function loadProfile() {
  refreshTokens();
  refresh2FA();
}

$('profile-email-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  setError('pe-error', null);
  try {
    const out = await api('POST', '/api/email', { email: $('pe-email').value.trim(), password: $('pe-password').value });
    $('pe-password').value = '';
    showAccountEmail(out.email);
    flashStatus($('pe-error'), 'Email updated: sign in with ' + out.email + ' from now on', false);
  } catch (err) {
    flashStatus($('pe-error'), err.message, true);
  }
});

$('profile-pw-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  setError('pp-error', null);
  try {
    await api('POST', '/api/password', { current: $('pp-current').value, new: $('pp-new').value });
    $('pp-current').value = '';
    $('pp-new').value = '';
    flashStatus($('pp-error'), 'Password updated', false);
  } catch (err) {
    flashStatus($('pp-error'), err.message, true);
  }
});

/* ---- logs page ----
   One viewer for every access log: traffic that matched no host, all of it,
   or a single host. The server returns the newest entries (at most 2000);
   filtering and paging happen here, so a busy log is a page of rows instead of
   twenty screens. */
const logState = { entries: [], page: 0, status: '', pendingScope: '' };

function logScopeQuery(scope) {
  if (scope === 'unmatched') return '&general=1';
  if (scope === 'all') return '';
  return '&host=' + encodeURIComponent(scope.replace(/^host:/, ''));
}

async function loadLogs() {
  if (!hosts.length) hosts = await api('GET', '/api/hosts').catch(() => []);
  fillLogScopes();
  await refreshLogs();
}

function fillLogScopes() {
  const sel = $('logs-scope');
  const keep = logState.pendingScope || sel.value || 'unmatched';
  logState.pendingScope = '';
  sel.innerHTML = '';
  const add = (parent, value, label) => {
    const o = document.createElement('option');
    o.value = value;
    o.textContent = label;
    parent.appendChild(o);
  };
  add(sel, 'unmatched', 'Unmatched traffic');
  add(sel, 'all', 'All traffic');
  const domains = [...new Set(hosts.flatMap((h) => h.domains))].sort();
  if (domains.length) {
    const group = document.createElement('optgroup');
    group.label = 'Proxy hosts';
    for (const d of domains) add(group, 'host:' + d, d);
    sel.appendChild(group);
  }
  sel.value = [...sel.options].some((o) => o.value === keep) ? keep : 'unmatched';
}

async function refreshLogs() {
  const scope = $('logs-scope').value || 'unmatched';
  logState.entries = (await api('GET', '/api/logs?n=2000' + logScopeQuery(scope)).catch(() => [])) || [];
  logState.page = 0;
  $('logs-host-col').hidden = scope.startsWith('host:');
  renderLogs();
}

function filteredLogs() {
  const q = $('logs-filter').value.trim().toLowerCase();
  return logState.entries.filter((e) => {
    if (logState.status && String(e.status).charAt(0) !== logState.status) return false;
    return !q || `${e.host} ${e.client_ip} ${e.method} ${e.path} ${e.status}`.toLowerCase().includes(q);
  });
}

function fmtLogTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  if (d.toDateString() === new Date().toDateString()) return d.toLocaleTimeString([], { hour12: false });
  return d.toLocaleString([], { hour12: false, month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function logRow(e, withHost) {
  const tr = document.createElement('tr');
  const cls = e.status >= 500 ? 'st--5' : e.status >= 400 ? 'st--4' : e.status >= 300 ? 'st--3' : 'st--2';
  // Host, method and path are whatever a remote client sent: never markup.
  tr.innerHTML =
    `<td class="mono nowrap">${esc(fmtLogTime(e.ts))}</td>` +
    `<td class="mono nowrap">${esc(e.client_ip)}</td>` +
    (withHost ? `<td class="mono">${esc(e.host)}</td>` : '') +
    `<td class="mono">${esc(e.method)}</td>` +
    `<td class="mono logpath" title="${esc(e.path)}">${esc(e.path)}</td>` +
    `<td><span class="st ${cls}">${esc(e.status)}</span></td>` +
    `<td class="mono num">${esc(e.dur_ms)}</td>`;
  return tr;
}

function renderLogs() {
  const rows = filteredLogs();
  const size = parseInt($('logs-pagesize').value, 10) || 50;
  const pages = Math.max(1, Math.ceil(rows.length / size));
  logState.page = Math.max(0, Math.min(logState.page, pages - 1));
  const start = logState.page * size;
  const slice = rows.slice(start, start + size);
  const withHost = !$('logs-scope').value.startsWith('host:');
  const body = $('logs-body');
  body.innerHTML = '';
  for (const e of slice) body.appendChild(logRow(e, withHost));
  $('logs-empty').hidden = rows.length > 0;
  $('logs-count').textContent = rows.length ? `${start + 1}-${start + slice.length} of ${rows.length}` : '0 entries';
  $('logs-page').textContent = `${logState.page + 1} / ${pages}`;
  $('logs-prev').disabled = logState.page === 0;
  $('logs-next').disabled = logState.page >= pages - 1;
}

function logsToPage(delta) {
  logState.page += delta;
  renderLogs();
  $('logs-table').closest('.logview__scroll').scrollTop = 0;
}

$('logs-scope').addEventListener('change', refreshLogs);
$('logs-filter').addEventListener('input', () => { logState.page = 0; renderLogs(); });
$('logs-pagesize').addEventListener('change', () => { logState.page = 0; renderLogs(); });
$('logs-status').addEventListener('click', (e) => {
  const b = e.target.closest('[data-status]');
  if (!b) return;
  logState.status = b.dataset.status;
  for (const x of $('logs-status').children) x.classList.toggle('is-active', x === b);
  logState.page = 0;
  renderLogs();
});
$('logs-prev').addEventListener('click', () => logsToPage(-1));
$('logs-next').addEventListener('click', () => logsToPage(1));
$('btn-logs-refresh').addEventListener('click', refreshLogs);

// A host's Logs button opens the Logs page scoped to that host.
function openHostLogs(h) {
  logState.pendingScope = 'host:' + h.domains[0];
  switchPage('logs');
}

async function refreshTokens() {
  const tokens = await api('GET', '/api/tokens').catch(() => []);
  const body = $('tokens-body');
  body.innerHTML = '';
  $('tokens-empty').hidden = tokens.length > 0;
  for (const t of tokens) {
    const tr = document.createElement('tr');
    const td0 = document.createElement('td'); td0.textContent = t.name;
    const tdMay = document.createElement('td'); tdMay.textContent = TOKEN_ACCESS[t.access] ? TOKEN_ACCESS[t.access].name : t.access;
    const td1 = document.createElement('td'); td1.className = 'domain'; td1.textContent = t.createdAt ? new Date(t.createdAt).toLocaleDateString() : '';
    const td2 = document.createElement('td'); td2.style.textAlign = 'right';
    const del = document.createElement('button');
    del.className = 'btn btn--danger btn--sm'; del.textContent = 'Revoke';
    del.addEventListener('click', async () => { await api('DELETE', `/api/tokens/${t.id}`); refreshTokens(); });
    td2.appendChild(del);
    tr.append(td0, tdMay, td1, td2);
    body.appendChild(tr);
  }
}
// What each kind of API token may do, in the words of the token page.
const TOKEN_ACCESS = {
  monitor: { name: 'Monitoring', hint: 'Reads how things are doing: hosts and whether their backends answer, certificates, traffic, bans and metrics. It cannot see how a host is configured, cannot read settings, logs or backups, and cannot change anything. Right for a dashboard.' },
  switch: { name: 'Monitoring + host switch', hint: 'Reads what a monitoring token reads, and can switch a proxy host on or off. It can change nothing else. Right for home automation.' },
  full: { name: 'Full access', hint: 'Does everything you can do in this interface, including downloading backups and changing settings. Give it only to something you trust as much as your own login.' },
};
function tokenAccessHint() { $('token-access-hint').textContent = TOKEN_ACCESS[$('token-access').value].hint; }
$('token-access').addEventListener('change', tokenAccessHint);
$('btn-add-token').addEventListener('click', () => {
  $('token-form').hidden = false;
  $('new-token').hidden = true;
  tokenAccessHint();
  $('token-name').focus();
});
$('token-cancel').addEventListener('click', () => { $('token-form').hidden = true; $('token-form').reset(); });
$('token-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = $('token-name').value.trim();
  if (!name) return;
  try {
    const t = await api('POST', '/api/tokens', { name, access: $('token-access').value });
    const el = $('new-token');
    el.hidden = false;
    el.textContent = `New ${TOKEN_ACCESS[t.access].name.toLowerCase()} token (copy now, shown once): ${t.token}`;
    $('token-form').hidden = true;
    $('token-form').reset();
    refreshTokens();
  } catch (err) { alert(err.message); }
});

let pending2FASecret = null;
async function refresh2FA() {
  const me = await api('GET', '/api/me');
  const el = $('twofa-status');
  el.innerHTML = '';
  setError('twofa-error', null);
  $('twofa-setup').hidden = true;
  $('twofa-disable').hidden = true;
  if (me.totpEnabled) {
    el.innerHTML = '<span class="badge badge--success">2FA enabled</span> ';
    const btn = document.createElement('button');
    btn.className = 'btn btn--danger btn--sm'; btn.textContent = 'Disable';
    // Switching the second factor off needs the password again.
    btn.addEventListener('click', () => { $('twofa-disable').hidden = false; $('twofa-disable-password').focus(); });
    el.appendChild(btn);
  } else {
    const btn = document.createElement('button');
    btn.className = 'btn btn--primary btn--sm'; btn.textContent = 'Enable 2FA';
    btn.addEventListener('click', async () => {
      const s = await api('POST', '/api/2fa/setup');
      pending2FASecret = s.secret;
      $('twofa-secret').textContent = s.secret;
      $('twofa-setup').hidden = false;
    });
    el.appendChild(btn);
  }
}
$('twofa-confirm').addEventListener('click', async () => {
  setError('twofa-error', null);
  try {
    await api('POST', '/api/2fa/enable', { secret: pending2FASecret, code: $('twofa-code').value.trim(), password: $('twofa-password').value });
    $('twofa-code').value = '';
    $('twofa-password').value = '';
    refresh2FA();
  } catch (err) { setError('twofa-error', err); }
});
$('twofa-disable-confirm').addEventListener('click', async () => {
  setError('twofa-error', null);
  try {
    await api('POST', '/api/2fa/disable', { password: $('twofa-disable-password').value });
    $('twofa-disable-password').value = '';
    refresh2FA();
  } catch (err) { setError('twofa-error', err); }
});

function sessionsNote(text) {
  const el = $('sessions-status');
  el.hidden = false;
  el.textContent = text;
}
$('btn-revoke-admin-sessions').addEventListener('click', async () => {
  if (!confirm('Sign out every other admin session? This session stays signed in.')) return;
  try {
    const r = await api('POST', '/api/sessions/revoke');
    sessionsNote(`Signed out ${r.revoked} other session${r.revoked === 1 ? '' : 's'}.`);
  } catch (err) { sessionsNote('Failed: ' + err.message); }
});
$('btn-revoke-sso-sessions').addEventListener('click', async () => {
  if (!confirm('Sign every user out of every SSO-protected host? They will have to log in at the identity provider again.')) return;
  try {
    await api('POST', '/api/sso/revoke-sessions');
    sessionsNote('The SSO signing key was replaced; every SSO session has ended.');
  } catch (err) { sessionsNote('Failed: ' + err.message); }
});

/* ---- settings page ---- */
// flashStatus shows the outcome of a save in the panel's own status line.
function flashStatus(el, text, isError) {
  if (!el) return;
  el.hidden = false;
  el.textContent = text;
  el.classList.toggle('is-error', !!isError);
  el.classList.toggle('is-ok', !isError);
  clearTimeout(el._timer);
  if (!isError) el._timer = setTimeout(() => { el.hidden = true; }, 4000);
}

async function saveSettings(panel, values, statusEl) {
  const el = statusEl || panel.querySelector('[data-status]');
  try {
    await api('PUT', '/api/settings', values);
    flashStatus(el, 'Saved', false);
    return true;
  } catch (err) {
    flashStatus(el, err.message, true);
    return false;
  }
}

function syncDnsField() {
  $('dns-config-field').hidden = $('set-dns-provider').value === '';
}
$('set-dns-provider').addEventListener('change', syncDnsField);

function syncDefaultSiteField() {
  const v = $('set-default-site').value;
  $('default-site-value-field').hidden = v === '404';
  $('default-site-value-label').textContent = v === 'redirect' ? 'Redirect URL' : 'HTML';
}
$('set-default-site').addEventListener('change', syncDefaultSiteField);

/* ---- docker ---- */
async function refreshDocker() {
  let st;
  try {
    st = await api('GET', '/api/docker/status');
  } catch (err) {
    $('docker-status').textContent = err.message;
    return;
  }
  const settingsCard = $('docker-settings-card');
  const contCard = $('docker-containers-card');
  if (st.enabled === false) {
    $('docker-status').innerHTML = 'Docker integration is <strong>disabled</strong>. Start quicgate with <span class="mono">QG_DOCKER=1</span> and the Docker socket mounted (<span class="mono">/var/run/docker.sock:ro</span>) to enable it.';
    settingsCard.hidden = true;
    contCard.hidden = true;
    return;
  }
  settingsCard.hidden = false;
  contCard.hidden = false;

  // Per-endpoint connection status.
  const eps = st.endpoints || [];
  $('docker-status').innerHTML = eps.length
    ? eps.map((e) => {
        const dot = e.connected
          ? '<span class="badge badge--success">connected</span>'
          : '<span class="badge badge--danger">disconnected</span>';
        let s = `${dot} <b>${esc(e.name)}</b> <span class="mono hs-muted">${esc(e.connect)}</span> &rarr; <span class="mono">${esc(e.address)}</span>`;
        if (e.error) s += `<br><span class="form-error" style="display:inline">${esc(e.error)}</span>`;
        return s;
      }).join('<div style="border-top:1px solid rgba(127,127,127,.25);margin:6px 0"></div>')
    : '<span class="hs-muted">No Docker hosts configured.</span>';

  // Settings.
  const s = await api('GET', '/api/settings');
  $('dk-domain').value = s.docker_default_domain || '';
  $('dk-endpoints').value = s.docker_endpoints || '';

  const body = $('docker-body');
  body.innerHTML = '';
  const cs = st.containers || [];
  $('docker-empty').hidden = cs.length > 0;
  for (const c of cs) {
    const tr = document.createElement('tr');

    const tdName = document.createElement('td');
    tdName.className = 'domain';
    tdName.textContent = c.name;

    const tdHost = document.createElement('td');
    tdHost.innerHTML = `<span class="badge badge--muted">${esc(c.endpoint)}</span>`;

    const tdRoute = document.createElement('td');
    tdRoute.innerHTML = c.routed
      ? '<span class="badge badge--success">routed</span>'
      : '<span class="badge badge--danger">not routed</span>';

    const tdDetail = document.createElement('td');
    const parts = [];
    if (c.domains && c.domains.length) {
      parts.push(c.domains.map(esc).join(', ') + (c.upstream ? ` <span class="hs-muted">&rarr; ${esc(c.upstream)}</span>` : ''));
    }
    for (const line of c.streams || []) parts.push(`<span class="mono">${esc(line)}</span>`);
    tdDetail.innerHTML = parts.join('<br>') || '<span class="hs-muted">&mdash;</span>';

    const tdWarn = document.createElement('td');
    tdWarn.innerHTML = (c.warnings && c.warnings.length)
      ? c.warnings.map((w) => `<span class="badge badge--danger">!</span> ${esc(w)}`).join('<br>')
      : '<span class="hs-muted">&mdash;</span>';

    const tdAct = document.createElement('td');
    tdAct.style.textAlign = 'right';
    if (c.routed) {
      const b = document.createElement('button');
      b.className = 'btn btn--secondary btn--sm';
      b.textContent = 'Convert to host';
      b.title = 'Persist this container’s routes as editable configuration';
      b.addEventListener('click', async () => {
        if (!confirm(`Convert ${c.name}'s routes into managed (editable) configuration? The container labels stay in place but the manual config takes over.`)) return;
        try {
          await api('POST', '/api/docker/adopt', { endpoint: c.endpoint, name: c.name });
          refreshDocker();
        } catch (err) {
          alert(err.message);
        }
      });
      tdAct.appendChild(b);
    }

    tr.append(tdName, tdHost, tdRoute, tdDetail, tdWarn, tdAct);
    body.appendChild(tr);
  }
}
$('btn-docker-refresh').addEventListener('click', refreshDocker);
$('dk-domain-save').addEventListener('click', async () => {
  try {
    await api('PUT', '/api/settings', { docker_default_domain: $('dk-domain').value.trim() });
    refreshDocker();
  } catch (err) {
    alert(err.message);
  }
});
$('dk-endpoints-save').addEventListener('click', async () => {
  const v = $('dk-endpoints').value.trim();
  if (v) {
    try { JSON.parse(v); } catch { alert('Docker hosts must be valid JSON'); return; }
  }
  try {
    await api('PUT', '/api/settings', { docker_endpoints: v });
    alert('Saved. Restart quicgate to apply Docker host changes.');
  } catch (err) {
    alert(err.message);
  }
});

/* ---- geoip ---- */
async function refreshGeoIP() {
  let g;
  try { g = await api('GET', '/api/geoip/status'); }
  catch (err) { $('geoip-status').textContent = err.message; return; }
  window.__geoLoaded = !!g.loaded;
  if (g.loaded) {
    $('geoip-status').innerHTML = '<span class="badge badge--success">loaded</span> ' +
      `<span class="mono">${esc(g.type || 'database')}</span>` +
      (g.buildDate ? ` &middot; built ${esc(g.buildDate)}` : '') +
      ` &middot; <span class="hs-muted mono">${esc(g.path)}</span>`;
  } else {
    $('geoip-status').innerHTML = '<span class="badge badge--danger">not loaded</span> country rules are inactive' +
      (g.path ? ` &middot; expected at <span class="mono">${esc(g.path)}</span>` : '') +
      (g.error ? `<br><span class="hs-muted">${esc(g.error)}</span>` : '');
  }
}
$('geoip-reload').addEventListener('click', async () => {
  try { await api('POST', '/api/geoip/reload'); refreshGeoIP(); }
  catch (err) { alert(err.message); }
});
$('geoip-test-btn').addEventListener('click', async () => {
  const ip = $('geoip-test-ip').value.trim();
  const out = $('geoip-test-result');
  if (!ip) { out.textContent = ''; return; }
  try {
    const r = await api('GET', '/api/geoip/lookup?ip=' + encodeURIComponent(ip));
    out.innerHTML = r.country
      ? `&rarr; <b>${esc(r.country)}</b> <span class="hs-muted">${esc(countryName(r.country))}</span>`
      : '&rarr; <span class="hs-muted">no country for this IP</span>';
  } catch (err) { out.innerHTML = `&rarr; <span class="form-error" style="display:inline">${esc(err.message)}</span>`; }
});

// Settings only shows the fields for features that are switched on, and only
// the inline IdP fields when no shared provider is selected. An unconfigured
// page is then a short list of toggles rather than three screens of empty
// inputs for things you do not use.
function syncSettingsDisclosure() {
  const pairs = [
    ['set-oidc-enabled', 'oidc-config'],
    ['set-ldap-enabled', 'ldap-config'],
    ['set-ban-enabled', 'ban-config'],
  ];
  for (const [toggle, block] of pairs) {
    const t = $(toggle);
    const b = $(block);
    if (t && b) b.hidden = !t.checked;
  }
  const prov = $('set-oidc-provider');
  const inline = $('oidc-inline-fields');
  if (prov && inline) inline.hidden = !!prov.value;
}
for (const id of ['set-oidc-enabled', 'set-ldap-enabled', 'set-ban-enabled', 'set-oidc-provider']) {
  const el = $(id);
  if (el) el.addEventListener('change', syncSettingsDisclosure);
}

async function loadSettings() {
  refreshGeoIP();
  // The admin-login provider picker lists the same providers as the hosts use.
  oidcProviders = await api('GET', '/api/oidc-providers').catch(() => oidcProviders);
  const s = await api('GET', '/api/settings');
  $('set-acme-email').value = s.acme_email || '';
  $('set-acme-staging').checked = s.acme_staging === '1';
  $('set-acme-ca-url').value = s.acme_ca_url || '';
  $('set-notify-url').value = s.notify_url || '';
  $('set-dns-provider').value = s.acme_dns_provider || '';
  $('set-dns-config').value = s.acme_dns_config || '';
  $('set-default-site').value = s.default_site || '404';
  $('set-default-site-value').value = s.default_site_value || '';
  $('set-ban-enabled').checked = s.ban_enabled === '1';
  $('set-ban-threshold').value = s.ban_threshold || '';
  $('set-ban-window').value = s.ban_window_sec || '';
  $('set-ban-duration').value = s.ban_duration_sec || '';
  $('set-ban-exempt-own').checked = s.ban_exempt_own === '1';
  $('set-ban-exempt').value = s.ban_exempt || '';
  refreshOwnAddresses();
  $('set-oidc-enabled').checked = s.oidc_enabled === '1';
  const adminProv = $('set-oidc-provider');
  adminProv.innerHTML = '';
  const inlineOpt = document.createElement('option');
  inlineOpt.value = '';
  inlineOpt.textContent = 'use the fields below';
  adminProv.appendChild(inlineOpt);
  for (const pv of oidcProviders) {
    const opt = document.createElement('option');
    opt.value = String(pv.id);
    opt.textContent = pv.name;
    adminProv.appendChild(opt);
  }
  adminProv.value = s.admin_oidc_provider_id || '';
  syncSettingsDisclosure();
  $('set-oidc-issuer').value = s.oidc_issuer || '';
  $('set-oidc-client-id').value = s.oidc_client_id || '';
  $('set-oidc-client-secret').value = s.oidc_client_secret || '';
  $('set-oidc-redirect').value = s.oidc_redirect_url || '';
  $('set-oidc-emails').value = s.oidc_allowed_emails || '';
  $('set-ldap-enabled').checked = s.ldap_enabled === '1';
  $('set-ldap-url').value = s.ldap_url || '';
  $('set-ldap-dn').value = s.ldap_bind_dn_template || '';
  $('set-ldap-allowed').value = s.ldap_allowed_users || '';
  $('set-trustedproxies').value = s.trusted_proxies || '';
  $('set-realip-header').value = s.real_ip_header || '';
  syncDnsField();
  syncDefaultSiteField();
}

$('oidc-form').addEventListener('submit', (e) => {
  e.preventDefault();
  saveSettings($('oidc-form'), {
    oidc_enabled: $('set-oidc-enabled').checked ? '1' : '0',
    admin_oidc_provider_id: $('set-oidc-provider').value,
    oidc_issuer: $('set-oidc-issuer').value.trim(),
    oidc_client_id: $('set-oidc-client-id').value.trim(),
    oidc_client_secret: $('set-oidc-client-secret').value,
    oidc_redirect_url: $('set-oidc-redirect').value.trim(),
    oidc_allowed_emails: $('set-oidc-emails').value.trim(),
  });
});

$('ldap-form').addEventListener('submit', (e) => {
  e.preventDefault();
  saveSettings($('ldap-form'), {
    ldap_enabled: $('set-ldap-enabled').checked ? '1' : '0',
    ldap_url: $('set-ldap-url').value.trim(),
    ldap_bind_dn_template: $('set-ldap-dn').value.trim(),
    ldap_allowed_users: $('set-ldap-allowed').value.trim(),
  });
});

$('set-trustedproxies-save').addEventListener('click', () => {
  saveSettings($('trustedproxies-panel'), {
    trusted_proxies: $('set-trustedproxies').value.trim(),
    real_ip_header: $('set-realip-header').value.trim(),
  });
});

$('ban-form').addEventListener('submit', (e) => {
  e.preventDefault();
  saveSettings($('ban-form'), {
    ban_enabled: $('set-ban-enabled').checked ? '1' : '0',
    ban_threshold: $('set-ban-threshold').value || '5',
    ban_window_sec: $('set-ban-window').value || '300',
    ban_duration_sec: $('set-ban-duration').value || '3600',
    ban_exempt_own: $('set-ban-exempt-own').checked ? '1' : '0',
    ban_exempt: $('set-ban-exempt').value.trim(),
  });
});

// Shows which addresses "Never ban my own addresses" covers, so it is clear
// whether the router's public address is known.
async function refreshOwnAddresses() {
  const out = $('ban-own-addresses');
  try {
    const own = await api('GET', '/api/own-addresses');
    const router = own.filter((a) => a.source === 'router').map((a) => a.ip);
    const local = own.filter((a) => a.source !== 'router').map((a) => a.ip);
    out.innerHTML = (router.length
      ? `public: ${router.map(esc).join(', ')}`
      : '<span class="hs-muted">public address unknown (needs UPnP); add it under Never ban</span>')
      + (local.length
        ? `<br><span title="${esc(local.join('\n'))}">this machine: ${local.length} address${local.length === 1 ? '' : 'es'}</span>`
        : '');
  } catch (err) { out.textContent = ''; }
}

$('settings-form').addEventListener('submit', (e) => {
  e.preventDefault();
  saveSettings($('settings-form'), {
    acme_email: $('set-acme-email').value.trim(),
    acme_staging: $('set-acme-staging').checked ? '1' : '0',
    acme_ca_url: $('set-acme-ca-url').value.trim(),
    acme_dns_provider: $('set-dns-provider').value,
    acme_dns_config: $('set-dns-config').value.trim(),
  }, $('settings-error'));
});

$('defaultsite-form').addEventListener('submit', (e) => {
  e.preventDefault();
  saveSettings($('defaultsite-form'), {
    default_site: $('set-default-site').value,
    default_site_value: $('set-default-site-value').value,
  });
});

$('notify-form').addEventListener('submit', (e) => {
  e.preventDefault();
  saveSettings($('notify-form'), { notify_url: $('set-notify-url').value.trim() }, $('notify-status'));
});

$('btn-notify-test').addEventListener('click', async () => {
  if (!await saveSettings($('notify-form'), { notify_url: $('set-notify-url').value.trim() }, $('notify-status'))) return;
  try {
    await api('POST', '/api/notify-test');
    flashStatus($('notify-status'), 'Test alert sent, check your notification channel', false);
  } catch (err) {
    flashStatus($('notify-status'), err.message, true);
  }
});

$('restore-file').addEventListener('change', async () => {
  const file = $('restore-file').files[0];
  if (!file) return;
  if (!confirm('Restore this backup? ALL current configuration, users and certificates will be replaced.')) {
    $('restore-file').value = '';
    return;
  }
  const el = $('restore-status');
  el.hidden = false;
  el.textContent = 'Restoring...';
  try {
    const res = await fetch('/api/restore', { method: 'POST', body: file });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.statusText);
    const warn = (data.warnings || []).length ? ` Warnings: ${data.warnings.join('; ')}.` : '';
    el.textContent = `Restored (certificates ${data.certificates || 'replaced'}).${warn} Every admin session was signed out; sign in again with the restored credentials.`;
    // The session that ran the restore was revoked with the others.
    setTimeout(() => window.location.reload(), 4000);
  } catch (err) {
    el.textContent = 'Restore failed: ' + err.message;
  }
  $('restore-file').value = '';
});

boot();

/* ---- VPN: WireGuard sites ---- */
// wgSites is loaded with the hosts and the streams too, for their "reach
// through" pickers.
let wgSites = [];
let editingWGSiteId = null;

async function loadWGSites() {
  wgSites = await api('GET', '/api/wg/sites').catch(() => []);
  return wgSites;
}

// viaOn marks an upstream with the site chosen in the host editor. The choice
// covers the host's pool and locations too: within one host an address is
// reached one way.
function viaOn(u) {
  const via = parseInt($('f-via').value, 10) || 0;
  return via ? { ...u, via } : u;
}

function wgSiteName(id) {
  const s = wgSites.find((x) => x.id === id);
  return s ? s.name : `site ${id}`;
}

// fillViaSelect lists the sites in a "reach through" picker. The row stays
// hidden while there are no sites and nothing is selected, so an install
// that does not use WireGuard never sees it.
function fillViaSelect(selectId, rowId, value) {
  const sel = $(selectId);
  sel.innerHTML = '';
  const local = document.createElement('option');
  local.value = '0';
  local.textContent = 'the local network';
  sel.appendChild(local);
  for (const s of wgSites) {
    const o = document.createElement('option');
    o.value = String(s.id);
    o.textContent = `another network: ${s.name} (${(s.networks || []).join(', ')})${s.enabled ? '' : ', switched off'}`;
    sel.appendChild(o);
  }
  sel.value = String(value || 0);
  if (sel.value !== String(value || 0)) sel.value = '0';
  $(rowId).hidden = wgSites.length === 0 && !value;
}

function fmtBytes(n) {
  if (!n) return '0 B';
  const units = ['B', 'kB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1000 && i < units.length - 1) { n /= 1000; i++; }
  return `${n >= 100 || i === 0 ? Math.round(n) : n.toFixed(1)} ${units[i]}`;
}

function ago(ts) {
  const sec = Math.max(0, Math.round((Date.now() - new Date(ts).getTime()) / 1000));
  if (sec < 90) return `${sec} s ago`;
  if (sec < 5400) return `${Math.round(sec / 60)} min ago`;
  return `${Math.round(sec / 3600)} h ago`;
}

/* ---- VPN page ----
   Built around what a person comes to do: use their own device, let one
   device reach one address at home, let other people log in, reach another
   network. Nothing hides because its prerequisite is missing: a part that is
   not set up says what it is for, what it needs first and where to get that. */
let vpnSettings = {};
let vpnStatus = {};
let vpnStreams = [];
let vpnTwoFactor = false;

// node builds an element: node('span', 'cls', 'text').
function node(tag, cls, text) {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  if (text !== undefined) el.textContent = text;
  return el;
}

// twoLines fills a table cell with a main line and a quieter one under it.
function twoLines(td, main, sub) {
  td.textContent = '';
  if (main instanceof Node) td.append(main); else td.append(node('span', 'cell-main', main));
  if (sub) td.append(node('span', 'cell-sub', sub));
  return td;
}

function dayText(ts) {
  return new Date(ts).toLocaleDateString(undefined, { day: 'numeric', month: 'long', year: 'numeric' });
}

function hadContact(st) {
  return !!(st && st.lastHandshake && !st.lastHandshake.startsWith('0001'));
}

async function refreshVPN() {
  const [settings, status, , streamList, me, hostList] = await Promise.all([
    api('GET', '/api/settings'), api('GET', '/api/wg/status'), loadWGSites(),
    api('GET', '/api/streams').catch(() => []), api('GET', '/api/me').catch(() => ({})), api('GET', '/api/hosts').catch(() => hosts),
  ]);
  vpnSettings = settings;
  vpnStatus = status;
  vpnStreams = streamList || [];
  vpnTwoFactor = !!me.totpEnabled;
  hosts = hostList || [];
  [vpnPolicies, vpnBlocked] = await Promise.all([
    api('GET', '/api/wg/policies').catch(() => []),
    api('GET', '/api/wg/blocked').catch(() => []),
    loadVPNPeople(),
  ]);
  if (!oidcProviders.length) oidcProviders = await api('GET', '/api/oidc-providers').catch(() => []);

  const off = !status.enabled;
  const lan = settings.wg_lan_access === '1';

  // The line at the top: is it on, and where do devices connect to.
  const badge = $('vpn-state-badge');
  badge.className = 'badge ' + (off ? 'badge--muted' : status.running ? 'badge--success' : 'badge--danger');
  badge.textContent = off ? 'Off' : status.running ? 'On' : 'Not running';
  $('vpn-state-line').textContent = off ? '' : (status.endpoint ? `Devices connect to ${status.endpoint}` : 'No address for devices yet: fill it in under VPN settings');
  const problem = $('vpn-problem');
  problem.hidden = off || status.running;
  problem.textContent = `The VPN is switched on but does not run: ${status.error || 'unknown error'}. Devices cannot connect, and hosts and streams that go through another network answer 502 until this is fixed.`;

  // First visit: two fields and one button.
  $('vpn-start').hidden = !off;
  $('vs-endpoint').value = settings.wg_endpoint || '';
  $('vs-port').value = settings.wg_port || '';
  $('vs-network').value = settings.wg_network || '';
  const pinned = wgSites.length > 0 || wgDevices.some((d) => !d.revokedAt);
  $('vs-network').disabled = pinned;

  // The settings fold.
  $('wg-enabled').checked = settings.wg_enabled === '1';
  $('wg-port').value = settings.wg_port || '';
  $('wg-endpoint').value = settings.wg_endpoint || '';
  $('wg-network').value = settings.wg_network || '';
  $('wg-network').disabled = pinned;
  $('wg-pubkey').textContent = status.publicKey || 'made when the VPN is switched on';
  $('wg-status-line').textContent = status.enabled && status.running
    ? `quicgate itself is ${status.address} inside the VPN. A new key would make every setup file useless, so there is no button for it.`
    : (status.keyUnreadable ? 'The stored key cannot be opened: it was sealed with another secret key. Restore that key, or make a new server key and set every device and network up again.' : '');
  $('wg-reset-key').hidden = !status.keyUnreadable;
  $('vlan-enabled').checked = lan;
  $('vlan-protected').value = (settings.wg_protected_endpoints || '').split(/[\s,]+/).filter(Boolean).join('\n');
  $('vlan-waive').checked = settings.wg_no_published_aliases === '1';
  $('vpn-settings-summary').textContent = off
    ? 'Off. Nothing listens.'
    : `${status.running ? 'On' : 'Not running'}. Port ${status.port || settings.wg_port || 51820}${status.endpoint ? `, devices connect to ${status.endpoint}` : ''}. Local network access ${lan ? 'on' : 'off'}.`;

  renderVPNDevices();
  renderVPNPeople();
  renderVPNNetworks();
  renderVPNMap();
}

// peopleRoutes lists what a person's device may reach on the local network:
// the destinations of every rule that names its owner.
function peopleRoutes(d) {
  const s = vpnSessions.find((x) => x.provider === d.provider && x.sub === d.sub);
  const groups = (s && s.groups) || [];
  const out = [];
  for (const p of vpnPolicies) {
    const v = p.subject || {};
    if (v.provider !== d.provider) continue;
    if (v.kind === 'any-user' || (v.kind === 'user' && v.sub === d.sub) || (v.kind === 'group' && groups.includes(v.group))) out.push(...(p.routes || []));
  }
  return out;
}

const isOwnDevice = (d) => d.kind === 'admin' || d.kind === 'breakglass';

function renderVPNDevices() {
  const status = vpnStatus;
  const off = !status.enabled;
  const lan = vpnSettings.wg_lan_access === '1';
  const shown = wgDevices.filter((d) => !d.revokedAt);
  $('btn-add-wgdevice').disabled = !status.running;
  $('btn-add-wgdevice').title = status.running ? '' : 'Switch on the VPN first';
  $('vpn-devices-card').classList.toggle('is-waiting', off);

  const live = {};
  for (const st of status.devices || []) live[st.id] = st;
  const body = $('wgdevices-body');
  body.textContent = '';
  const empty = $('wgdevices-empty');
  empty.hidden = shown.length > 0;
  empty.textContent = '';
  empty.append(node('b', '', 'No devices yet. '), 'A device gets a setup file for the WireGuard app and then reaches your private hosts, and the local addresses you name for it. '
    + (off ? 'Needs the VPN switched on, at the top of this page.' : 'Start with "Add a device".'));
  $('wgdevices-table').hidden = shown.length === 0;

  for (const d of shown) {
    const st = live[d.id];
    const own = isOwnDevice(d);
    const tr = document.createElement('tr');
    const cell = () => tr.appendChild(document.createElement('td'));

    const tdName = twoLines(cell(), d.name);
    tdName.title = `Address inside the VPN: ${d.address}`;

    const tdBy = cell();
    if (own) tdBy.textContent = 'You';
    else { tdBy.textContent = d.email || d.sub; tdBy.title = `Logged in with ${providerName(d.provider)}`; }

    // What it may reach: private hosts always, local addresses when named.
    const tdReach = cell();
    const reach = node('div', 'reach');
    reach.append(node('span', 'reach__item', 'Private hosts'));
    const routes = own ? (d.routes || []) : peopleRoutes(d);
    for (const r of routes) reach.append(destChip(r));
    tdReach.append(reach);
    const expired = d.expiresAt && new Date(d.expiresAt) < new Date();
    const notes = [];
    if (routes.length && !lan) notes.push('Local network access is switched off: only private hosts work now.');
    if (own && routes.length) notes.push(d.expiresAt ? `${expired ? 'Stopped working on' : 'Stops working on'} ${dayText(d.expiresAt)}.` : 'No end date, and no login behind it.');
    if (notes.length) tdReach.append(node('span', 'cell-sub', notes.join(' ')));

    const tdSeen = cell();
    const traffic = st ? `${fmtBytes(st.rxBytes)} in, ${fmtBytes(st.txBytes)} out${st.connections ? ', ' + st.connections + ' open' : ''}` : '';
    if (!d.enabled) twoLines(tdSeen, node('span', 'cell-main cell-main--muted', 'Paused'), 'switched off under "Allowed"');
    else if (!status.running) twoLines(tdSeen, node('span', 'cell-main cell-main--muted', 'VPN not running'));
    else if (!st) twoLines(tdSeen, node('span', 'cell-main cell-main--muted', 'No access'), own ? 'its end date has passed' : 'the login ran out or was ended: logging in again brings it back');
    else if (st.up) twoLines(tdSeen, 'Connected', `${ago(st.lastHandshake)}${st.endpoint ? ', from ' + st.endpoint : ''}`);
    else if (hadContact(st)) twoLines(tdSeen, node('span', 'cell-main cell-main--muted', 'Not connected'), `last seen ${ago(st.lastHandshake)}`);
    else twoLines(tdSeen, node('span', 'cell-main cell-main--muted', 'Never connected'), d.createdAt ? `added ${dayText(d.createdAt)}` : '');
    tdSeen.title = traffic;

    const tdOn = cell();
    const sw = document.createElement('input');
    sw.type = 'checkbox';
    sw.checked = d.enabled;
    sw.title = d.enabled ? 'Pause this device' : 'Let this device connect again';
    sw.setAttribute('aria-label', `${d.name} is allowed to connect`);
    sw.addEventListener('change', async () => {
      try { await api('PUT', `/api/wg/devices/${d.id}/enabled`, { enabled: sw.checked }); } catch (err) { alert(err.message); }
      refreshVPN();
    });
    const wrap = node('span', 'switch switch--sm');
    wrap.append(sw, node('span', 'switch__slot'), node('span', 'switch__knob'));
    tdOn.append(wrap);

    const tdAct = cell();
    tdAct.className = 'actions';
    const acts = node('span', 'rowactions');
    if (own) {
      const change = node('button', 'linkbtn', 'Change access');
      change.type = 'button';
      change.addEventListener('click', () => openWGDeviceModal({ device: d }));
      acts.append(change);
    }
    const del = node('button', 'btn btn--ghost btn--sm btn--danger-hover', 'Remove');
    del.type = 'button';
    del.addEventListener('click', async () => {
      if (!confirm(`Remove ${d.name}? Its setup file stops working at once and can never be used again.`)) return;
      try { await api('DELETE', `/api/wg/devices/${d.id}`); refreshVPN(); } catch (err) { alert(err.message); }
    });
    acts.append(del);
    tdAct.append(acts);
    body.appendChild(tr);
  }
}

function renderVPNPeople() {
  const off = !vpnStatus.enabled;
  const lan = vpnSettings.wg_lan_access === '1';
  const settings = vpnSettings;
  const portals = hosts.filter((h) => h.type === 'vpn-portal');
  const portal = portals[0];
  const portalURL = portal ? `https://${portal.domains[0]}` : '';
  const haveProvider = oidcProviders.length > 0;
  $('vpn-people-card').classList.toggle('is-waiting', off);

  const hint = $('vpn-people-hint');
  hint.textContent = portal
    ? `at ${portalURL}${portal.options && portal.options.portal ? ' with ' + providerName(portal.options.portal.providerId) : ''}`
    : 'family or colleagues add their own devices';
  $('vpn-people-intro').hidden = vpnSessions.length > 0;

  const addRule = $('btn-add-vpnpolicy');
  addRule.disabled = off || !haveProvider;
  addRule.title = off ? 'Switch on the VPN first' : (haveProvider ? '' : 'A rule is about people from a login provider: add one first');

  // The three steps, shown until people can log in.
  const step = (id, done, desc, where, enabled) => {
    const li = $(id);
    li.classList.toggle('is-done', done);
    li.classList.toggle('is-waiting', !done && !enabled);
    li.classList.toggle('is-next', !done && enabled);
    li.querySelector('.goal__mark').textContent = done ? '✓' : li.dataset.n || (li.dataset.n = li.querySelector('.goal__mark').textContent);
    li.querySelector('.needs__d').textContent = desc;
    li.querySelector('.goal__where').textContent = done ? '' : where;
    const btn = li.querySelector('button');
    btn.hidden = done;
    btn.disabled = !enabled;
  };
  $('vpn-people-steps').hidden = !!portal;
  step('vp-step-provider', haveProvider,
    haveProvider ? `${oidcProviders.map((p) => p.name).join(', ')}.` : 'None yet. This is the service people sign in with, such as Keycloak or Authentik. On the Access control page it is called an identity provider.',
    'on Access control', true);
  step('vp-step-portal', false,
    'A proxy host of the type "VPN portal", for example vpn.example.com. People go there to sign in and get their setup file. It has to be reachable without the VPN.',
    off ? 'needs the VPN switched on' : (haveProvider ? 'on Proxy hosts' : 'needs step 1'), haveProvider && !off);
  // A rule only needs a login provider, so it can be made before the login
  // page exists; it is optional, and done once there is one.
  step('vp-step-rules', vpnPolicies.length > 0,
    vpnPolicies.length
      ? `${vpnPolicies.length === 1 ? 'One rule' : vpnPolicies.length + ' rules'}, listed below.`
      : 'Private hosts straight away. For addresses on your local network, add a rule for a group or for one person.',
    off ? 'needs the VPN switched on' : (haveProvider ? 'optional' : 'needs step 1'), haveProvider && !off);

  // Rules: who may reach what on the local network.
  const pbody = $('vpnpolicies-body');
  pbody.textContent = '';
  $('vpnpolicies-table').hidden = vpnPolicies.length === 0;
  const pnote = $('vpnpolicies-empty');
  pnote.textContent = '';
  if (vpnPolicies.length && !lan) {
    pnote.hidden = false;
    pnote.append(node('b', '', 'These rules do nothing yet. '), 'Local network access is switched off: switch it on under VPN settings.');
  } else if (!vpnPolicies.length && portal) {
    pnote.hidden = false;
    pnote.append(node('b', '', 'No rules yet. '), 'People who log in reach your private hosts only. Add a rule to let a group or a person reach addresses on your local network.');
  } else pnote.hidden = true;
  for (const p of vpnPolicies) {
    const tr = document.createElement('tr');
    const cell = () => tr.appendChild(document.createElement('td'));
    twoLines(cell(), describeSubject(p.subject), `rule "${p.name}"`);
    const reach = node('div', 'reach');
    for (const r of p.routes || []) reach.append(destChip(r));
    cell().append(reach);
    const tdAct = cell();
    tdAct.className = 'actions';
    const acts = node('span', 'rowactions');
    const edit = node('button', 'linkbtn', 'Change');
    edit.type = 'button';
    edit.addEventListener('click', () => openPolicyModal(p));
    const del = node('button', 'btn btn--ghost btn--sm btn--danger-hover', 'Remove');
    del.type = 'button';
    del.addEventListener('click', async () => {
      if (!confirm(`Remove the rule "${p.name}"? Open connections that only this rule allowed are closed.`)) return;
      try { await api('DELETE', `/api/wg/policies/${p.id}`); refreshVPN(); } catch (err) { alert(err.message); }
    });
    acts.append(edit, del);
    tdAct.append(acts);
    pbody.appendChild(tr);
  }

  // People and the state of their login.
  const sbody = $('vpnsessions-body');
  sbody.textContent = '';
  $('vpnsessions-table').hidden = vpnSessions.length === 0;
  const snote = $('vpnsessions-empty');
  snote.hidden = !portal || vpnSessions.length > 0;
  snote.textContent = '';
  if (portal) snote.append(node('b', '', 'Nobody has logged in yet. '), `People go to ${portalURL}/, sign in and add their own devices there.`);
  const isBlocked = (s) => vpnBlocked.some((b) => b.provider === s.provider && b.sub === s.sub);
  for (const s of vpnSessions) {
    const tr = document.createElement('tr');
    const cell = () => tr.appendChild(document.createElement('td'));
    twoLines(cell(), s.email || s.sub, (s.groups || []).join(', ')).title = `Logged in with ${providerName(s.provider)}`;
    const theirs = wgDevices.filter((d) => d.kind === 'sso' && !d.revokedAt && d.provider === s.provider && d.sub === s.sub);
    const tdDev = cell();
    tdDev.textContent = theirs.map((d) => d.name).join(', ') || 'none yet';
    if (!theirs.length) tdDev.className = 'hs-muted';
    const until = new Date(s.transient && new Date(s.graceUntil) > new Date(s.leaseUntil) ? s.graceUntil : s.leaseUntil);
    const hard = new Date(s.hardUntil);
    const liveNow = s.state === 'active' && until > new Date() && hard > new Date();
    let state = ['badge--muted', s.state === 'ended' ? 'Ended' : 'Ran out', 'has to log in again'];
    if (isBlocked(s)) state = ['badge--danger', 'Blocked', 'stays off until you lift the block'];
    else if (liveNow && s.transient) state = ['badge--danger', 'Provider unreachable', `keeps working until ${until.toLocaleTimeString()}`];
    else if (liveNow) state = ['badge--success', 'Good', `checked ${ago(s.renewedAt)}`];
    twoLines(cell(), node('span', `badge ${state[0]}`, state[1]), state[2]);
    const tdAgain = cell();
    tdAgain.textContent = liveNow ? dayText(s.hardUntil) : '';
    const tdAct = cell();
    tdAct.className = 'actions';
    const acts = node('span', 'rowactions');
    if (liveNow) {
      const end = node('button', 'linkbtn', 'End login');
      end.type = 'button';
      end.title = 'Their devices stop until they log in again';
      end.addEventListener('click', async () => {
        if (!confirm(`End the login of ${s.email}? Their devices stop until they log in again.`)) return;
        try { await api('POST', `/api/wg/sessions/${s.id}/end`); refreshVPN(); } catch (err) { alert(err.message); }
      });
      acts.append(end);
    }
    if (!isBlocked(s)) {
      const block = node('button', 'btn btn--ghost btn--sm btn--danger-hover', 'Block');
      block.type = 'button';
      block.title = 'Their devices stay off whatever the login provider says';
      block.addEventListener('click', async () => {
        if (!confirm(`Block ${s.email} from the VPN? Their devices stop now and stay off, whatever the login provider says, until you lift the block.`)) return;
        try { await api('POST', '/api/wg/owners/block', { provider: s.provider, sub: s.sub, email: s.email }); refreshVPN(); } catch (err) { alert(err.message); }
      });
      acts.append(block);
    }
    tdAct.append(acts);
    sbody.appendChild(tr);
  }
  const blockedBox = $('vpnblocked');
  blockedBox.hidden = vpnBlocked.length === 0;
  blockedBox.textContent = '';
  if (vpnBlocked.length) {
    blockedBox.append('Blocked: ');
    vpnBlocked.forEach((b, i) => {
      if (i) blockedBox.append(', ');
      blockedBox.append(`${b.email || b.sub} `);
      const un = node('button', 'linkbtn', 'lift the block');
      un.type = 'button';
      un.addEventListener('click', async () => {
        try { await api('POST', '/api/wg/owners/unblock', { provider: b.provider, sub: b.sub }); refreshVPN(); } catch (err) { alert(err.message); }
      });
      blockedBox.append(un);
    });
  }

  $('vl-lease').value = settings.wg_lease_minutes || '';
  $('vl-grace').value = settings.wg_outage_grace_minutes || '';
  $('vl-days').value = settings.wg_session_days || '';
  $('vl-maxage').value = settings.wg_auth_max_age || '';
  $('vl-devices').value = settings.wg_devices_per_user || '';
  $('vpn-lease-summary').textContent = `checked every ${settings.wg_lease_minutes || 10} minutes, log in again after ${settings.wg_session_days || 30} days, ${settings.wg_devices_per_user || 5} devices per person`;
}

// networkUsers lists the hosts and streams that send traffic through one of
// the other networks.
function networkUsers(id) {
  const out = [];
  for (const h of hosts) {
    const through = [h.upstream, ...(h.upstreams || []), ...(h.locations || []).map((l) => l.upstream)].some((u) => u && u.via === id);
    if (through) out.push(h.domains && h.domains[0] ? h.domains[0] : `host ${h.id}`);
  }
  for (const s of vpnStreams) if (s.via === id) out.push(`stream on port ${s.listenPort || s.port || '?'}`);
  return out;
}

function renderVPNNetworks() {
  const status = vpnStatus;
  const off = !status.enabled;
  $('btn-add-wgsite').disabled = !status.running;
  $('btn-add-wgsite').title = status.running ? '' : 'Switch on the VPN first';
  $('vpn-sites-card').classList.toggle('is-waiting', off);
  const live = {};
  for (const st of status.sites || []) live[st.id] = st;
  const body = $('wgsites-body');
  body.textContent = '';
  const empty = $('wgsites-empty');
  empty.hidden = wgSites.length > 0;
  empty.textContent = '';
  empty.append(node('b', '', 'No other network connected. '), 'For a service at the office or on a rented server that a proxy host or a stream here should use. Not needed for your own phone or laptop. '
    + (off ? 'Needs the VPN switched on, at the top of this page.' : ''));
  $('wgsites-table').hidden = wgSites.length === 0;
  for (const s of wgSites) {
    const st = live[s.id];
    const tr = document.createElement('tr');
    const cell = () => tr.appendChild(document.createElement('td'));
    twoLines(cell(), s.name).title = `Address inside the VPN: ${s.address}`;
    const tdNet = cell();
    tdNet.className = 'mono';
    tdNet.textContent = (s.networks || []).join(', ');
    const how = s.endpoint ? `quicgate calls it at ${s.endpoint}` : 'it calls in';
    const tdState = cell();
    if (!s.enabled) twoLines(tdState, node('span', 'badge badge--muted', 'Switched off'), 'hosts and streams that go through it answer 502');
    else if (!status.running) twoLines(tdState, node('span', 'badge badge--danger', 'VPN not running'));
    else if (st && st.up) twoLines(tdState, node('span', 'badge badge--success', 'Connected'), `${ago(st.lastHandshake)}, ${how}`);
    else if (hadContact(st)) twoLines(tdState, node('span', 'badge badge--danger', 'Lost'), `last seen ${ago(st.lastHandshake)}, ${how}`);
    else twoLines(tdState, node('span', 'badge badge--muted', 'Waiting'), s.endpoint
      ? `No contact yet. quicgate calls it at ${s.endpoint} with the first request that needs it.`
      : 'It has not connected yet. Put its setup file on the router or the machine there.');
    // A problem of this network alone (a name that does not resolve) does
    // not stop it from calling in, so it is said next to the state.
    if (st && st.warning) tdState.append(node('span', 'cell-sub cell-sub--bad', st.warning));
    if (st) tdState.title = `${fmtBytes(st.rxBytes)} in, ${fmtBytes(st.txBytes)} out${st.connections ? ', ' + st.connections + ' open' : ''}`;
    const users = networkUsers(s.id);
    const tdUsed = cell();
    if (users.length) twoLines(tdUsed, users.slice(0, 3).join(', ') + (users.length > 3 ? ` and ${users.length - 3} more` : ''));
    else twoLines(tdUsed, node('span', 'cell-main cell-main--muted', 'Nothing yet'), `On a host or a stream, pick "Reach through: ${s.name}".`);
    const tdAct = cell();
    tdAct.className = 'actions';
    const acts = node('span', 'rowactions');
    const edit = node('button', 'linkbtn', 'Change');
    edit.type = 'button';
    edit.addEventListener('click', () => openWGSiteModal(s));
    const del = node('button', 'btn btn--ghost btn--sm btn--danger-hover', 'Remove');
    del.type = 'button';
    del.addEventListener('click', async () => {
      if (!confirm(`Remove ${s.name}? Its setup file stops working at once, and hosts and streams that go through it answer 502.`)) return;
      try { await api('DELETE', `/api/wg/sites/${s.id}`); refreshVPN(); } catch (err) { alert(err.message); }
    });
    acts.append(edit, del);
    tdAct.append(acts);
    body.appendChild(tr);
  }
}

// The map: per thing a person comes to do, where it stands and the one next
// step. state is done, next (something concrete is waiting), idle (not
// started, and nothing is wrong with that) or waiting (needs the VPN first).
function setGoal(id, state, text, label, action, where) {
  const el = $(id);
  for (const s of ['done', 'next', 'waiting']) el.classList.toggle(`is-${s}`, s === state);
  const mark = el.querySelector('.goal__mark');
  if (!el.dataset.n) el.dataset.n = mark.textContent;
  mark.textContent = state === 'done' ? '✓' : el.dataset.n;
  el.querySelector('.goal__state').textContent = text;
  el.querySelector('.goal__where').textContent = where || '';
  const btn = el.querySelector('button');
  btn.textContent = label;
  btn.disabled = !action;
  btn.onclick = action || null;
  // One button on the map stands out: the first step that is waiting.
  let first = true;
  for (const g of $('vpnmap').querySelectorAll('.goal')) {
    const lead = first && g.classList.contains('is-next');
    if (lead) first = false;
    g.querySelector('button').className = 'btn btn--sm ' + (lead ? 'btn--primary' : 'btn--secondary');
  }
}

function openVPNFold(id) {
  const fold = $(id);
  fold.open = true;
  fold.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function switchLocalAccessOn() {
  if (!confirm('Switch local network access on? Devices can then reach the local addresses you named for them, and nothing else. The VPN restarts, which drops open VPN connections for a moment.')) return false;
  try {
    await api('PUT', '/api/settings', { wg_lan_access: '1' });
  } catch (err) {
    alert(`${err.message}\n\nYou can set this under VPN settings, at the bottom of the VPN page.`);
    return false;
  }
  await refreshVPN();
  return true;
}

async function addPortalHost() {
  if (!oidcProviders.length) {
    alert('A login page signs people in through a login provider. Add one first: Access control page, Identity providers.');
    switchPage('access');
    return;
  }
  switchPage('hosts');
  await refresh();
  openModal(null);
  $('f-type').value = 'vpn-portal';
  syncHostType();
}

function renderVPNMap() {
  const status = vpnStatus;
  const lan = vpnSettings.wg_lan_access === '1';
  const devices = wgDevices.filter((d) => !d.revokedAt);
  const live = {};
  for (const st of status.sites || []) live[st.id] = st;

  if (!status.enabled) {
    setGoal('vg-own', 'waiting', 'Switch on the VPN first. Then: add a device, and mark a host "VPN only".', 'Add a device');
    setGoal('vg-local', 'waiting', 'Switch on the VPN first. Then: add a device and name the address it may reach.', 'Give a device access');
    setGoal('vg-people', 'waiting', 'Switch on the VPN first. It also needs a login provider, such as Keycloak.', 'Add a login provider');
    setGoal('vg-networks', 'waiting', 'Switch on the VPN first. Then: connect the other network.', 'Connect a network');
    return;
  }
  const canAdd = status.running;

  // 1. My own phone or laptop.
  const privateHosts = hosts.filter((h) => h.options && h.options.vpnOnly).length;
  if (!devices.length) setGoal('vg-own', 'next', 'No device yet. A device gets a setup file for the WireGuard app.', 'Add a device', canAdd && (() => openWGDeviceModal({})));
  else if (!privateHosts) setGoal('vg-own', 'next', `${plural(devices.length, 'device', 'devices')} added. No host is private yet, so they have nothing to open: tick "VPN only" on a proxy host.`, 'Make a host private', () => switchPage('hosts'), 'on Proxy hosts');
  else setGoal('vg-own', 'done', `${plural(devices.length, 'device', 'devices')}, ${plural(privateHosts, 'private host', 'private hosts')}.`, 'Add a device', canAdd && (() => openWGDeviceModal({})));

  // 2. One device, one address at home.
  const withLocal = devices.filter((d) => isOwnDevice(d) && (d.routes || []).length);
  if (!withLocal.length) {
    setGoal('vg-local', 'idle', `No device of yours may reach your local network yet${lan ? '' : ', and local network access is switched off'}.`, 'Give a device access', canAdd && (() => openWGDeviceModal({ local: true })));
  } else if (!lan) {
    setGoal('vg-local', 'next', `${withLocal.map((d) => d.name).join(', ')} ${withLocal.length === 1 ? 'has' : 'have'} local addresses, but local network access is switched off.`, 'Switch it on', () => switchLocalAccessOn());
  } else {
    const first = withLocal[0];
    const r = first.routes[0];
    const more = withLocal.length - 1;
    setGoal('vg-local', 'done', `${first.name} may reach ${r.name || destAddress(r)}${first.routes.length > 1 ? ' and more' : ''}${more ? `, and ${plural(more, 'other device has', 'other devices have')} local addresses too` : ''}.`, 'Give a device access', canAdd && (() => openWGDeviceModal({ local: true })));
  }

  // 3. Other people log in.
  const portal = hosts.find((h) => h.type === 'vpn-portal');
  if (!oidcProviders.length) setGoal('vg-people', 'idle', 'Needs a login provider first, such as Keycloak or Authentik.', 'Add a login provider', () => switchPage('access'), 'on Access control');
  else if (!portal) setGoal('vg-people', 'next', 'Needs a login page: a proxy host of the type "VPN portal".', 'Add the login page', () => addPortalHost(), 'on Proxy hosts');
  else if (!vpnSessions.length) {
    const url = `https://${portal.domains[0]}/`;
    setGoal('vg-people', 'next', `Nobody has logged in yet. Send people to ${url}`, 'Copy the address', async (e) => {
      try { await navigator.clipboard.writeText(url); e.currentTarget.textContent = 'Copied'; } catch (err) { prompt('The address of the login page', url); }
    });
  } else setGoal('vg-people', 'done', `${plural(vpnSessions.length, 'person has', 'people have')} logged in at ${portal.domains[0]}. ${plural(vpnPolicies.length, 'rule', 'rules')} for the local network.`, 'Add a rule', () => openPolicyModal(null));

  // 4. Another network.
  if (!wgSites.length) setGoal('vg-networks', 'idle', 'No other network connected. Only needed when a service lives somewhere else.', 'Connect a network', canAdd && (() => openWGSiteModal(null)));
  else {
    const never = wgSites.find((s) => s.enabled && !(live[s.id] && (live[s.id].up || hadContact(live[s.id]))));
    const unused = wgSites.find((s) => !networkUsers(s.id).length);
    if (never) setGoal('vg-networks', 'next', `${never.name} is added but has not connected yet.`, 'How to connect it', () => openVPNFold('vpn-sites-info'));
    else if (unused) setGoal('vg-networks', 'next', `${unused.name} is connected, but no host or stream uses it yet. Pick it under "Reach through".`, 'Pick it on a host', () => switchPage('hosts'), 'on Proxy hosts');
    else setGoal('vg-networks', 'done', `${plural(wgSites.length, 'network', 'networks')} connected and in use.`, 'Connect a network', canAdd && (() => openWGSiteModal(null)));
  }
}

$('vpn-open-settings').addEventListener('click', () => openVPNFold('vpn-settings'));
$('vm-guide').addEventListener('click', async (e) => { e.preventDefault(); switchPage('help'); await openGuide('vpn'); });
$('vp-step-provider').querySelector('button').addEventListener('click', () => switchPage('access'));
$('vp-step-portal').querySelector('button').addEventListener('click', () => addPortalHost());
$('vp-step-rules').querySelector('button').addEventListener('click', () => openPolicyModal(null));

// withPort adds the port to an address that was typed without one.
function withPort(address, port) {
  address = address.trim();
  if (!address || /:\d+$/.test(address)) return address;
  return `${address}:${port || 51820}`;
}

$('vpn-start').addEventListener('submit', async (e) => {
  e.preventDefault();
  const port = $('vs-port').value || '';
  const ok = await saveSettings($('vpn-start'), {
    wg_enabled: '1',
    wg_port: port,
    wg_endpoint: withPort($('vs-endpoint').value, port),
    ...($('vs-network').disabled || !$('vs-network').value.trim() ? {} : { wg_network: $('vs-network').value.trim() }),
  });
  if (ok) refreshVPN();
});

$('wg-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const on = $('wg-enabled').checked;
  const lanOn = $('vlan-enabled').checked;
  if (!on && vpnSettings.wg_enabled === '1' && !confirm('Switch the VPN off? Every device and every other network stops at once.')) return;
  if (lanOn && vpnSettings.wg_lan_access !== '1' && !confirm('Switch local network access on? Devices can then reach the local addresses you named for them, and nothing else. The VPN restarts, which drops open VPN connections for a moment.')) return;
  const port = $('wg-port').value || '';
  await saveSettings($('wg-form'), {
    wg_enabled: on ? '1' : '0',
    wg_port: port,
    wg_endpoint: withPort($('wg-endpoint').value, port),
    ...($('wg-network').disabled || !$('wg-network').value.trim() ? {} : { wg_network: $('wg-network').value.trim() }),
    wg_lan_access: lanOn ? '1' : '0',
    wg_protected_endpoints: $('vlan-protected').value.split(/[\s,]+/).filter(Boolean).join(', '),
    wg_no_published_aliases: $('vlan-waive').checked ? '1' : '0',
  });
  refreshVPN();
});

$('vlan-check').addEventListener('click', async () => {
  const out = $('vlan-check-answer');
  let dest = $('vlan-check-dest').value.trim();
  if (dest && !dest.includes(':')) dest += ':443';
  const ip = dest.split(':')[0];
  try {
    const r = await api('POST', '/api/wg/explain', { routes: [{ cidr: `${ip}/32`, proto: 'any' }], proto: 'tcp', dest });
    const refused = r.answer.startsWith('refused');
    out.textContent = r.answer.startsWith('refused')
      ? `Nobody can reach ${dest}, whatever they are given: ${r.answer.replace(/^refused:\s*/, '')}.`
      : `A device that was given ${ip} could reach ${dest}. Nothing protects it.`;
  } catch (err) {
    out.textContent = err.message;
  }
});

$('vpn-lease-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  await saveSettings($('vpn-lease-form'), {
    wg_lease_minutes: $('vl-lease').value, wg_outage_grace_minutes: $('vl-grace').value, wg_session_days: $('vl-days').value,
    wg_auth_max_age: $('vl-maxage').value, wg_devices_per_user: $('vl-devices').value,
  });
  refreshVPN();
});

// canMakeKeys reports whether this page can generate an X25519 keypair: that
// takes a secure context (HTTPS or localhost) and a recent browser.
async function canMakeKeys() {
  try {
    if (!window.isSecureContext || !crypto.subtle) return false;
    await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    return true;
  } catch (err) { return false; }
}

const b64 = (bytes) => btoa(String.fromCharCode(...bytes));

// makeWGKeypair returns base64 keys as WireGuard writes them. The private key
// is the last 32 bytes of the PKCS#8 export; WireGuard clamps it on use.
async function makeWGKeypair() {
  const kp = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const pub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
  return { privateKey: b64(pkcs8.slice(-32)), publicKey: b64(pub) };
}

function syncWGKeyMode() {
  $('w-pubkey-field').hidden = !$('w-key-paste').checked;
}
$('w-key-generate').addEventListener('change', syncWGKeyMode);
$('w-key-paste').addEventListener('change', syncWGKeyMode);

async function openWGSiteModal(s) {
  editingWGSiteId = s ? s.id : null;
  $('wgsite-modal-title').textContent = s ? `Change ${s.name}` : 'Connect a network';
  setError('wgsite-error', null);
  $('wgsite-form').hidden = false;
  $('wgsite-created').hidden = true;
  $('w-name').value = s ? s.name : '';
  $('w-networks').value = s ? (s.networks || []).join('\n') : '';
  $('w-endpoint').value = s ? s.endpoint : '';
  $('w-keepalive').value = s ? s.keepalive : 25;
  $('w-enabled').checked = s ? s.enabled : true;
  $('w-overlap').checked = !!(s && s.allowOwnOverlap);
  $('w-overlap-row').hidden = !(s && s.allowOwnOverlap);
  // An existing site keeps its key: a new key is a new site.
  $('w-key-block').hidden = !!s;
  $('w-pubkey').value = '';
  const can = s ? false : await canMakeKeys();
  $('w-key-generate').disabled = !can;
  $('w-key-unsupported').hidden = !!s || can;
  $('w-key-generate').checked = can;
  $('w-key-paste').checked = !can;
  syncWGKeyMode();
  $('wgsite-modal').hidden = false;
}

function closeWGSiteModal() {
  // The configuration holds keys: it does not stay in the page.
  $('w-config').value = '';
  $('wgsite-modal').hidden = true;
  refreshVPN();
}
$('btn-add-wgsite').addEventListener('click', () => openWGSiteModal(null));
$('wgsite-modal-close').addEventListener('click', closeWGSiteModal);
$('wgsite-btn-cancel').addEventListener('click', closeWGSiteModal);
$('wgsite-btn-done').addEventListener('click', closeWGSiteModal);
$('wgsite-btn-copy').addEventListener('click', async () => {
  const ta = $('w-config');
  try { await navigator.clipboard.writeText(ta.value); } catch (err) { ta.select(); document.execCommand('copy'); }
  $('wgsite-btn-copy').textContent = 'Copied';
  setTimeout(() => { $('wgsite-btn-copy').textContent = 'Copy'; }, 1500);
});

$('wgsite-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  setError('wgsite-error', null);
  const site = {
    name: $('w-name').value.trim(),
    networks: $('w-networks').value.split('\n').map((v) => v.trim()).filter(Boolean),
    endpoint: $('w-endpoint').value.trim(),
    keepalive: parseInt($('w-keepalive').value, 10) || 0,
    enabled: $('w-enabled').checked,
    allowOwnOverlap: $('w-overlap').checked,
  };
  try {
    if (editingWGSiteId) {
      const cur = wgSites.find((x) => x.id === editingWGSiteId);
      site.publicKey = cur.publicKey;
      await api('PUT', `/api/wg/sites/${editingWGSiteId}`, site);
      closeWGSiteModal();
      return;
    }
    let privateKey = '';
    if ($('w-key-generate').checked) {
      const kp = await makeWGKeypair();
      privateKey = kp.privateKey;
      site.publicKey = kp.publicKey;
    } else {
      site.publicKey = $('w-pubkey').value.trim();
    }
    const [created, status] = [await api('POST', '/api/wg/sites', site), await api('GET', '/api/wg/status')];
    const listen = created.endpoint ? created.endpoint.split(':').pop() : '';
    $('w-config').value = [
      '[Interface]',
      `PrivateKey = ${privateKey || '(the private key that belongs to the public key you pasted)'}`,
      `Address = ${created.address}/32`,
      ...(listen ? [`ListenPort = ${listen}`] : []),
      '',
      '[Peer]',
      `# quicgate`,
      `PublicKey = ${status.publicKey}`,
      `PresharedKey = ${created.presharedKey}`,
      ...(status.endpoint ? [`Endpoint = ${status.endpoint}`] : ['# Endpoint = (fill in "Address devices connect to" under VPN settings, or let quicgate call this network)']),
      `AllowedIPs = ${status.address}/32`,
      ...(created.keepalive ? [`PersistentKeepalive = ${created.keepalive}`] : []),
      '',
    ].join('\n');
    $('w-tunnel-addr').textContent = status.address;
    $('wgsite-form').hidden = true;
    $('wgsite-created').hidden = false;
  } catch (err) {
    // The server names an overlap with this machine's own networks; offer the
    // confirmation only then.
    if (/a network this machine is on/.test(err.message)) $('w-overlap-row').hidden = false;
    setError('wgsite-error', err);
  }
});

/* ---- VPN: devices, people, LAN access ---- */
let wgDevices = [];
let vpnPolicies = [];
let vpnSessions = [];
let vpnBlocked = [];
let editingPolicyId = null;

// loadVPNPeople fetches what the subject pickers offer: the devices, and the
// people who have logged in at a portal.
async function loadVPNPeople() {
  [wgDevices, vpnSessions] = await Promise.all([
    api('GET', '/api/wg/devices').catch(() => []),
    api('GET', '/api/wg/sessions').catch(() => []),
  ]);
}

function providerName(id) {
  const p = oidcProviders.find((x) => x.id === id);
  return p ? p.name : `provider ${id}`;
}

// knownPeople lists everybody quicgate has seen at a portal: a person is
// picked from it, never typed as an id.
function knownPeople(provider) {
  const seen = new Map();
  for (const s of vpnSessions) if (s.provider === provider) seen.set(s.sub, s.email || s.sub);
  for (const d of wgDevices) if (d.kind === 'sso' && d.provider === provider && !seen.has(d.sub)) seen.set(d.sub, d.email || d.sub);
  return [...seen].map(([sub, email]) => ({ sub, email })).sort((a, b) => a.email.localeCompare(b.email));
}

function knownGroups(provider) {
  const out = new Set();
  for (const s of vpnSessions) if (s.provider === provider) for (const g of s.groups || []) out.add(g);
  return [...out].sort();
}

function describeSubject(v) {
  if (!v) return '';
  switch (v.kind) {
    case 'any': return 'anyone on the VPN';
    case 'site': return 'any site';
    case 'device': return 'any device';
    case 'peer': {
      const [kind, id] = String(v.peer || '').split(':');
      if (kind === 'site') return `site ${wgSiteName(parseInt(id, 10))}`;
      const d = wgDevices.find((x) => x.id === parseInt(id, 10));
      return d ? `device ${d.name}` : `device ${id}`;
    }
    case 'group': return `group ${v.group} (${providerName(v.provider)})`;
    case 'user': {
      const p = knownPeople(v.provider).find((x) => x.sub === v.sub);
      return `${p ? p.email : v.sub} (${providerName(v.provider)})`;
    }
    case 'any-user': return `everybody from ${providerName(v.provider)}`;
    default: return v.kind;
  }
}

// makeSubjectPicker fills box with the controls that choose who a rule, a
// policy or an enrolment is about, and returns a function that reads them.
// identityOnly leaves out the kinds that do not name a person.
function makeSubjectPicker(box, current, identityOnly, fixedProvider) {
  box.textContent = '';
  const kinds = [
    ...(identityOnly ? [] : [['any', 'anyone on the VPN'], ['site', 'any site'], ['device', 'any device'], ['peer', 'one site or device']]),
    ['group', 'a group'], ['user', 'one person'], ['any-user', 'everybody from'],
  ];
  const kind = document.createElement('select');
  kind.className = 'subj-kind';
  for (const [v, label] of kinds) kind.add(new Option(label, v));
  const prov = document.createElement('select');
  prov.className = 'subj-provider';
  for (const p of oidcProviders) prov.add(new Option(p.name, String(p.id)));
  const slot = document.createElement('span');
  slot.className = 'r-value-slot';
  box.append(kind, prov, slot);

  let control = null;
  const providerID = () => fixedProvider ? fixedProvider() : (parseInt(prov.value, 10) || 0);
  const build = (cur) => {
    slot.textContent = '';
    control = null;
    const identity = ['group', 'user', 'any-user'].includes(kind.value);
    prov.hidden = !identity || !!fixedProvider;
    if (kind.value === 'peer') {
      control = document.createElement('select');
      control.className = 'r-value';
      for (const s of wgSites) control.add(new Option(`site ${s.name}`, `site:${s.id}`));
      for (const d of wgDevices.filter((x) => !x.revokedAt)) control.add(new Option(`device ${d.name}${d.email ? ' of ' + d.email : ''}`, `device:${d.id}`));
      if (!control.options.length) control.add(new Option('no sites or devices yet', ''));
      if (cur && cur.peer) control.value = cur.peer;
    } else if (kind.value === 'user') {
      control = document.createElement('select');
      control.className = 'r-value';
      const people = knownPeople(providerID());
      for (const p of people) control.add(new Option(p.email, p.sub));
      if (cur && cur.sub && !people.some((p) => p.sub === cur.sub)) control.add(new Option(cur.sub, cur.sub));
      if (!control.options.length) control.add(new Option('nobody has logged in yet', ''));
      if (cur && cur.sub) control.value = cur.sub;
    } else if (kind.value === 'group') {
      control = document.createElement('input');
      control.className = 'r-value';
      control.placeholder = 'group name, as the identity provider writes it';
      control.autocomplete = 'off';
      const listId = `groups-${Math.random().toString(36).slice(2)}`;
      const list = document.createElement('datalist');
      list.id = listId;
      for (const g of knownGroups(providerID())) list.append(new Option(g));
      control.setAttribute('list', listId);
      slot.append(list);
      if (cur && cur.group) control.value = cur.group;
    }
    if (control) slot.append(control);
  };
  kind.addEventListener('change', () => build(null));
  prov.addEventListener('change', () => build(null));
  if (current) {
    kind.value = current.kind;
    if (current.provider) prov.value = String(current.provider);
  } else if (identityOnly) kind.value = 'group';
  build(current);

  return () => {
    const v = { kind: kind.value };
    if (['group', 'user', 'any-user'].includes(v.kind)) v.provider = providerID();
    if (v.kind === 'peer') v.peer = control.value;
    if (v.kind === 'user') v.sub = control.value;
    if (v.kind === 'group') v.group = control.value.trim();
    return v;
  };
}

/* destinations on the local network: one line per address, with a name and
   a "what for" that fills in the ports */
const DEST_USES = [
  // key, label, protocol, ports (null: the person types them)
  ['file', 'File sharing', 'tcp', '445'],
  ['web', 'Web page', 'tcp', '80,443'],
  ['rdp', 'Remote desktop', 'any', '3389'],
  ['ssh', 'SSH', 'tcp', '22'],
  ['print', 'Printing', 'tcp', '631,9100'],
  ['all', 'Everything on this address', 'any', ''],
  ['tcp', 'Other ports (TCP)', 'tcp', null],
  ['udp', 'Other ports (UDP)', 'udp', null],
  ['any', 'Other ports (TCP and UDP)', 'any', null],
];

function destUse(route) {
  const proto = route.proto || 'any';
  const ports = (route.ports || '').replace(/\s+/g, '');
  return DEST_USES.find((u) => u[3] !== null && u[2] === proto && u[3] === ports) || DEST_USES.find((u) => u[3] === null && u[2] === proto);
}

// destAddress writes a route's address the way a person does: one address
// without its /32.
const destAddress = (r) => String(r.cidr || '').replace(/\/32$/, '');

// destChip shows one destination: its name, its address and what for.
function destChip(r) {
  const chip = node('span', 'reach__item');
  const single = /\/32$/.test(r.cidr || '') || !String(r.cidr || '').includes('/');
  if (r.name) chip.append(r.name + ' ');
  else if (!single) chip.append('Network ');
  chip.append(node('code', '', destAddress(r)));
  const use = destUse(r);
  let what = '';
  if (use[3] === null) what = `${{ tcp: 'TCP', udp: 'UDP', any: 'TCP and UDP' }[use[2]]} ${r.ports}`;
  else if (use[0] !== 'all') what = use[1].toLowerCase();
  if (what) chip.append(' ' + what);
  chip.title = use[0] === 'all' ? 'Every port, TCP and UDP' : `${{ tcp: 'TCP', udp: 'UDP', any: 'TCP and UDP' }[r.proto || 'any']}, port ${r.ports}`;
  return chip;
}

// addDestRow adds one destination to an editor. onChange is called when the
// person changed something that is worth checking again.
function addDestRow(boxId, route, onChange) {
  const row = node('div', 'dest');
  const field = (label, el) => { const l = node('label', '', label); l.append(el); row.append(l); return el; };
  const name = field('Name', node('input', 'dt-name'));
  name.placeholder = 'NAS';
  name.maxLength = 64;
  name.autocomplete = 'off';
  const cidr = field('Address', node('input', 'dt-cidr mono'));
  cidr.placeholder = '192.168.1.10';
  cidr.autocomplete = 'off';
  cidr.spellcheck = false;
  const use = field('What for', node('select', 'dt-use'));
  for (const u of DEST_USES) use.add(new Option(u[1], u[0]));
  const ports = field('Ports', node('input', 'dt-ports mono'));
  ports.autocomplete = 'off';
  ports.spellcheck = false;
  const del = node('button', 'btn btn--ghost btn--sm', '×');
  del.type = 'button';
  del.title = 'Take this address out';
  del.setAttribute('aria-label', 'Take this address out');
  row.append(del);

  const sync = (keep) => {
    const u = DEST_USES.find((x) => x[0] === use.value);
    ports.readOnly = u[3] !== null;
    if (u[3] !== null) ports.value = u[3];
    else if (!keep) ports.value = '';
    ports.placeholder = u[0] === 'all' ? 'all ports' : '8080 or 8000-8100';
  };
  if (route) {
    name.value = route.name || '';
    cidr.value = destAddress(route);
    use.value = destUse(route)[0];
    ports.value = route.ports || '';
    sync(true);
  } else sync(false);
  use.addEventListener('change', () => { sync(false); if (ports.readOnly === false) ports.focus(); });
  row.addEventListener('change', () => onChange && onChange());
  del.addEventListener('click', () => { row.remove(); if (onChange) onChange(); });
  $(boxId).appendChild(row);
}

function readDests(boxId) {
  const out = [];
  for (const row of $(boxId).children) {
    let cidr = row.querySelector('.dt-cidr').value.trim();
    if (!cidr) continue;
    if (!cidr.includes('/')) cidr += '/32';
    const u = DEST_USES.find((x) => x[0] === row.querySelector('.dt-use').value);
    out.push({ name: row.querySelector('.dt-name').value.trim(), cidr, proto: u[2], ports: row.querySelector('.dt-ports').value.replace(/\s+/g, '') });
  }
  return out;
}

// checkDests asks quicgate, for every destination in an editor, whether a
// device that was given it could really get there, and says why not. It
// tries the first port of each line.
const destCheckRun = {};
async function checkDests(boxId, outId) {
  const run = (destCheckRun[outId] = (destCheckRun[outId] || 0) + 1);
  const lines = [];
  for (const r of readDests(boxId)) {
    const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/.exec(r.cidr);
    if (!m) { lines.push([false, `${r.cidr} is not an address like 192.168.1.10`]); continue; }
    const single = m[5] === '32';
    // For a whole network, try its first address.
    const host = single ? destAddress(r) : `${m[1]}.${m[2]}.${m[3]}.${Math.min(254, (parseInt(m[4], 10) & ~1) + 1)}`;
    const port = (/\d+/.exec(r.ports) || ['443'])[0];
    const proto = r.proto === 'udp' ? 'udp' : 'tcp';
    try {
      const a = await api('POST', '/api/wg/explain', { routes: [r], proto, dest: `${host}:${port}` });
      if (a.answer.startsWith('refused')) lines.push([false, `${host} on port ${port} cannot be reached: ${a.answer.replace(/^refused:\s*/, '')}`]);
      else lines.push([true, `Checked: ${host} on port ${port} can be reached with this${single ? '' : ' (tried the first address of the network)'}.`]);
    } catch (err) {
      lines.push([false, err.message]);
    }
  }
  if (run !== destCheckRun[outId]) return; // an older answer came in late
  const out = $(outId);
  out.textContent = '';
  for (const [ok, text] of lines) {
    const p = node('p', 'checkline' + (ok ? '' : ' is-bad'));
    p.append(node('span', '', ok ? '✓' : '✗'), node('span', '', text));
    out.append(p);
  }
}

/* devices: add one, or change what one may reach */
let wgDeviceEditing = null;

function syncWGDeviceKeyMode() { $('wd-pubkey-field').hidden = !$('wd-key-paste').checked; }
$('wd-key-generate').addEventListener('change', syncWGDeviceKeyMode);
$('wd-key-paste').addEventListener('change', syncWGDeviceKeyMode);

const checkDeviceDests = () => checkDests('wd-routes', 'wd-check');

function syncWGDeviceReach() {
  const local = $('wd-reach-local').checked;
  const editing = !!wgDeviceEditing;
  $('wd-choice-private').classList.toggle('is-picked', !local);
  $('wd-choice-local').classList.toggle('is-picked', local);
  $('wd-local').hidden = !local;
  // Giving local addresses costs a confirmation, and so does every later
  // change, also one that takes them away.
  const confirmIt = local || editing;
  $('wd-confirm').hidden = !confirmIt;
  $('wd-confirm-why').textContent = editing
    ? 'Asked for every change to what a device of yours may reach, because nobody logs in behind such a device.'
    : 'Asked because this device gets into your local network without anybody logging in.';
  $('wd-lan-off').hidden = !local || vpnSettings.wg_lan_access === '1';
  $('wd-no-2fa').hidden = !confirmIt || vpnTwoFactor;
  $('wgdevice-btn-save').textContent = editing ? 'Save' : 'Add device';
  if (local && !$('wd-routes').children.length) addDestRow('wd-routes', null, checkDeviceDests);
}
$('wd-reach-private').addEventListener('change', syncWGDeviceReach);
$('wd-reach-local').addEventListener('change', syncWGDeviceReach);
$('wd-add-route').addEventListener('click', () => addDestRow('wd-routes', null, checkDeviceDests));
$('wd-never').addEventListener('change', () => { $('wd-expires').disabled = $('wd-never').checked; });
$('wd-lan-on').addEventListener('click', async () => { if (await switchLocalAccessOn()) syncWGDeviceReach(); });
$('wd-open-2fa').addEventListener('click', () => { closeWGDeviceModal(); switchPage('account', 'security'); });

// openWGDeviceModal adds a device, or with {device} changes what an existing
// device of the admin's may reach. {local: true} starts on the choice with
// addresses on the local network.
async function openWGDeviceModal({ device = null, local = false } = {}) {
  wgDeviceEditing = device;
  const routes = (device && device.routes) || [];
  $('wgdevice-modal-title').textContent = device ? `What may ${device.name} reach?` : 'Add a device';
  setError('wgdevice-error', null);
  $('wgdevice-form').reset();
  $('wgdevice-form').hidden = false;
  $('wgdevice-created').hidden = true;
  $('wgdevice-changed').hidden = true;
  $('wd-steps').hidden = !!device;
  $('wd-step-1').classList.add('is-now');
  $('wd-step-2').classList.remove('is-now');
  $('wd-name-field').hidden = !!device;
  $('wd-name').required = !device;
  $('wd-technical').hidden = !!device;
  $('wd-technical').open = false;
  $('wd-routes').textContent = '';
  $('wd-check').textContent = '';
  for (const r of routes) addDestRow('wd-routes', r, checkDeviceDests);
  $('wd-reach-local').checked = device ? routes.length > 0 : local;
  $('wd-reach-private').checked = !$('wd-reach-local').checked;
  // An end date is offered by default: a year from now.
  const end = device && device.expiresAt ? new Date(device.expiresAt) : new Date(Date.now() + 365 * 86400 * 1000);
  $('wd-expires').value = end.toISOString().slice(0, 10);
  $('wd-never').checked = !!device && routes.length > 0 && !device.expiresAt;
  $('wd-expires').disabled = $('wd-never').checked;
  syncWGDeviceReach();
  if (!device) {
    const can = await canMakeKeys();
    $('wd-key-generate').disabled = !can;
    $('wd-key-unsupported').hidden = can;
    $('wd-key-generate').checked = can;
    $('wd-key-paste').checked = !can;
    // Without a key made here the person has to paste one: show where.
    $('wd-technical').open = !can;
    syncWGDeviceKeyMode();
  }
  $('wgdevice-modal').hidden = false;
  if (routes.length) checkDeviceDests();
}

function closeWGDeviceModal() {
  // The setup text holds keys, and the form a password: neither stays.
  $('wd-config').value = '';
  $('wd-allowed').value = '';
  $('wgdevice-form').reset();
  $('wgdevice-modal').hidden = true;
  wgDeviceEditing = null;
  refreshVPN();
}
$('btn-add-wgdevice').addEventListener('click', () => openWGDeviceModal({}));
$('wgdevice-modal-close').addEventListener('click', closeWGDeviceModal);
$('wgdevice-btn-cancel').addEventListener('click', closeWGDeviceModal);
$('wgdevice-btn-done').addEventListener('click', closeWGDeviceModal);
$('wgdevice-btn-changed-done').addEventListener('click', closeWGDeviceModal);

async function copyFrom(field, button, label) {
  try { await navigator.clipboard.writeText(field.value); } catch (err) { field.select(); document.execCommand('copy'); }
  button.textContent = 'Copied';
  setTimeout(() => { button.textContent = label; }, 1500);
}
$('wgdevice-btn-copy').addEventListener('click', () => copyFrom($('wd-config'), $('wgdevice-btn-copy'), 'Copy as text'));
$('wd-allowed-copy').addEventListener('click', () => copyFrom($('wd-allowed'), $('wd-allowed-copy'), 'Copy'));
$('wgdevice-btn-download').addEventListener('click', () => {
  const url = URL.createObjectURL(new Blob([$('wd-config').value], { type: 'text/plain' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = `${$('wgdevice-btn-download').dataset.name || 'vpn'}.conf`;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

// allowedIPs is the line of a device's setup file that says what goes into
// the VPN: quicgate itself, and the local addresses the device was given.
function allowedIPs(status, routes) {
  return [...new Set([`${status.address}/32`, ...(routes || []).map((r) => r.cidr)])].join(', ');
}

$('wgdevice-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  setError('wgdevice-error', null);
  const editing = wgDeviceEditing;
  try {
    const local = $('wd-reach-local').checked;
    const routes = local ? readDests('wd-routes') : [];
    if (local && !routes.length) throw new Error('Name at least one address on your local network, or pick "Private hosts only".');
    const never = $('wd-never').checked;
    const access = routes.length ? {
      routes, neverExpires: never,
      expiresAt: never || !$('wd-expires').value ? '' : new Date($('wd-expires').value + 'T23:59:59').toISOString(),
    } : {};
    const confirmation = { password: $('wd-password').value, code: $('wd-code').value.trim() };

    if (editing) {
      const changed = await api('PUT', `/api/wg/devices/${editing.id}/access`, { routes: [], ...access, ...confirmation });
      $('wd-password').value = '';
      $('wd-code').value = '';
      const status = await api('GET', '/api/wg/status');
      const before = allowedIPs(status, editing.routes);
      const after = allowedIPs(status, changed.routes);
      $('wd-allowed').value = `AllowedIPs = ${after}`;
      const same = before === after;
      $('wd-changed-todo').textContent = same
        ? 'Nothing is left to do on the device: the addresses it sends into the VPN did not change. For reference, this is its line in the WireGuard app:'
        : 'One thing is left to do on the device itself. quicgate cannot make its setup file again, because it never had the device\'s private key. In the WireGuard app, edit the tunnel and replace the line that starts with AllowedIPs with this one:';
      $('wgdevice-form').hidden = true;
      $('wgdevice-changed').hidden = false;
      return;
    }

    let privateKey = '';
    let publicKey = $('wd-pubkey').value.trim();
    if ($('wd-key-generate').checked) {
      const kp = await makeWGKeypair();
      privateKey = kp.privateKey;
      publicKey = kp.publicKey;
    }
    const name = $('wd-name').value.trim();
    const created = await api('POST', '/api/wg/devices', { name, publicKey, ...access, ...(routes.length ? confirmation : {}) });
    $('wd-password').value = '';
    $('wd-code').value = '';
    const status = await api('GET', '/api/wg/status');
    $('wd-config').value = [
      '[Interface]',
      `PrivateKey = ${privateKey || '(keep the private key that is in the WireGuard app)'}`,
      `Address = ${created.address}/32`,
      `DNS = ${status.address}`,
      '',
      '[Peer]',
      '# quicgate',
      `PublicKey = ${status.publicKey}`,
      `PresharedKey = ${created.presharedKey}`,
      ...(status.endpoint ? [`Endpoint = ${status.endpoint}`] : ['# Endpoint = (fill in "Address devices connect to" under VPN settings first)']),
      `AllowedIPs = ${allowedIPs(status, created.routes)}`,
      'PersistentKeepalive = 25',
      '',
    ].join('\n');
    $('wgdevice-btn-download').dataset.name = name.replace(/[^A-Za-z0-9_-]+/g, '-').slice(0, 15) || 'vpn';
    const first = (created.routes || [])[0];
    $('wd-try-line').textContent = first
      ? `Try it: reach ${first.name ? first.name + ' at ' : ''}${destAddress(first)} from the device.${vpnSettings.wg_lan_access === '1' ? '' : ' (Local network access is still switched off: switch it on under VPN settings first.)'}`
      : 'Try it: open one of your private hosts from the device.';
    $('wgdevice-modal-title').textContent = `Set up ${name}`;
    $('wd-step-1').classList.remove('is-now');
    $('wd-step-2').classList.add('is-now');
    $('wgdevice-form').hidden = true;
    $('wgdevice-created').hidden = false;
  } catch (err) {
    setError('wgdevice-error', err);
  }
});

/* rules: what people who log in may reach on the local network */
let readPolicySubject = null;
const checkPolicyDests = () => checkDests('vp-routes', 'vp-check');

function openPolicyModal(p) {
  editingPolicyId = p ? p.id : null;
  $('vpnpolicy-modal-title').textContent = p ? `Change the rule "${p.name}"` : 'Add a rule';
  setError('vpnpolicy-error', null);
  $('vp-name').value = p ? p.name : '';
  readPolicySubject = makeSubjectPicker($('vp-subject'), p ? p.subject : null, true);
  $('vp-routes').textContent = '';
  $('vp-check').textContent = '';
  for (const r of (p && p.routes) || [null]) addDestRow('vp-routes', r, checkPolicyDests);
  $('vp-try-dest').value = '';
  $('vp-try-answer').hidden = true;
  $('vpnpolicy-modal').hidden = false;
  if (p) checkPolicyDests();
}
$('btn-add-vpnpolicy').addEventListener('click', () => openPolicyModal(null));
$('vp-add-route').addEventListener('click', () => addDestRow('vp-routes', null, checkPolicyDests));
$('vpnpolicy-modal-close').addEventListener('click', () => { $('vpnpolicy-modal').hidden = true; });
$('vpnpolicy-btn-cancel').addEventListener('click', () => { $('vpnpolicy-modal').hidden = true; });
$('vp-try').addEventListener('click', async () => {
  const out = $('vp-try-answer');
  out.hidden = false;
  try {
    const r = await api('POST', '/api/wg/explain', { routes: readDests('vp-routes'), proto: $('vp-try-proto').value, dest: $('vp-try-dest').value.trim() });
    const refused = r.answer.startsWith('refused');
    out.textContent = refused ? `No: ${r.answer.replace(/^refused:\s*/, '')}.` : 'Yes, this rule lets it through.';
    out.classList.toggle('form-error', refused);
  } catch (err) {
    out.textContent = err.message;
    out.classList.add('form-error');
  }
});
$('vpnpolicy-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  setError('vpnpolicy-error', null);
  const policy = { name: $('vp-name').value.trim(), subject: readPolicySubject(), routes: readDests('vp-routes') };
  try {
    if (editingPolicyId) await api('PUT', `/api/wg/policies/${editingPolicyId}`, policy);
    else await api('POST', '/api/wg/policies', policy);
    $('vpnpolicy-modal').hidden = true;
    refreshVPN();
  } catch (err) {
    setError('vpnpolicy-error', err);
  }
});

/* the VPN portal host type */
function addPortalEnrolRow(subject) {
  const row = document.createElement('div');
  row.className = 'hdr-rule';
  const box = document.createElement('span');
  box.style.display = 'contents';
  const del = document.createElement('button');
  del.type = 'button';
  del.className = 'btn btn--ghost btn--sm';
  del.innerHTML = '&times;';
  del.addEventListener('click', () => row.remove());
  row.append(box, del);
  row._read = makeSubjectPicker(box, subject, true, () => parseInt($('f-portal-provider').value, 10) || 0);
  $('f-portal-enrol').appendChild(row);
}
$('btn-add-portal-enrol').addEventListener('click', () => addPortalEnrolRow(null));

async function fillPortalBlock(h) {
  await loadVPNPeople();
  const po = (h && h.options && h.options.portal) || null;
  const sel = $('f-portal-provider');
  sel.innerHTML = '';
  for (const pv of oidcProviders) sel.add(new Option(pv.name, String(pv.id)));
  if (po) sel.value = String(po.providerId);
  $('f-portal-claims').value = (po && po.claimsSource) || 'id_token';
  $('f-portal-warn').hidden = oidcProviders.length > 0;
  $('f-portal-enrol').textContent = '';
  for (const s of (po && po.enrol) || [null]) addPortalEnrolRow(s);
  const first = (h && h.domains && h.domains[0]) || '<host>';
  $('f-portal-redirect-hint').textContent = `https://${first}/.qg/vpn/callback`;
}

function readPortalOptions() {
  const providerId = parseInt($('f-portal-provider').value, 10) || 0;
  return {
    providerId,
    claimsSource: $('f-portal-claims').value,
    enrol: [...$('f-portal-enrol').children].map((row) => row._read()).filter((s) => s.kind !== 'group' || s.group),
  };
}

$('wg-reset-key').addEventListener('click', async () => {
  if (!confirm('Make a new server key? Do this only when the original secret key (secret.key) is lost. Every device and every other network has to be set up again: their setup files name the old key.')) return;
  const password = prompt('Confirm with your password');
  if (!password) return;
  try { await api('POST', '/api/wg/server-key/reset', { password }); refreshVPN(); } catch (err) { alert(err.message); }
});
