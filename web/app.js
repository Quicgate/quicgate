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

function switchPage(name, section) {
  if (!pageLoaders[name]) name = 'overview';
  for (const b of $('pagenav').children) b.classList.toggle('is-active', b.dataset.page === name);
  for (const p of Object.keys(pageLoaders)) $(`page-${p}`).hidden = p !== name;
  if (sectionNavs[name]) showSection(name, section);
  history.replaceState(null, '', `#/${name}${sectionNavs[name] ? '/' + currentSection[name] : ''}`);
  window.scrollTo(0, 0);
  pageLoaders[name]();
}

for (const [page, navId] of Object.entries(sectionNavs)) {
  $(navId).addEventListener('click', (e) => {
    const b = e.target.closest('[data-section]');
    if (!b) return;
    showSection(page, b.dataset.section);
    history.replaceState(null, '', `#/${page}/${b.dataset.section}`);
  });
}
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
  { id: 'streams', title: 'Streams & port forwards', blurb: 'TCP/UDP forwarding, PROXY protocol, SNI routing, UPnP.' },
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

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = res.status === 204 ? {} : await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
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

function afterLogin(me) {
  // Password managers match a password field to the account through a
  // username field in the same form.
  document.querySelectorAll('.pm-user').forEach((el) => { el.value = me.email; });
  $('me-email').textContent = me.email;
  $('me-email-full').textContent = me.email;
  $('account-sub').textContent = me.email;
  $('me-avatar').textContent = initials(me.email);
  if (me.version) $('qg-version').textContent = 'quicgate ' + (/^v|^dev/.test(me.version) ? me.version : 'v' + me.version);
  if (me.mustChange) {
    show('view-password');
  } else {
    show('view-app');
    const r = routeFromHash();
    switchPage(r.page, r.section);
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
  if (down) attn('bad', `${plural(down, 'upstream is', 'upstreams are')} unreachable`, 'hosts');
  if (failedCerts) attn('bad', `${plural(failedCerts, 'certificate', 'certificates')} failed to issue or renew`, 'certs');
  const closed = (routes || []).filter((r) => (r.warnings || []).length).length;
  if (closed) attn('warn', `${plural(closed, 'route fails', 'routes fail')} closed because of a configuration problem`, 'hosts');
  const notRunning = (streams || []).filter((s) => (s.listeners || []).some((l) => l.state !== 'running')).length;
  if (notRunning) attn('bad', `${plural(notRunning, 'stream is', 'streams are')} not running`, 'streams');
  if (o.docker && o.docker.connected < o.docker.endpoints) {
    attn('warn', `${plural(o.docker.endpoints - o.docker.connected, 'Docker host is', 'Docker hosts are')} disconnected`, 'docker');
  }
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
    } else {
      const pool = [h.upstream, ...(h.upstreams || [])];
      const primary = `${h.upstream.scheme}://${h.upstream.host}:${h.upstream.port}`;
      const up = pool.filter((u) => healthMap[`${u.scheme}://${u.host}:${u.port}`] !== false).length;
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
      : '<span class="badge badge--muted">public</span>';

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
    upstream: type === 'proxy' ? {
      scheme: $('f-scheme').value,
      host: $('f-uhost').value.trim(),
      port: parseInt($('f-uport').value, 10),
    } : { scheme: 'http', host: '', port: 0 },
    upstreams: type === 'proxy' ? parsePool($('f-pool').value) : [],
    locations: type === 'proxy' ? readLocations() : [],
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
    tdRules.textContent = (a.rules || []).map((r) => `${r.action} ${r.cidr || r.host || ('country:' + r.country)}`).join('\n') || '-';
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
    '<select class="r-kind"><option value="cidr">IP/CIDR</option><option value="host">Hostname (DDNS)</option><option value="country">Country</option></select>' +
    '<span class="r-value-slot"></span>' +
    '<span class="r-methods" title="Click the verbs this rule applies to. None selected = all methods.">' + chips + '</span>' +
    '<button type="button" class="btn btn--ghost btn--sm r-del">&times;</button>';
  const action = row.querySelector('.r-action');
  const kind = row.querySelector('.r-kind');
  const slot = row.querySelector('.r-value-slot');
  const hints = { cidr: '192.168.1.0/24 or single IP', host: 'home.duckdns.org' };
  const setField = (current) => {
    slot.innerHTML = '';
    slot.appendChild(kind.value === 'country' ? makeCountrySelect(current) : makeTextField(hints[kind.value], current));
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
    if (rule.host) kind.value = 'host';
    else if (rule.country) kind.value = 'country';
    else kind.value = 'cidr';
    setField(rule.host || rule.country || rule.cidr || '');
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
    const val = row.querySelector('.r-value').value.trim();
    if (!val) continue;
    const rule = { action, [kind]: val };
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
  [streams, customCerts, accessLists] = await Promise.all([api('GET', '/api/streams'), api('GET', '/api/custom-certs'), api('GET', '/api/access-lists')]);
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
    tdFwd.textContent = `${s.forwardHost}:${s.forwardPort}`;
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
    const td1 = document.createElement('td'); td1.className = 'domain'; td1.textContent = t.createdAt ? new Date(t.createdAt).toLocaleDateString() : '';
    const td2 = document.createElement('td'); td2.style.textAlign = 'right';
    const del = document.createElement('button');
    del.className = 'btn btn--danger btn--sm'; del.textContent = 'Revoke';
    del.addEventListener('click', async () => { await api('DELETE', `/api/tokens/${t.id}`); refreshTokens(); });
    td2.appendChild(del);
    tr.append(td0, td1, td2);
    body.appendChild(tr);
  }
}
$('btn-add-token').addEventListener('click', async () => {
  const name = prompt('Token name (e.g. "ci-pipeline"):');
  if (!name) return;
  try {
    const t = await api('POST', '/api/tokens', { name });
    const el = $('new-token');
    el.hidden = false;
    el.textContent = `New token (copy now, shown once): ${t.token}`;
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
  });
});

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
