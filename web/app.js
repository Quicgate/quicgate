'use strict';

const $ = (id) => document.getElementById(id);
const views = ['view-login', 'view-password', 'view-app'];
let hosts = [];
let accessLists = [];
let customCerts = [];
let editingId = null;
let editingAclId = null;
let editingStreamId = null;
let editingCertId = null;

/* ---- theme ---- */
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem('qg_theme', theme);
}
applyTheme(localStorage.getItem('qg_theme') || 'dark');
$('btn-theme').addEventListener('click', () => {
  applyTheme(document.documentElement.dataset.theme === 'light' ? 'dark' : 'light');
});

/* ---- page nav ---- */
const pages = { hosts: 'btn-add', access: 'btn-add-acl', streams: 'btn-add-stream', certs: 'btn-add-cert', system: null, settings: null, profile: null };
function switchPage(name) {
  for (const b of $('pagenav').children) b.classList.toggle('is-active', b.dataset.page === name);
  for (const p of Object.keys(pages)) {
    $(`page-${p}`).hidden = p !== name;
    if (pages[p]) $(pages[p]).hidden = p !== name;
  }
  if (name === 'hosts') refresh();
  if (name === 'access') refreshAcls();
  if (name === 'streams') refreshStreams();
  if (name === 'certs') { refreshCerts(); refreshCustomCerts(); }
  if (name === 'system') loadSystem();
  if (name === 'settings') loadSettings();
  if (name === 'profile') loadProfile();
}
$('pagenav').addEventListener('click', (e) => {
  if (e.target.dataset.page) switchPage(e.target.dataset.page);
});
$('me-email').addEventListener('click', () => switchPage('profile'));

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
  $('me-email').textContent = me.email;
  if (me.mustChange) {
    show('view-password');
  } else {
    show('view-app');
    refresh();
  }
}

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
    refresh();
  } catch (err) {
    setError('pw-error', err);
  }
});

$('btn-logout').addEventListener('click', async () => {
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
async function refresh() {
  let health;
  [hosts, accessLists, customCerts, health] = await Promise.all([
    api('GET', '/api/hosts'), api('GET', '/api/access-lists'), api('GET', '/api/custom-certs'),
    api('GET', '/api/health').catch(() => []),
  ]);
  healthMap = {};
  for (const t of health) healthMap[t.target] = t.up;
  renderHosts();
  refreshCerts();
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
    tdDomains.textContent = h.domains.join('\n');
    tdDomains.style.whiteSpace = 'pre';

    const tdUpstream = document.createElement('td');
    tdUpstream.className = 'domain';
    if (h.type === 'redirect' && h.redirect) {
      tdUpstream.innerHTML = `<span class="badge">${h.redirect.httpCode} redirect</span> ${h.redirect.targetHost}`;
    } else if (h.type === 'dead') {
      tdUpstream.innerHTML = '<span class="badge badge--danger">404 host</span>';
    } else if (h.type === 'static') {
      tdUpstream.innerHTML = `<span class="badge">static</span> ${h.staticRoot}`;
    } else {
      const pool = [h.upstream, ...(h.upstreams || [])];
      const primary = `${h.upstream.scheme}://${h.upstream.host}:${h.upstream.port}`;
      if (pool.length > 1) {
        const up = pool.filter((u) => healthMap[`${u.scheme}://${u.host}:${u.port}`] !== false).length;
        tdUpstream.innerHTML = `${primary} <span class="badge ${up === pool.length ? 'badge--success' : 'badge--danger'}">${up}/${pool.length} up</span>`;
      } else {
        tdUpstream.textContent = primary;
      }
    }

    const tdTLS = document.createElement('td');
    const badge = document.createElement('span');
    const cm = h.certMode;
    badge.className = 'badge' + (cm === 'auto' || cm === 'custom' ? ' badge--success' : '');
    badge.textContent = cm === 'auto' ? (h.forceSsl ? 'auto + force ssl' : 'auto')
      : cm === 'custom' ? 'custom cert' : 'http only';
    tdTLS.appendChild(badge);

    const tdAccess = document.createElement('td');
    const acl = accessLists.find((a) => a.id === h.accessListId);
    tdAccess.innerHTML = acl
      ? `<span class="badge badge--success">${acl.name}</span>`
      : '<span class="badge">public</span>';

    const tdCert = document.createElement('td');
    tdCert.className = 'domain';
    if (h.certMode === 'auto') {
      const c = h.domains.map((d) => certByDomain[d.toLowerCase()]).find(Boolean);
      if (c) {
        const cls = c.status === 'issued' ? 'badge--success' : c.status === 'failed' ? 'badge--danger' : '';
        const exp = c.notAfter ? ' ' + new Date(c.notAfter).toLocaleDateString() : '';
        tdCert.innerHTML = `<span class="badge ${cls}">${c.status}</span>${exp}`;
      } else {
        tdCert.innerHTML = '<span class="badge">pending</span>';
      }
    } else if (h.certMode === 'custom') {
      tdCert.innerHTML = '<span class="badge">custom</span>';
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
      ? `<div class="hs-muted" style="font-size:var(--fs-xs)" title="${c.lastError.replace(/"/g, '&quot;')}">last error: ${c.lastError.slice(0, 90)}</div>`
      : '';
    tr.innerHTML = `<td class="domain">${c.domain}</td>` +
      `<td><span class="${badgeClass}">${c.status}</span>${detail}</td>` +
      `<td class="domain">${c.notAfter ? new Date(c.notAfter).toLocaleString() : '-'}</td>`;
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
  $('f-ratelimit').checked = !!o.rateLimit;
  $('f-rate-rps').value = o.rateLimit ? o.rateLimit.rps : '';
  $('f-rate-burst').value = o.rateLimit ? o.rateLimit.burst : '';
  const fa = o.forwardAuth || {};
  $('f-fauth').checked = !!o.forwardAuth;
  $('f-fauth-url').value = fa.url || '';
  $('f-fauth-headers').value = (fa.responseHeaders || []).join(',');
  $('f-fauth-skipverify').checked = !!fa.skipTlsVerify;
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
      maxBodyMb: parseInt($('f-maxbody').value, 10) || 0,
      buffering: $('f-buffering').checked ? undefined : false,
      blockIndexing: $('f-noindex').checked,
      blockExploits: $('f-exploits').checked,
      blockBadBots: $('f-badbots').checked,
      compression: $('f-compress').checked,
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
async function refreshAcls() {
  accessLists = await api('GET', '/api/access-lists');
  const body = $('acl-body');
  body.innerHTML = '';
  $('acl-empty').hidden = accessLists.length > 0;
  for (const a of accessLists) {
    const tr = document.createElement('tr');
    const tdName = document.createElement('td');
    tdName.textContent = a.name;
    const tdSatisfy = document.createElement('td');
    tdSatisfy.innerHTML = `<span class="badge">${a.satisfy}</span>`;
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

function addAclRuleRow(rule) {
  const row = document.createElement('div');
  row.className = 'hdr-rule';
  row.innerHTML =
    '<select class="r-action"><option value="allow">allow</option><option value="deny">deny</option></select>' +
    '<select class="r-kind"><option value="cidr">IP/CIDR</option><option value="host">Hostname (DDNS)</option><option value="country">Country</option></select>' +
    '<input class="r-value" placeholder="192.168.178.0/24">' +
    '<button type="button" class="btn btn--ghost btn--sm">&times;</button>';
  const [action, kind, value] = [row.querySelector('.r-action'), row.querySelector('.r-kind'), row.querySelector('.r-value')];
  const hints = { cidr: '192.168.178.0/24 or single IP', host: 'home.duckdns.org', country: 'NL' };
  kind.addEventListener('change', () => { value.placeholder = hints[kind.value]; });
  if (rule) {
    action.value = rule.action;
    if (rule.host) { kind.value = 'host'; value.value = rule.host; }
    else if (rule.country) { kind.value = 'country'; value.value = rule.country; }
    else { kind.value = 'cidr'; value.value = rule.cidr; }
    value.placeholder = hints[kind.value];
  }
  row.children[3].addEventListener('click', () => row.remove());
  $('acl-rules').appendChild(row);
}

function addAclUserRow(user) {
  const row = document.createElement('div');
  row.className = 'hdr-rule';
  row.innerHTML =
    '<input placeholder="username">' +
    '<input type="password" placeholder="password">' +
    '<button type="button" class="btn btn--ghost btn--sm">&times;</button>';
  if (user) {
    row.children[0].value = user.username;
    row.children[1].placeholder = 'unchanged';
  }
  row.children[2].addEventListener('click', () => row.remove());
  $('acl-users').appendChild(row);
}

function openAclModal(a) {
  editingAclId = a ? a.id : null;
  $('acl-modal-title').textContent = a ? 'Edit access list' : 'Add access list';
  setError('acl-error', null);
  $('a-name').value = a ? a.name : '';
  $('a-satisfy').value = a ? a.satisfy : 'any';
  $('a-passauth').checked = a ? a.passAuth : false;
  $('acl-rules').innerHTML = '';
  $('acl-users').innerHTML = '';
  for (const r of (a && a.rules) || []) addAclRuleRow(r);
  for (const u of (a && a.users) || []) addAclUserRow(u);
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
    rules.push({ action, [kind]: val });
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

/* ---- streams page ---- */
async function refreshStreams() {
  let streams;
  [streams, customCerts] = await Promise.all([api('GET', '/api/streams'), api('GET', '/api/custom-certs')]);
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
    if (badges.length) tdListen.innerHTML += ' ' + badges.map((b) => `<span class="badge">${b}</span>`).join(' ');
    const tdProto = document.createElement('td');
    tdProto.innerHTML = `<span class="badge">${s.protocol === 'both' ? 'tcp + udp' : s.protocol}</span>`;
    const tdFwd = document.createElement('td');
    tdFwd.className = 'domain';
    tdFwd.textContent = `${s.forwardHost}:${s.forwardPort}`;
    const tdSources = document.createElement('td');
    const nCidrs = (s.allowedCidrs || []).length;
    tdSources.innerHTML = nCidrs
      ? `<span class="badge badge--success">${nCidrs} CIDR${nCidrs > 1 ? 's' : ''}</span>`
      : '<span class="badge badge--danger">open</span>';
    const tdEnabled = document.createElement('td');
    const sw = document.createElement('label');
    sw.className = 'switch';
    sw.innerHTML = '<input type="checkbox"><span class="switch__slot"></span><span class="switch__knob"></span>';
    const cb = sw.querySelector('input');
    cb.checked = s.enabled;
    cb.addEventListener('change', async () => {
      try {
        await api('PUT', `/api/streams/${s.id}`, { ...s, enabled: cb.checked });
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
  $('s-sendproxy').value = s ? (s.sendProxyProtocol || '') : '';
  $('s-acceptproxy').checked = s ? !!s.acceptProxyProtocol : false;
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
    allowedCidrs: $('s-cidrs').value.split('\n').map((v) => v.trim()).filter(Boolean),
    sendProxyProtocol: $('s-sendproxy').value,
    acceptProxyProtocol: $('s-acceptproxy').checked,
    terminateTls: $('s-terminatetls').checked,
    certId: $('s-terminatetls').checked && $('s-certid').value ? parseInt($('s-certid').value, 10) : null,
    sniRoutes,
    enabled: $('s-enabled').checked,
  };
  try {
    if (editingStreamId) await api('PUT', `/api/streams/${editingStreamId}`, s);
    else await api('POST', '/api/streams', s);
    $('stream-modal').hidden = true;
    refreshStreams();
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
      `<td>${c.name}</td>` +
      `<td class="domain">${(c.domains || []).join(', ')}</td>` +
      `<td class="domain"><span class="badge ${expired ? 'badge--danger' : 'badge--success'}">${c.notAfter ? new Date(c.notAfter).toLocaleDateString() : '-'}</span></td>`;
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
    el.textContent = `Imported ${data.hosts || 0} hosts, ${data.accessLists || 0} access lists, ${data.streams || 0} streams.`;
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

/* ---- system page ---- */
function loadSystem() {
  refreshLogs();
  refreshEffConfig();
}

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
    setError('pp-error', 'Password updated.');
  } catch (err) {
    setError('pp-error', err);
  }
});

let logCache = [];
async function refreshLogs() {
  // System page shows only traffic that matched no configured host.
  logCache = await api('GET', '/api/logs?n=500&general=1').catch(() => []);
  renderLogs();
}
$('logs-filter').addEventListener('input', renderLogs);

function logRow(e, withHost) {
  const tr = document.createElement('tr');
  const cls = e.status >= 400 ? 'badge--danger' : 'badge--success';
  tr.innerHTML =
    `<td class="domain">${e.ts ? new Date(e.ts).toLocaleTimeString() : ''}</td>` +
    `<td class="domain">${e.client_ip || ''}</td>` +
    (withHost ? `<td class="domain">${e.host || ''}</td>` : '') +
    `<td class="domain">${e.method || ''} ${e.path || ''}</td>` +
    `<td><span class="badge ${cls}">${e.status || ''}</span></td>` +
    `<td class="domain">${e.dur_ms ?? ''}</td>`;
  return tr;
}

function renderLogs() {
  const q = $('logs-filter').value.trim().toLowerCase();
  const logs = q
    ? logCache.filter((e) => `${e.host} ${e.client_ip} ${e.path} ${e.status}`.toLowerCase().includes(q))
    : logCache;
  const body = $('logs-body');
  body.innerHTML = '';
  $('logs-empty').hidden = logs.length > 0;
  for (const e of logs) body.appendChild(logRow(e, true));
}
$('btn-logs-refresh').addEventListener('click', refreshLogs);

// ---- per-host access log modal ----
let hostLogCache = [];
let hostLogDomain = '';
async function refreshHostLogs() {
  hostLogCache = await api('GET', `/api/logs?n=300&host=${encodeURIComponent(hostLogDomain)}`).catch(() => []);
  renderHostLogs();
}
function renderHostLogs() {
  const q = $('hostlog-filter').value.trim().toLowerCase();
  const logs = q
    ? hostLogCache.filter((e) => `${e.client_ip} ${e.path} ${e.status}`.toLowerCase().includes(q))
    : hostLogCache;
  const body = $('hostlog-body');
  body.innerHTML = '';
  $('hostlog-empty').hidden = logs.length > 0;
  for (const e of logs) body.appendChild(logRow(e, false));
}
function openHostLogs(h) {
  hostLogDomain = h.domains[0];
  $('hostlog-title').textContent = `Access log: ${hostLogDomain}`;
  $('hostlog-filter').value = '';
  $('hostlog-modal').hidden = false;
  refreshHostLogs();
}
$('hostlog-filter').addEventListener('input', renderHostLogs);
$('hostlog-refresh').addEventListener('click', refreshHostLogs);
$('hostlog-close').addEventListener('click', () => { $('hostlog-modal').hidden = true; });
$('hostlog-modal').addEventListener('click', (e) => {
  if (e.target === $('hostlog-modal')) $('hostlog-modal').hidden = true;
});

async function refreshEffConfig() {
  const routes = (await api('GET', '/api/config').catch(() => [])) || [];
  const body = $('effconfig-body');
  body.innerHTML = '';
  for (const r of routes.sort((a, b) => a.domain.localeCompare(b.domain))) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td class="domain">${r.domain}</td><td><span class="badge">${r.type}</span></td><td class="domain">${r.target || ''}</td>`;
    body.appendChild(tr);
  }
}
$('btn-config-refresh').addEventListener('click', refreshEffConfig);

async function refreshTokens() {
  const tokens = await api('GET', '/api/tokens').catch(() => []);
  const body = $('tokens-body');
  body.innerHTML = '';
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
  if (me.totpEnabled) {
    el.innerHTML = '<span class="badge badge--success">2FA enabled</span> ';
    const btn = document.createElement('button');
    btn.className = 'btn btn--danger btn--sm'; btn.textContent = 'Disable';
    btn.addEventListener('click', async () => { await api('POST', '/api/2fa/disable'); refresh2FA(); });
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
    await api('POST', '/api/2fa/enable', { secret: pending2FASecret, code: $('twofa-code').value.trim() });
    $('twofa-code').value = '';
    refresh2FA();
  } catch (err) { setError('twofa-error', err); }
});

/* ---- settings page ---- */
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

async function loadSettings() {
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
  $('set-oidc-issuer').value = s.oidc_issuer || '';
  $('set-oidc-client-id').value = s.oidc_client_id || '';
  $('set-oidc-client-secret').value = s.oidc_client_secret || '';
  $('set-oidc-redirect').value = s.oidc_redirect_url || '';
  $('set-oidc-emails').value = s.oidc_allowed_emails || '';
  $('set-ldap-enabled').checked = s.ldap_enabled === '1';
  $('set-ldap-url').value = s.ldap_url || '';
  $('set-ldap-dn').value = s.ldap_bind_dn_template || '';
  syncDnsField();
  syncDefaultSiteField();
}

$('oidc-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api('PUT', '/api/settings', {
      oidc_enabled: $('set-oidc-enabled').checked ? '1' : '0',
      oidc_issuer: $('set-oidc-issuer').value.trim(),
      oidc_client_id: $('set-oidc-client-id').value.trim(),
      oidc_client_secret: $('set-oidc-client-secret').value,
      oidc_redirect_url: $('set-oidc-redirect').value.trim(),
      oidc_allowed_emails: $('set-oidc-emails').value.trim(),
    });
  } catch (err) { alert(err.message); }
});

$('ldap-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api('PUT', '/api/settings', {
      ldap_enabled: $('set-ldap-enabled').checked ? '1' : '0',
      ldap_url: $('set-ldap-url').value.trim(),
      ldap_bind_dn_template: $('set-ldap-dn').value.trim(),
    });
  } catch (err) { alert(err.message); }
});

$('ban-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api('PUT', '/api/settings', {
      ban_enabled: $('set-ban-enabled').checked ? '1' : '0',
      ban_threshold: $('set-ban-threshold').value || '5',
      ban_window_sec: $('set-ban-window').value || '300',
      ban_duration_sec: $('set-ban-duration').value || '3600',
    });
  } catch (err) {
    alert(err.message);
  }
});

$('settings-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  setError('settings-error', null);
  try {
    await api('PUT', '/api/settings', {
      acme_email: $('set-acme-email').value.trim(),
      acme_staging: $('set-acme-staging').checked ? '1' : '0',
      acme_ca_url: $('set-acme-ca-url').value.trim(),
      notify_url: $('set-notify-url').value.trim(),
      acme_dns_provider: $('set-dns-provider').value,
      acme_dns_config: $('set-dns-config').value.trim(),
    });
    setError('settings-error', 'Saved.');
  } catch (err) {
    setError('settings-error', err);
  }
});

$('defaultsite-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api('PUT', '/api/settings', {
      default_site: $('set-default-site').value,
      default_site_value: $('set-default-site-value').value,
    });
  } catch (err) {
    alert(err.message);
  }
});

$('btn-notify-test').addEventListener('click', async () => {
  setError('settings-error', null);
  try {
    await api('PUT', '/api/settings', { notify_url: $('set-notify-url').value.trim() });
    await api('POST', '/api/notify-test');
    setError('settings-error', 'Test alert sent (check your notification channel).');
  } catch (err) {
    setError('settings-error', err);
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
    el.textContent = 'Restored. The restored admin credentials now apply; you may need to sign in again.';
  } catch (err) {
    el.textContent = 'Restore failed: ' + err.message;
  }
  $('restore-file').value = '';
});

boot();
