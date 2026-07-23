'use strict';

const $ = (id) => document.getElementById(id);
const views = ['view-login', 'view-password', 'view-app'];
let hosts = [];
let editingId = null;

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

function setError(id, err) {
  const el = $(id);
  el.hidden = !err;
  el.textContent = err ? String(err.message || err) : '';
}

/* ---- boot ---- */
async function boot() {
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
    const me = await api('POST', '/api/login', {
      email: $('login-email').value,
      password: $('login-password').value,
    });
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
async function refresh() {
  hosts = await api('GET', '/api/hosts');
  const body = $('hosts-body');
  body.innerHTML = '';
  $('hosts-empty').hidden = hosts.length > 0;
  for (const h of hosts) {
    const tr = document.createElement('tr');

    const tdDomains = document.createElement('td');
    tdDomains.className = 'domain';
    tdDomains.textContent = h.domains.join('\n');
    tdDomains.style.whiteSpace = 'pre';

    const tdUpstream = document.createElement('td');
    tdUpstream.className = 'domain';
    tdUpstream.textContent = `${h.upstream.scheme}://${h.upstream.host}:${h.upstream.port}`;

    const tdTLS = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = 'badge' + (h.certMode === 'auto' ? ' badge--success' : '');
    badge.textContent = h.certMode === 'auto' ? (h.forceSsl ? 'auto + force ssl' : 'auto') : 'http only';
    tdTLS.appendChild(badge);

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
    tdActions.append(btnEdit, btnDel);

    tr.append(tdDomains, tdUpstream, tdTLS, tdEnabled, tdActions);
    body.appendChild(tr);
  }
  refreshCerts();
}

async function refreshCerts() {
  const certs = await api('GET', '/api/certs').catch(() => []);
  const body = $('certs-body');
  body.innerHTML = '';
  $('certs-empty').hidden = certs.length > 0;
  for (const c of certs) {
    const tr = document.createElement('tr');
    const badgeClass = c.status === 'issued' ? 'badge badge--success' : 'badge';
    tr.innerHTML = `<td class="domain">${c.domain}</td>` +
      `<td><span class="${badgeClass}">${c.status}</span></td>` +
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

/* ---- modal ---- */
function switchTab(name) {
  for (const t of $('modal-tabs').children) t.classList.toggle('is-active', t.dataset.tab === name);
  for (const p of document.querySelectorAll('.tabpane')) p.hidden = p.dataset.pane !== name;
}
$('modal-tabs').addEventListener('click', (e) => {
  if (e.target.dataset.tab) switchTab(e.target.dataset.tab);
});

function openModal(h) {
  editingId = h ? h.id : null;
  $('modal-title').textContent = h ? 'Edit proxy host' : 'Add proxy host';
  setError('host-error', null);
  const o = (h && h.options) || {};
  $('f-domains').value = h ? h.domains.join('\n') : '';
  $('f-scheme').value = h ? h.upstream.scheme : 'http';
  $('f-uhost').value = h ? h.upstream.host : '';
  $('f-uport').value = h ? h.upstream.port : '';
  $('f-enabled').checked = h ? h.enabled : true;
  $('f-certmode').value = h ? h.certMode : 'auto';
  $('f-forcessl').checked = h ? h.forceSsl : true;
  $('f-http3').checked = o.http3 !== false;
  $('f-mintls').value = o.minTlsVersion || '';
  $('f-hsts').checked = !!(o.hsts && o.hsts.enabled);
  $('f-hsts-age').value = (o.hsts && o.hsts.maxAge) || 15552000;
  $('f-hsts-sub').checked = !!(o.hsts && o.hsts.includeSubdomains);
  $('f-hsts-preload').checked = !!(o.hsts && o.hsts.preload);
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
  const host = {
    type: 'proxy',
    domains: $('f-domains').value.split('\n').map((s) => s.trim()).filter(Boolean),
    upstream: {
      scheme: $('f-scheme').value,
      host: $('f-uhost').value.trim(),
      port: parseInt($('f-uport').value, 10),
    },
    certMode: $('f-certmode').value,
    forceSsl: $('f-certmode').value === 'auto' && $('f-forcessl').checked,
    enabled: $('f-enabled').checked,
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

boot();
