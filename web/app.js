'use strict';

const $ = (id) => document.getElementById(id);
const views = ['view-login', 'view-password', 'view-app'];
let hosts = [];
let accessLists = [];
let editingId = null;
let editingAclId = null;
let editingStreamId = null;

/* ---- page nav ---- */
const pages = { hosts: 'btn-add', access: 'btn-add-acl', streams: 'btn-add-stream' };
function switchPage(name) {
  for (const b of $('pagenav').children) b.classList.toggle('is-active', b.dataset.page === name);
  for (const p of Object.keys(pages)) {
    $(`page-${p}`).hidden = p !== name;
    $(pages[p]).hidden = p !== name;
  }
  if (name === 'hosts') refresh();
  if (name === 'access') refreshAcls();
  if (name === 'streams') refreshStreams();
}
$('pagenav').addEventListener('click', (e) => {
  if (e.target.dataset.page) switchPage(e.target.dataset.page);
});

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
  [hosts, accessLists] = await Promise.all([api('GET', '/api/hosts'), api('GET', '/api/access-lists')]);
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

    const tdAccess = document.createElement('td');
    const acl = accessLists.find((a) => a.id === h.accessListId);
    tdAccess.innerHTML = acl
      ? `<span class="badge badge--success">${acl.name}</span>`
      : '<span class="badge">public</span>';

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

    tr.append(tdDomains, tdUpstream, tdTLS, tdAccess, tdEnabled, tdActions);
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
    tdRules.textContent = (a.rules || []).map((r) => `${r.action} ${r.cidr}`).join('\n') || '-';
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
    '<select><option value="allow">allow</option><option value="deny">deny</option></select>' +
    '<input placeholder="192.168.178.0/24 or single IP">' +
    '<button type="button" class="btn btn--ghost btn--sm">&times;</button>';
  if (rule) {
    row.children[0].value = rule.action;
    row.children[1].value = rule.cidr;
  }
  row.children[2].addEventListener('click', () => row.remove());
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
    const cidr = row.children[1].value.trim();
    if (cidr) rules.push({ action: row.children[0].value, cidr });
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
  const streams = await api('GET', '/api/streams');
  const body = $('streams-body');
  body.innerHTML = '';
  $('streams-empty').hidden = streams.length > 0;
  for (const s of streams) {
    const tr = document.createElement('tr');
    const tdListen = document.createElement('td');
    tdListen.className = 'domain';
    tdListen.textContent = `:${s.listenPort}`;
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
  $('s-proto').value = s ? s.protocol : 'tcp';
  $('s-fhost').value = s ? s.forwardHost : '';
  $('s-fport').value = s ? s.forwardPort : '';
  $('s-cidrs').value = s && s.allowedCidrs ? s.allowedCidrs.join('\n') : '';
  $('s-enabled').checked = s ? s.enabled : true;
  $('stream-modal').hidden = false;
}

$('btn-add-stream').addEventListener('click', () => openStreamModal(null));
$('stream-modal-close').addEventListener('click', () => { $('stream-modal').hidden = true; });
$('stream-btn-cancel').addEventListener('click', () => { $('stream-modal').hidden = true; });

$('stream-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  setError('stream-error', null);
  const s = {
    listenPort: parseInt($('s-port').value, 10),
    protocol: $('s-proto').value,
    forwardHost: $('s-fhost').value.trim(),
    forwardPort: parseInt($('s-fport').value, 10),
    allowedCidrs: $('s-cidrs').value.split('\n').map((v) => v.trim()).filter(Boolean),
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

boot();
