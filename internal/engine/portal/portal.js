// The VPN portal page. It talks only to /.qg/vpn/api on this host. A device's
// private key is made here and never sent anywhere.
'use strict';
const $ = (id) => document.getElementById(id);
let me = null;

async function api(method, path, body) {
  const res = await fetch('/.qg/vpn/api' + path, {
    method,
    credentials: 'same-origin',
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) { const err = new Error(data.error || res.statusText); err.status = res.status; throw err; }
  return data;
}

function when(ts) {
  if (!ts || String(ts).startsWith('0001')) return 'never';
  const d = new Date(ts);
  const sec = Math.round((Date.now() - d.getTime()) / 1000);
  if (sec >= 0 && sec < 90) return 'just now';
  if (sec >= 0 && sec < 5400) return Math.round(sec / 60) + ' min ago';
  return d.toLocaleString();
}

async function canMakeKeys() {
  try {
    if (!window.isSecureContext || !crypto.subtle) return false;
    await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    return true;
  } catch (err) { return false; }
}

const b64 = (bytes) => btoa(String.fromCharCode(...bytes));

async function makeKeypair() {
  const kp = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const pub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
  return { privateKey: b64(pkcs8.slice(-32)), publicKey: b64(pub) };
}

function render() {
  $('who').textContent = me.email;
  const lease = me.lease || {};
  const box = $('lease');
  box.textContent = '';
  const p = document.createElement('p');
  if (lease.live) {
    p.textContent = 'Your access is active. quicgate keeps checking with your identity provider; you have to log in here again by ' + new Date(lease.hardUntil).toLocaleString() + '.';
  } else {
    p.className = 'error';
    p.textContent = 'Your access has run out. Log in again to get your devices back: their configuration stays the same.';
    const a = document.createElement('a');
    a.className = 'btn primary';
    a.href = '/.qg/vpn/login';
    a.textContent = 'Log in again';
    box.append(p, a);
  }
  if (lease.live) box.append(p);
  if ((me.routes || []).length) {
    const r = document.createElement('p');
    r.className = 'muted';
    r.textContent = 'On the VPN you can reach: ' + me.routes.map((x) => x.cidr + (x.ports ? ' (' + (x.proto || 'any') + ' ' + x.ports + ')' : '')).join(', ') + ', and the services this server hosts.';
    box.append(r);
  }

  const body = $('devices').querySelector('tbody');
  body.textContent = '';
  $('devices-empty').hidden = me.devices.length > 0;
  $('devices').hidden = me.devices.length === 0;
  for (const d of me.devices) {
    const tr = document.createElement('tr');
    const cell = (text, cls) => { const td = document.createElement('td'); td.textContent = text; if (cls) td.className = cls; tr.append(td); return td; };
    cell(d.name);
    cell(d.address, 'mono');
    cell(d.connected ? when(d.lastHandshake) + (d.lastEndpoint ? ' from ' + d.lastEndpoint.replace(/:\d+$/, '') : '') : 'not connected', 'muted');
    const td = cell('');
    const rm = document.createElement('button');
    rm.className = 'btn danger';
    rm.type = 'button';
    rm.textContent = 'Remove';
    rm.addEventListener('click', async () => {
      if (!confirm('Remove ' + d.name + '? Its configuration stops working at once and cannot be used again.')) return;
      try { await api('DELETE', '/devices/' + d.id); await load(); } catch (err) { alert(err.message); }
    });
    td.append(rm);
    body.append(tr);
  }
  $('add-card').hidden = me.devices.length >= me.limit || !lease.live;
}

async function load() {
  try {
    me = await api('GET', '/me');
    $('view-login').hidden = true;
    $('view-main').hidden = false;
    render();
  } catch (err) {
    $('view-login').hidden = false;
    $('view-main').hidden = true;
  }
}

function syncKeyMode() { $('pubkey-row').hidden = !$('mode-paste').checked; }
$('mode-generate').addEventListener('change', syncKeyMode);
$('mode-paste').addEventListener('change', syncKeyMode);

$('add-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errBox = $('add-error');
  errBox.hidden = true;
  try {
    let privateKey = '';
    let publicKey = $('d-pubkey').value.trim();
    if ($('mode-generate').checked) {
      const kp = await makeKeypair();
      privateKey = kp.privateKey;
      publicKey = kp.publicKey;
    }
    const d = await api('POST', '/devices', { name: $('d-name').value.trim(), publicKey });
    const s = me.server || {};
    const allowed = [s.address + '/32'].concat((me.routes || []).map((r) => r.cidr));
    $('config').value = [
      '[Interface]',
      'PrivateKey = ' + (privateKey || '(keep the private key that is in your WireGuard app)'),
      'Address = ' + d.address + '/32',
      'DNS = ' + s.address,
      '',
      '[Peer]',
      'PublicKey = ' + s.publicKey,
      'PresharedKey = ' + d.presharedKey,
      'Endpoint = ' + (s.endpoint || '(ask the administrator for the server address)'),
      'AllowedIPs = ' + [...new Set(allowed)].join(', '),
      'PersistentKeepalive = 25',
      '',
    ].join('\n');
    $('config-note').textContent = privateKey ? '' : 'You pasted a public key, so this page does not know the private key: enter these values into the tunnel you made in the app.';
    $('btn-download').dataset.name = (d.name || 'vpn').replace(/[^A-Za-z0-9_-]+/g, '-').slice(0, 15) || 'vpn';
    $('config-card').hidden = false;
    $('add-card').hidden = true;
    $('add-form').reset();
    syncKeyMode();
  } catch (err) {
    errBox.textContent = err.message;
    errBox.hidden = false;
  }
});

$('btn-copy').addEventListener('click', async () => {
  const ta = $('config');
  try { await navigator.clipboard.writeText(ta.value); } catch (err) { ta.select(); document.execCommand('copy'); }
  $('btn-copy').textContent = 'Copied';
  setTimeout(() => { $('btn-copy').textContent = 'Copy'; }, 1500);
});
$('btn-download').addEventListener('click', () => {
  const url = URL.createObjectURL(new Blob([$('config').value], { type: 'text/plain' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = $('btn-download').dataset.name + '.conf';
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
$('btn-done').addEventListener('click', async () => {
  $('config').value = ''; // it holds keys: it does not stay in the page
  $('config-card').hidden = true;
  await load();
});
$('btn-logout').addEventListener('click', async () => { try { await api('POST', '/logout', {}); } catch (err) { /* gone already */ } await load(); });
$('btn-disconnect').addEventListener('click', async () => {
  if (!confirm('Disconnect all your devices? They stop working until you log in here again.')) return;
  try { await api('POST', '/disconnect', {}); await load(); } catch (err) { alert(err.message); }
});

(async () => {
  const can = await canMakeKeys();
  $('key-generate').hidden = !can;
  $('mode-generate').checked = can;
  $('mode-paste').checked = !can;
  syncKeyMode();
  await load();
})();
