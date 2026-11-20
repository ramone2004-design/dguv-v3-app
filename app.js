'use strict';
/*
 * DGUV-V3 Prüfungen
 *
 * Sicherheit:
 * - Alle Kundendaten, Fotos und Dokumente werden mit AES-256-GCM verschlüsselt – im Browser und in Google Drive.
 * - Der Datenschlüssel ist mit dem App-Passwort geschützt (PBKDF2-SHA-256, 600.000 Runden) und liegt
 *   unverschlüsselt nur im Arbeitsspeicher, solange die App entsperrt ist.
 * - Nach 10 Minuten ohne Bedienung sperrt sich die App selbst.
 */

// Nicht in fremde Seiten einbetten lassen (Schutz vor untergeschobenen Klicks)
if (window.top !== window.self) { document.documentElement.innerHTML = ''; throw new Error('Einbettung nicht erlaubt'); }

const KEY_ALT = 'dguv-v3-daten';          // frühere, unverschlüsselte Ablage
const KEY = 'dguv-v3-daten-enc';           // verschlüsselte Daten
const SKEY = 'dguv-v3-schluessel';         // mit dem Passwort geschützter Datenschlüssel
const FKEY = 'dguv-v3-fehlversuche';
const DKEY = 'dguv-v3-dateien-verschluesselt';
const SPERRE_MINUTEN = 10;
const PBKDF2_RUNDEN = 600000;
const MIN_PASSWORT = 10;

const KATS = [
  { id: 'verteilungen', name: 'Verteilungen', einzahl: 'Verteilung', icon: '⚡', intervall: 48 },
  { id: 'maschinen',    name: 'Maschinen',    einzahl: 'Maschine',   icon: '⚙️', intervall: 12 },
  { id: 'tore',         name: 'Tore',         einzahl: 'Tor',        icon: '🚪', intervall: 12 },
  { id: 'kraene',       name: 'Kräne',        einzahl: 'Kran',       icon: '🏗️', intervall: 12 },
];

const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
const lesenJson = k => { try { return JSON.parse(localStorage.getItem(k)); } catch (e) { return null; } };

let db = null;      // Daten – erst nach dem Entsperren vorhanden
let dek = null;     // Datenschlüssel – nur im Arbeitsspeicher
let schluessel = lesenJson(SKEY);   // { v, id, salt, iter, wrapped, geaendert }

// Ältere Daten: einzelnes "Ergebnis: Mangel" wird zu einem Eintrag in der Mängelliste
function migrieren(d) {
  d.kunden.forEach(k => k.gebaeude.forEach(g => g.items.forEach(it => {
    if (!Array.isArray(it.maengel)) {
      it.maengel = it.ergebnis === 'mangel'
        ? [{ id: uid(), text: it.bemerkung || 'Mangel festgestellt', datum: it.letztePruefung || '', behoben: false }] : [];
    }
    delete it.ergebnis;
  })));
  return d;
}

/* ---------- Verschlüsselung ---------- */
const te = new TextEncoder(), td = new TextDecoder();
function zuB64(buf) {
  const b = new Uint8Array(buf); let s = '';
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
  return btoa(s);
}
function vonB64(s) {
  const bin = atob(s), b = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
  return b;
}
async function kekAus(passwort, salt, runden) {
  const basis = await crypto.subtle.importKey('raw', te.encode(passwort), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: runden, hash: 'SHA-256' },
    basis, { name: 'AES-KW', length: 256 }, false, ['wrapKey', 'unwrapKey']);
}
async function schluesselVerpacken(dekExportierbar, passwort, alt) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const kek = await kekAus(passwort, salt, PBKDF2_RUNDEN);
  const wrapped = await crypto.subtle.wrapKey('raw', dekExportierbar, kek, 'AES-KW');
  return { v: 1, id: alt?.id || uid(), salt: zuB64(salt), iter: PBKDF2_RUNDEN, wrapped: zuB64(wrapped), geaendert: Date.now() };
}
// Liefert den Datenschlüssel; wirft bei falschem Passwort
async function schluesselOeffnen(s, passwort, exportierbar = false) {
  const kek = await kekAus(passwort, vonB64(s.salt), s.iter);
  return crypto.subtle.unwrapKey('raw', vonB64(s.wrapped), kek, 'AES-KW',
    { name: 'AES-GCM', length: 256 }, exportierbar, ['encrypt', 'decrypt']);
}
async function verschluesseln(bytes, key = dek) {
  if (!key) throw new Error('gesperrt');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes));
  const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12);
  return out;
}
async function entschluesseln(bytes, key = dek) {
  if (!key) throw new Error('gesperrt');
  const b = new Uint8Array(bytes);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b.subarray(0, 12) }, key, b.subarray(12)));
}
const jsonVer = (o, key) => verschluesseln(te.encode(JSON.stringify(o)), key);
const jsonEnt = async (b, key) => JSON.parse(td.decode(await entschluesseln(b, key)));

/* ---------- Dateien (Fotos, Dokumente) – verschlüsselt in IndexedDB ---------- */
const DOKARTEN = [
  { id: 'plan', name: 'Plan' }, { id: 'anleitung', name: 'Anleitung' },
  { id: 'bericht', name: 'Prüfbericht' }, { id: 'sonstiges', name: 'Sonstiges' },
];
const dokArt = (id, kt) => id === 'plan' ? (kt.id === 'verteilungen' ? 'Verteilungsplan' : 'Schaltplan')
  : (DOKARTEN.find(a => a.id === id) || DOKARTEN[3]).name;
let idbP;
function idb() {
  return idbP ||= new Promise((res, rej) => {
    const r = indexedDB.open('dguv-v3-dateien', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('dateien');
    r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
  });
}
async function dateiOp(mode, fn) {
  const d = await idb();
  return new Promise((res, rej) => {
    const tx = d.transaction('dateien', mode), rq = fn(tx.objectStore('dateien'));
    tx.oncomplete = () => res(rq?.result); tx.onerror = tx.onabort = () => rej(tx.error);
  });
}
const dateiRoh = id => dateiOp('readonly', s => s.get(id));
async function dateiPut(id, blob) {
  const daten = await verschluesseln(new Uint8Array(await blob.arrayBuffer()));
  return dateiOp('readwrite', s => s.put({ v: 1, typ: blob.type || '', daten }, id));
}
async function dateiGet(id) {
  const r = await dateiRoh(id);
  if (!r) return null;
  if (r instanceof Blob) return r;   // Altbestand vor der Verschlüsselung
  return new Blob([await entschluesseln(r.daten)], { type: r.typ });
}
const dateiDel = ids => ids.length ? dateiOp('readwrite', s => { ids.forEach(i => s.delete(i)); }) : Promise.resolve();
// Unverschlüsselte Altdateien einmalig verschlüsseln
async function altDateienVerschluesseln() {
  if (localStorage.getItem(DKEY)) return;
  const keys = await dateiOp('readonly', s => s.getAllKeys());
  for (const k of keys) {
    const r = await dateiRoh(k);
    if (r instanceof Blob) await dateiPut(k, r);
  }
  localStorage.setItem(DKEY, '1');
}
// Alle Datei-Einträge unterhalb eines Objekts (Kunde, Gebäudeteil, Bauteil, Mangel)
function dateiEintraege(o, out = []) {
  if (Array.isArray(o)) o.forEach(x => dateiEintraege(x, out));
  else if (o && typeof o === 'object') for (const [k, v] of Object.entries(o)) {
    if ((k === 'fotos' || k === 'dokumente') && Array.isArray(v)) out.push(...v);
    else dateiEintraege(v, out);
  }
  return out;
}
const dateiIds = o => dateiEintraege(o).map(f => f.id);
function typRaten(f) {
  if (f.typ) return f.typ;
  const n = (f.datei || f.name || '').toLowerCase();
  if (n.endsWith('.pdf')) return 'application/pdf';
  if (/\.jpe?g$/.test(n)) return 'image/jpeg';
  if (n.endsWith('.png')) return 'image/png';
  if (n.endsWith('.txt')) return 'text/plain';
  return '';
}
// Datei lokal holen; fehlt sie auf diesem Gerät, aus Google Drive nachladen (bleibt verschlüsselt gespeichert)
async function dateiHolen(id) {
  const lokal = await dateiGet(id);
  if (lokal) return lokal;
  const f = dateiEintraege(db).find(x => x.id === id);
  if (!f?.driveId || !angemeldet()) return null;
  try {
    const bytes = new Uint8Array(await (await drive(`/drive/v3/files/${f.driveId}?alt=media`)).arrayBuffer());
    const klar = await entschluesseln(bytes);   // prüft zugleich, dass die Datei unverändert ist
    const typ = typRaten(f);
    await dateiOp('readwrite', s => s.put({ v: 1, typ, daten: bytes }, id));
    return new Blob([klar], { type: typ });
  } catch (e) { return null; }
}
// Dateien lokal löschen und zum Löschen in Drive vormerken
function dateienEntfernen(eintraege) {
  const driveIds = eintraege.map(f => f.driveId).filter(Boolean);
  if (driveIds.length) { cloud.loeschen = [...(cloud.loeschen || []), ...driveIds]; cloudSave(); syncPlanen(); }
  return dateiDel(eintraege.map(f => f.id));
}
// Handyfotos auf max. 1600 px verkleinern, damit Speicher und Sicherung klein bleiben
async function bildVerkleinern(file) {
  try {
    const bmp = await createImageBitmap(file);
    const f = Math.min(1, 1600 / Math.max(bmp.width, bmp.height));
    const c = document.createElement('canvas');
    c.width = Math.round(bmp.width * f); c.height = Math.round(bmp.height * f);
    c.getContext('2d').drawImage(bmp, 0, 0, c.width, c.height);
    return (await new Promise(r => c.toBlob(r, 'image/jpeg', 0.82))) || file;
  } catch (e) { return file; }
}
async function fotosSpeichern(files) {
  const out = [];
  for (const f of files) {
    const id = uid(), bild = await bildVerkleinern(f);
    await dateiPut(id, bild);
    out.push({ id, name: f.name, typ: bild.type || 'image/jpeg' });
  }
  return out;
}
let bildUrls = [];
async function ladeBilder(root) {
  for (const img of root.querySelectorAll('img[data-file]')) {
    const blob = await dateiHolen(img.dataset.file);
    if (blob && img.isConnected) { const u = URL.createObjectURL(blob); bildUrls.push(u); img.src = u; }
  }
}
navigator.storage?.persist?.();

function heute() { const d = new Date(); return new Date(d - d.getTimezoneOffset() * 6e4).toISOString().slice(0, 10); }
const datumDE = d => d.toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric' });

// Speichern: verschlüsselt, in der Reihenfolge der Aufrufe
let schreibKette = Promise.resolve();
function speichernRoh() {
  if (!dek || !db) return schreibKette;
  const text = JSON.stringify(db), key = dek;
  schreibKette = schreibKette
    .then(async () => localStorage.setItem(KEY, zuB64(await verschluesseln(te.encode(text), key))))
    .catch(() => alert('Speichern fehlgeschlagen. Möglicherweise ist der Speicher des Browsers voll.'));
  return schreibKette;
}
// Jede Änderung bekommt einen Zeitstempel; daran erkennt die Cloud-Synchronisierung, welcher Stand neuer ist
function speichern() { db.stand = Math.max(Date.now(), (db.stand || 0) + 1); speichernRoh(); syncPlanen(); }
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const datum = iso => iso ? iso.split('-').reverse().join('.') : '–';

/* ---------- Prüfstatus ---------- */
function faellig(it) {
  if (!it.letztePruefung) return null;
  const d = new Date(it.letztePruefung + 'T00:00:00');
  d.setMonth(d.getMonth() + (Number(it.intervall) || 12));
  return d;
}
function status(it) {
  if ((it.maengel || []).some(m => !m.behoben)) return 'mangel';
  if (!it.letztePruefung) return 'offen';
  const tage = (faellig(it) - new Date()) / 864e5;
  if (tage < 0) return 'ueberfaellig';
  if (tage <= 30) return 'bald';
  return 'ok';
}
const STATUS = {
  ok:           ['b-ok',   'Geprüft'],
  bald:         ['b-warn', 'Bald fällig'],
  ueberfaellig: ['b-bad',  'Überfällig'],
  mangel:       ['b-bad',  'Mangel'],
  offen:        ['b-open', 'Noch nicht geprüft'],
};
function zusammenfassung(items) {
  const z = { ok: 0, bald: 0, ueberfaellig: 0, mangel: 0, offen: 0 };
  items.forEach(it => z[status(it)]++);
  return z;
}
function badges(items) {
  if (!items.length) return '<div class="badges"><span class="badge b-open">Keine Einträge</span></div>';
  const z = zusammenfassung(items);
  const teile = [];
  if (z.ok) teile.push(`<span class="badge b-ok">${z.ok} geprüft</span>`);
  if (z.bald) teile.push(`<span class="badge b-warn">${z.bald} bald fällig</span>`);
  if (z.ueberfaellig) teile.push(`<span class="badge b-bad">${z.ueberfaellig} überfällig</span>`);
  if (z.mangel) teile.push(`<span class="badge b-bad">${z.mangel} mit Mangel</span>`);
  if (z.offen) teile.push(`<span class="badge b-open">${z.offen} offen</span>`);
  return `<div class="badges">${teile.join('')}</div>`;
}
const alleItems = k => k.gebaeude.flatMap(g => g.items);

/* ---------- Sperre ---------- */
const entsperrt = () => !!dek && !!db;
let letzteAktivitaet = Date.now();
['pointerdown', 'keydown', 'touchstart', 'wheel'].forEach(t =>
  addEventListener(t, () => { letzteAktivitaet = Date.now(); }, { passive: true, capture: true }));
const sperrzeitAbgelaufen = () => Date.now() - letzteAktivitaet > SPERRE_MINUTEN * 6e4;
setInterval(() => { if (entsperrt() && sperrzeitAbgelaufen()) sperren(); }, 20000);

function sperren() {
  dek = null; db = null; fotoZiel = null;
  clearTimeout(syncTimer);
  if (dlg.open) dlg.close();
  render();
}
function fehlStand() { return lesenJson(FKEY) || { n: 0, bis: 0 }; }
async function entsperren(passwort) {
  const f = fehlStand();
  if (Date.now() < f.bis) throw new Error(`Zu viele Fehlversuche. Bitte ${Math.ceil((f.bis - Date.now()) / 1000)} Sekunden warten.`);
  let key;
  try { key = await schluesselOeffnen(schluessel, passwort); }
  catch (e) {
    f.n++;
    if (f.n >= 3) f.bis = Date.now() + Math.min(300, 5 * 2 ** (f.n - 3)) * 1000;   // 5 s, 10 s, 20 s … max. 5 min
    localStorage.setItem(FKEY, JSON.stringify(f));
    throw new Error('Falsches Passwort.');
  }
  localStorage.removeItem(FKEY);
  dek = key;
  await lokaleDatenLaden();
  letzteAktivitaet = Date.now();
  render(); sync();
}
// Verschlüsselte Daten laden; unverschlüsselte Altdaten dabei einmalig übernehmen und verschlüsseln
async function lokaleDatenLaden() {
  const enc = localStorage.getItem(KEY);
  if (enc) db = migrieren(await jsonEnt(vonB64(enc)));
  else {
    const alt = lesenJson(KEY_ALT);
    db = alt && Array.isArray(alt.kunden) ? migrieren(alt) : { kunden: [] };
  }
  await altDateienVerschluesseln();
  await speichernRoh();
  if (localStorage.getItem(KEY)) localStorage.removeItem(KEY_ALT);
}
async function passwortFestlegen(passwort) {
  const dekX = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const s = await schluesselVerpacken(dekX, passwort);
  // erst den geschützten Schlüssel sichern, dann damit verschlüsseln – so geht nie etwas verloren
  localStorage.setItem(SKEY, JSON.stringify(s));
  schluessel = s;
  dek = await crypto.subtle.importKey('raw', await crypto.subtle.exportKey('raw', dekX), 'AES-GCM', false, ['encrypt', 'decrypt']);
  await lokaleDatenLaden();
  letzteAktivitaet = Date.now();
  render(); sync();
}

/* ---------- Routing ---------- */
const app = document.getElementById('app');
const crumbs = document.getElementById('crumbs');
window.addEventListener('hashchange', () => { render(); window.scrollTo(0, 0); });

function render() {
  bildUrls.forEach(u => URL.revokeObjectURL(u)); bildUrls = [];
  const gesperrt = !entsperrt();
  document.body.classList.toggle('gesperrt', gesperrt);
  if (gesperrt) {
    crumbs.innerHTML = ''; document.getElementById('bottom').innerHTML = '';
    return viewSperre();
  }
  const p = location.hash.replace(/^#\/?/, '').split('/').filter(Boolean);
  const kunde = p[0] === 'k' ? db.kunden.find(k => k.id === p[1]) : null;
  const geb = kunde && p[2] === 'g' ? kunde.gebaeude.find(g => g.id === p[3]) : null;
  const kat = geb && p[4] ? KATS.find(k => k.id === p[4]) : null;
  const item = kat && p[5] ? geb.items.find(i => i.id === p[5]) : null;
  if (kat && p[5] && !item) { location.hash = `#/k/${kunde.id}/g/${geb.id}/${kat.id}`; return; }
  // Kategorie-Liste: über alle Kunden (#/liste/x) oder für einen Kunden (#/k/ID/liste/x)
  const listKat = p[0] === 'liste' ? KATS.find(k => k.id === p[1])
    : kunde && p[2] === 'liste' ? KATS.find(k => k.id === p[3]) : null;
  const basis = kunde ? `#/k/${kunde.id}/liste/` : '#/liste/';
  document.getElementById('bottom').innerHTML =
    `<a href="#/" class="${p.length ? '' : 'active'}"><span class="icon">🏠</span>Übersicht</a>` +
    KATS.map(kt => `<a href="${basis}${kt.id}" class="${listKat === kt ? 'active' : ''}"><span class="icon">${kt.icon}</span>${kt.name}</a>`).join('');

  const c = ['<a href="#/">Kunden</a>'];
  if (kunde) c.push(`<a href="#/k/${kunde.id}">${esc(kunde.name)}</a>`);
  if (geb) c.push(`<a href="#/k/${kunde.id}/g/${geb.id}">${esc(geb.name)}</a>`);
  if (kat) c.push(`<a href="#/k/${kunde.id}/g/${geb.id}/${kat.id}">${kat.name}</a>`);
  if (item) c.push(`<span>${esc(item.name)}</span>`);
  if (listKat) c.push(`<span>Alle ${listKat.name}</span>`);
  crumbs.innerHTML = c.join('<span>›</span>');

  if (listKat) viewListe(kunde, listKat);
  else if (item) viewItem(kunde, geb, kat, item);
  else if (kat) viewItems(kunde, geb, kat);
  else if (geb) viewGebaeude(kunde, geb);
  else if (kunde) viewKunde(kunde);
  else viewKunden();
}

/* ---------- Sperrbildschirm und Einrichtung ---------- */
let einrichtungsSchritt = 'start';
function viewSperre() {
  if (schluessel) {
    const f = fehlStand();
    app.innerHTML = `<div class="sperre">
      <div class="schloss">🔒</div><h1>App gesperrt</h1>
      <p class="sub">Gib dein App-Passwort ein, um die Kundendaten zu entschlüsseln.</p>
      <form id="sperrForm">
        <label>App-Passwort<input type="password" name="pw" autocomplete="current-password" required autofocus></label>
        <div class="fehlertext" id="sperrFehler">${f.n >= 3 ? 'Mehrere Fehlversuche – nach jedem weiteren wächst die Wartezeit.' : ''}</div>
        <button class="primary voll" type="submit">Entsperren</button>
      </form>
      <p><button class="link" type="button" id="vergessenBtn">Passwort vergessen?</button></p>
    </div>`;
    const form = document.getElementById('sperrForm');
    form.onsubmit = async e => {
      e.preventDefault();
      const knopf = form.querySelector('button'), feldPw = form.pw;
      knopf.disabled = true; knopf.textContent = 'Prüfe …';
      try { await entsperren(feldPw.value); }
      catch (err) {
        document.getElementById('sperrFehler').textContent = err.message;
        knopf.disabled = false; knopf.textContent = 'Entsperren'; feldPw.value = ''; feldPw.focus();
      }
    };
    document.getElementById('vergessenBtn').onclick = vergessenDialog;
    return;
  }
  if (einrichtungsSchritt === 'passwort') {
    app.innerHTML = `<div class="sperre">
      <div class="schloss">🔑</div><h1>App-Passwort festlegen</h1>
      <p class="sub">Mit diesem Passwort werden alle Kundendaten, Fotos und Dokumente verschlüsselt – auf diesem Gerät und in Google Drive.
        Nimm mindestens ${MIN_PASSWORT} Zeichen, am besten einen Satz, den nur du kennst.</p>
      <form id="pwForm">
        <label>Neues App-Passwort<input type="password" name="pw" autocomplete="new-password" minlength="${MIN_PASSWORT}" required autofocus></label>
        <label>Passwort wiederholen<input type="password" name="pw2" autocomplete="new-password" required></label>
        <label class="haken"><input type="checkbox" name="ok" required>
          <span>Ich habe verstanden: <b>Wenn ich das Passwort vergesse, sind die Daten verloren.</b> Niemand kann es zurücksetzen.</span></label>
        <div class="fehlertext" id="pwFehler"></div>
        <button class="primary voll" type="submit">Passwort festlegen</button>
      </form>
    </div>`;
    const form = document.getElementById('pwForm');
    form.onsubmit = async e => {
      e.preventDefault();
      const fehler = document.getElementById('pwFehler');
      if (form.pw.value.length < MIN_PASSWORT) return fehler.textContent = `Das Passwort muss mindestens ${MIN_PASSWORT} Zeichen haben.`;
      if (form.pw.value !== form.pw2.value) return fehler.textContent = 'Die beiden Passwörter stimmen nicht überein.';
      form.querySelector('button').disabled = true;
      try { await passwortFestlegen(form.pw.value); }
      catch (err) { fehler.textContent = 'Einrichtung fehlgeschlagen: ' + err.message; form.querySelector('button').disabled = false; }
    };
    return;
  }
  app.innerHTML = `<div class="sperre">
    <div class="schloss">🔐</div><h1>Sichere Einrichtung</h1>
    <p class="sub">Die Kundendaten werden ab jetzt mit einem App-Passwort verschlüsselt. Ohne das Passwort kann sie niemand lesen –
      weder jemand mit Zugriff auf dieses Gerät noch Google.</p>
    <div class="fehlertext" id="einrFehler"></div>
    <button class="primary voll" id="einrGoogle">Mit Google anmelden und fortfahren</button>
    <p class="sub klein">Die App prüft dabei, ob du auf einem anderen Gerät schon ein App-Passwort festgelegt hast.</p>
    <p><button class="link" type="button" id="einrOhne">Ohne Google Drive fortfahren</button></p>
  </div>`;
  document.getElementById('einrOhne').onclick = () => { einrichtungsSchritt = 'passwort'; render(); };
  document.getElementById('einrGoogle').onclick = async e => {
    e.target.disabled = true; e.target.textContent = 'Verbinde …';
    try {
      if (!cloud.clientId) { cloud = { clientId: STANDARD_CLIENT_ID, loeschen: [] }; cloudSave(); }
      if (!angemeldet()) await anmelden();
      await ordnerSichern();
      const f = await dateiImOrdner(SCHLUESSEL_NAME, 'id');
      if (f) {
        const s = await driveJson(`/drive/v3/files/${f.id}?alt=media`);
        localStorage.setItem(SKEY, JSON.stringify(s)); schluessel = s;
        cloud.migriert = true; cloudSave();   // Drive ist bereits auf Verschlüsselung umgestellt
      } else einrichtungsSchritt = 'passwort';
      render();
      if (schluessel) document.getElementById('sperrFehler').textContent = 'Gib das App-Passwort ein, das du auf dem anderen Gerät festgelegt hast.';
    } catch (err) {
      document.getElementById('einrFehler').textContent = 'Anmeldung fehlgeschlagen: ' + err.message;
      e.target.disabled = false; e.target.textContent = 'Mit Google anmelden und fortfahren';
    }
  };
}

function vergessenDialog() {
  dlg.innerHTML = `<h2>Passwort vergessen</h2>
    <p>Das App-Passwort lässt sich nicht wiederherstellen – das ist Absicht, sonst wären die Daten nicht wirklich geschützt.
      Ohne Passwort sind die verschlüsselten Daten nicht mehr lesbar.</p>
    <p>Wenn du es sicher nicht mehr weißt, bleibt nur ein Neuanfang:</p>
    <div class="dlg-actions spalte">
      <button class="danger" data-geraet>Nur dieses Gerät zurücksetzen</button>
      <button class="danger" data-alles>Alles löschen – auch in Google Drive</button>
      <button data-close>Abbrechen</button>
    </div>`;
  dlg.querySelector('[data-close]').onclick = () => dlg.close();
  dlg.querySelector('[data-geraet]').onclick = async () => {
    if (prompt('Alle Daten auf DIESEM Gerät werden gelöscht. Die Daten in Google Drive bleiben (verschlüsselt) erhalten.\n\nZum Bestätigen LÖSCHEN eintippen:') !== 'LÖSCHEN') return;
    await geraetZuruecksetzen(); dlg.close(); render();
  };
  dlg.querySelector('[data-alles]').onclick = async () => {
    if (prompt('Alle Daten auf diesem Gerät UND der Ordner „' + ORDNER + '“ in Google Drive werden endgültig gelöscht.\n\nZum Bestätigen LÖSCHEN eintippen:') !== 'LÖSCHEN') return;
    try {
      if (!cloud.clientId) cloud = { clientId: STANDARD_CLIENT_ID, loeschen: [] };
      if (!angemeldet()) await anmelden();
      await ordnerSichern();
      await drive(`/drive/v3/files/${cloud.folderId}`, { method: 'DELETE' });
    } catch (err) {
      if (!confirm('Google Drive konnte nicht geleert werden (' + err.message + ').\nTrotzdem dieses Gerät zurücksetzen?')) return;
    }
    await geraetZuruecksetzen(); dlg.close(); render();
  };
  dlg.classList.remove('breit');
  dlg.showModal();
}
async function geraetZuruecksetzen() {
  [KEY, KEY_ALT, SKEY, FKEY, DKEY].forEach(k => localStorage.removeItem(k));
  await dateiOp('readwrite', s => s.clear());
  cloud = { clientId: cloud.clientId || STANDARD_CLIENT_ID, loeschen: [] }; cloudSave();
  schluessel = null; dek = null; db = null; einrichtungsSchritt = 'start';
}

/* ---------- Ansichten ---------- */
function viewKunden() {
  app.innerHTML = `
    <div class="head"><h1>Kunden</h1><button class="primary" data-act="kunde-neu">+ Kunde</button></div>
    <div class="list">${db.kunden.length ? db.kunden.map(k => `
      <div class="row">
        <a class="main" href="#/k/${k.id}">
          <div class="title">${esc(k.name)}</div>
          <div class="sub">${esc(k.ort || '')}${k.ort ? ' · ' : ''}${k.gebaeude.length} Gebäudeteil${k.gebaeude.length === 1 ? '' : 'e'}</div>
          ${badges(alleItems(k))}
        </a>
        <div class="actions">
          <button class="small" data-act="kunde-edit" data-id="${k.id}">Bearbeiten</button>
          <button class="small danger" data-act="kunde-del" data-id="${k.id}">Löschen</button>
        </div>
      </div>`).join('') : '<div class="empty">Noch kein Kunde angelegt.<br>Lege mit „+ Kunde“ den ersten an.</div>'}
    </div>
    <div class="foot">
      <button class="small" data-act="kunde-import">Kunde aus Importdatei hinzufügen</button>
      <button class="small" data-act="export">Datensicherung exportieren</button>
      <button class="small" data-act="import">Sicherung importieren</button>
      <button class="small" data-act="pw-aendern">App-Passwort ändern</button>
      <span>🔒 Alle Daten sind mit deinem App-Passwort verschlüsselt – auf diesem Gerät und in Google Drive.
        Die App sperrt sich nach ${SPERRE_MINUTEN} Minuten ohne Bedienung.</span>
    </div>`;
}

function viewKunde(k) {
  app.innerHTML = `
    <div class="head"><h1>${esc(k.name)}</h1><button class="primary" data-act="geb-neu">+ Gebäudeteil</button>
      <p>${esc(k.ort || '')}${k.ort ? ' · ' : ''}Übersicht der Gebäudeteile</p></div>
    <div class="list">${k.gebaeude.length ? k.gebaeude.map(g => `
      <div class="row">
        <a class="main" href="#/k/${k.id}/g/${g.id}">
          <div class="title">${esc(g.name)}</div>
          <div class="sub">${KATS.map(kt => `${g.items.filter(i => i.typ === kt.id).length} ${kt.name}`).join(' · ')}</div>
          ${badges(g.items)}
        </a>
        <div class="actions">
          <button class="small" data-act="geb-edit" data-id="${g.id}">Bearbeiten</button>
          <button class="small danger" data-act="geb-del" data-id="${g.id}">Löschen</button>
        </div>
      </div>`).join('') : '<div class="empty">Noch kein Gebäudeteil angelegt.</div>'}
    </div>`;
}

function viewGebaeude(k, g) {
  app.innerHTML = `
    <div class="head"><h1>${esc(g.name)}</h1><p>${esc(k.name)} · Was soll geprüft werden?</p></div>
    <div class="grid4">${KATS.map(kt => {
      const items = g.items.filter(i => i.typ === kt.id);
      return `<a class="tile" href="#/k/${k.id}/g/${g.id}/${kt.id}">
        <div class="icon">${kt.icon}</div>
        <div class="count">${items.length}</div>
        <div class="title">${kt.name}</div>
        ${badges(items)}
      </a>`;
    }).join('')}</div>`;
}

function viewItems(k, g, kt) {
  const items = g.items.filter(i => i.typ === kt.id);
  app.innerHTML = `
    <div class="head"><h1>${kt.icon} ${kt.name}</h1><button class="primary" data-act="item-neu">+ ${kt.einzahl}</button>
      <p>${esc(k.name)} · ${esc(g.name)}</p></div>
    <div class="list">${items.length ? items.map(it => itemRow(k, g, it, false)).join('')
      : `<div class="empty">Noch keine ${kt.name} in diesem Gebäudeteil.</div>`}
    </div>`;
}

function itemRow(k, g, it, mitPfad) {
  const s = status(it), f = faellig(it);
  return `<div class="row">
    <a class="main" href="#/k/${k.id}/g/${g.id}/${it.typ}/${it.id}">
      <div class="title">${esc(it.name)}</div>
      ${mitPfad ? `<div class="sub">${esc(k.name)} · ${esc(g.name)}</div>` : ''}
      <div class="sub">${it.standort ? esc(it.standort) + ' · ' : ''}Letzte Prüfung: ${datum(it.letztePruefung)}${f ? ' · Nächste: ' + datumDE(f) : ''}</div>
      <div class="badges"><span class="badge ${STATUS[s][0]}">${STATUS[s][1]}</span></div>
    </a>
    ${mitPfad ? '' : `<div class="actions">
      <button class="small" data-act="item-edit" data-id="${it.id}">Bearbeiten</button>
      <button class="small danger" data-act="item-del" data-id="${it.id}">Löschen</button>
    </div>`}
  </div>`;
}

// Alle Bauteile einer Kategorie – für einen Kunden oder über alle Kunden
function viewListe(kunde, kt) {
  const rows = (kunde ? [kunde] : db.kunden).flatMap(k => k.gebaeude.flatMap(g =>
    g.items.filter(i => i.typ === kt.id).map(it => itemRow(k, g, it, true))));
  app.innerHTML = `
    <div class="head"><h1>${kt.icon} Alle ${kt.name}</h1>
      <p>${kunde ? esc(kunde.name) + ' · alle Gebäudeteile' : 'Alle Kunden und Gebäudeteile'} · ${rows.length} Einträge</p></div>
    <div class="list">${rows.length ? rows.join('') : `<div class="empty">Keine ${kt.name} vorhanden.</div>`}</div>`;
}

// Statusanzeige eines einzelnen Bauteils
function viewItem(k, g, kt, it) {
  const s = status(it), f = faellig(it), m = it.maengel || [];
  const offen = m.filter(x => !x.behoben).length;
  let rest = 'Noch keine Prüfung eingetragen';
  if (f) {
    const t = Math.ceil((f - new Date()) / 864e5);
    rest = t < 0 ? `seit ${-t} Tag${t === -1 ? '' : 'en'} überfällig` : t === 0 ? 'heute fällig' : `in ${t} Tag${t === 1 ? '' : 'en'}`;
  }
  app.innerHTML = `
    <div class="head"><h1>${kt.icon} ${esc(it.name)}</h1>
      <div class="actions">
        <button data-act="item-edit" data-id="${it.id}">Bearbeiten</button>
        <button class="danger" data-act="item-del" data-id="${it.id}">Löschen</button>
      </div>
      <p>${esc(k.name)} · ${esc(g.name)}${it.standort ? ' · ' + esc(it.standort) : ''}</p></div>
    <div class="cards">
      <div class="card"><div class="label">Status</div>
        <div class="badges"><span class="badge ${STATUS[s][0]}">${STATUS[s][1]}</span></div>
        <div class="sub" style="margin-top:6px">${offen} offene${offen === 1 ? 'r' : ''} M${offen === 1 ? 'angel' : 'ängel'}</div></div>
      <div class="card"><div class="label">Letzte Prüfung</div>
        <div class="big">${datum(it.letztePruefung)}</div>
        <div class="sub">Intervall: ${esc(it.intervall)} Monate</div></div>
      <div class="card"><div class="label">Nächste Prüfung</div>
        <div class="big">${f ? datumDE(f) : '–'}</div>
        <div class="sub">${rest}</div></div>
    </div>
    ${it.bemerkung ? `<div class="card" style="margin-bottom:22px"><div class="label">Bemerkung</div>${esc(it.bemerkung)}</div>` : ''}
    <div class="head"><h2 class="sec">Mängelliste</h2><button class="primary" data-act="mangel-neu">+ Mangel</button></div>
    <div class="list">${m.length ? m.map(x => `
      <div class="row ${x.behoben ? 'erledigt' : ''}">
        <div class="main">
          <div class="title">${esc(x.text)}</div>
          <div class="sub">Festgestellt: ${datum(x.datum)}${x.behoben ? ' · Behoben: ' + datum(x.behobenAm) : ''}</div>
          <div class="badges"><span class="badge ${x.behoben ? 'b-ok' : 'b-bad'}">${x.behoben ? 'Behoben' : 'Offen'}</span></div>
          <div class="fotos">${(x.fotos || []).map(f => `<button class="thumb" title="Foto ansehen" data-act="foto-zeigen" data-id="${esc(f.id)}" data-mangel="${esc(x.id)}"><img data-file="${esc(f.id)}" alt="Foto zum Mangel"></button>`).join('')}</div>
        </div>
        <div class="actions">
          <button class="small" data-act="foto-neu" data-id="${esc(x.id)}">+ Foto</button>
          <button class="small" data-act="mangel-toggle" data-id="${esc(x.id)}">${x.behoben ? 'Wieder öffnen' : 'Als behoben markieren'}</button>
          <button class="small danger" data-act="mangel-del" data-id="${esc(x.id)}">Löschen</button>
        </div>
      </div>`).join('') : '<div class="empty">Keine Mängel erfasst.</div>'}
    </div>
    <div class="head abstand"><h2 class="sec">Dokumente</h2><button class="primary" data-act="dok-neu">+ Dokument</button></div>
    <div class="list">${(it.dokumente || []).length ? [...it.dokumente]
      .sort((a, b) => DOKARTEN.findIndex(x => x.id === a.art) - DOKARTEN.findIndex(x => x.id === b.art))
      .map(d => `
      <div class="row">
        <div class="main">
          <div class="title">${esc(d.name)}</div>
          <div class="sub">${esc(d.datei)} · hinzugefügt ${datum(d.datum)}</div>
          <div class="badges"><span class="badge b-open">${dokArt(d.art, kt)}</span></div>
        </div>
        <div class="actions">
          <button class="small" data-act="dok-open" data-id="${esc(d.id)}">Öffnen</button>
          <button class="small danger" data-act="dok-del" data-id="${esc(d.id)}">Löschen</button>
        </div>
      </div>`).join('') : '<div class="empty">Noch keine Dokumente hinterlegt.<br>Pläne, Anleitungen und Prüfberichte kannst du hier ablegen.</div>'}
    </div>`;
  ladeBilder(app);
}

/* ---------- Dialog ---------- */
const dlg = document.getElementById('dlg');
function formular(titel, felder, onSave, knopfText = 'Speichern') {
  dlg.innerHTML = `<form method="dialog"><h2>${esc(titel)}</h2>${felder}
    <div class="fehlertext" data-fehler></div>
    <div class="dlg-actions"><button type="button" data-close>Abbrechen</button><button class="primary" type="submit">${esc(knopfText)}</button></div></form>`;
  const form = dlg.querySelector('form');
  dlg.querySelector('[data-close]').onclick = () => dlg.close();
  form.onsubmit = async e => {
    e.preventDefault();
    const knopf = form.querySelector('[type=submit]');
    knopf.disabled = true;
    try {
      // Dateifelder nicht in die Daten übernehmen – die holt sich onSave direkt aus dem Formular
      const d = Object.fromEntries([...new FormData(form)].filter(([, v]) => typeof v === 'string'));
      const ergebnis = await onSave(d, form);
      if (ergebnis !== 'ohneSpeichern' && entsperrt()) speichern();
      dlg.close(); render();
    } catch (err) {
      knopf.disabled = false;
      form.querySelector('[data-fehler]').textContent = err.nachricht || 'Speichern fehlgeschlagen. Möglicherweise ist der Speicher des Browsers voll.';
    }
  };
  dlg.classList.remove('breit');
  dlg.showModal();
}
const feld = (label, name, wert = '', extra = '') =>
  `<label>${label}<input name="${name}" value="${esc(wert)}" ${extra}></label>`;
const meldung = text => Object.assign(new Error(text), { nachricht: text });

function kundeForm(k) {
  formular(k ? 'Kunde bearbeiten' : 'Neuer Kunde',
    feld('Name', 'name', k?.name, 'required autofocus') + feld('Ort / Adresse', 'ort', k?.ort),
    d => { if (k) Object.assign(k, d); else db.kunden.push({ id: uid(), gebaeude: [], ...d }); });
}
function gebForm(kunde, g) {
  formular(g ? 'Gebäudeteil bearbeiten' : 'Neuer Gebäudeteil',
    feld('Bezeichnung', 'name', g?.name, 'required autofocus placeholder="z. B. Halle 1"'),
    d => { if (g) Object.assign(g, d); else kunde.gebaeude.push({ id: uid(), items: [], ...d }); });
}
function itemForm(geb, kt, it) {
  const nr = geb.items.filter(i => i.typ === kt.id).length + 1;
  formular(it ? `${kt.einzahl} bearbeiten` : `${kt.einzahl} hinzufügen`,
    feld('Bezeichnung', 'name', it?.name ?? `${kt.einzahl} ${nr}`, 'required autofocus') +
    feld('Standort / Raum', 'standort', it?.standort) +
    `<div class="two">${feld('Letzte Prüfung', 'letztePruefung', it?.letztePruefung, 'type="date"')}
      ${feld('Prüfintervall (Monate)', 'intervall', it?.intervall ?? kt.intervall, 'type="number" min="1" max="120" required')}</div>
    <label>Bemerkung<textarea name="bemerkung">${esc(it?.bemerkung)}</textarea></label>`,
    d => { if (it) Object.assign(it, d); else geb.items.push({ id: uid(), typ: kt.id, maengel: [], ...d }); });
}
function mangelForm(it) {
  formular('Mangel erfassen',
    `<label>Beschreibung<textarea name="text" required autofocus></textarea></label>` +
    feld('Festgestellt am', 'datum', heute(), 'type="date" required') +
    `<label>Fotos (optional)<input type="file" name="fotos" accept="image/*" multiple></label>`,
    async (d, form) => {
      const fotos = await fotosSpeichern(form.querySelector('[name=fotos]').files);
      (it.maengel ||= []).push({ id: uid(), behoben: false, fotos, ...d });
    });
}
function dokForm(it, kt) {
  formular('Dokument hinzufügen',
    `<label>Art<select name="art">${DOKARTEN.map(a => `<option value="${a.id}">${dokArt(a.id, kt)}</option>`).join('')}</select></label>
     <label>Datei (PDF, Bild …)<input type="file" name="datei" required></label>` +
    feld('Bezeichnung (optional)', 'name', '', 'placeholder="sonst der Dateiname"'),
    async (d, form) => {
      const f = form.querySelector('[name=datei]').files[0], id = uid();
      await dateiPut(id, f);
      (it.dokumente ||= []).push({ id, art: d.art, name: d.name.trim() || f.name, datei: f.name, typ: f.type || '', datum: heute() });
    });
}
// Nur Formate, die keinen Programmcode ausführen können, werden im Browser angezeigt; alles andere wird heruntergeladen
const SICHER_ANZEIGEN = /^(application\/pdf|image\/(png|jpeg|gif|webp)|text\/plain)$/;
async function dokOeffnen(id) {
  const f = dateiEintraege(db).find(x => x.id === id);
  const anzeigen = SICHER_ANZEIGEN.test(typRaten(f || {}));
  const w = anzeigen ? window.open('', '_blank') : null;   // sofort öffnen, sonst blockt der Popup-Schutz
  const blob = await dateiHolen(id);
  if (!blob) { w?.close(); return alert('Die Datei ist auf diesem Gerät nicht vorhanden. Melde dich bei Google Drive an, um sie zu laden.'); }
  if (anzeigen && SICHER_ANZEIGEN.test(blob.type)) {
    const url = URL.createObjectURL(blob);
    if (w) w.location = url; else location.href = url;
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  } else {
    w?.close();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([blob], { type: 'application/octet-stream' }));
    a.download = f?.datei || 'dokument';
    a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 60000);
  }
}
async function fotoDialog(mangel, fid) {
  const blob = await dateiHolen(fid);
  const url = blob ? URL.createObjectURL(blob) : '';
  if (url) bildUrls.push(url);
  dlg.innerHTML = `${url ? `<img class="gross" src="${url}" alt="Foto zum Mangel">` : '<p>Foto auf diesem Gerät nicht gefunden.</p>'}
    <div class="dlg-actions"><button class="danger" data-del>Foto löschen</button><button class="primary" data-close>Schließen</button></div>`;
  dlg.querySelector('[data-close]').onclick = () => dlg.close();
  dlg.querySelector('[data-del]').onclick = async () => {
    if (!confirm('Dieses Foto löschen?')) return;
    const weg = mangel.fotos.filter(f => f.id === fid);
    mangel.fotos = mangel.fotos.filter(f => f.id !== fid);
    speichern(); await dateienEntfernen(weg); dlg.close(); render();
  };
  dlg.classList.add('breit');
  dlg.showModal();
}
let fotoZiel = null;
document.getElementById('fotoFile').addEventListener('change', async e => {
  const files = [...e.target.files]; e.target.value = '';
  if (!files.length || !fotoZiel || !entsperrt()) return;
  try {
    (fotoZiel.fotos ||= []).push(...await fotosSpeichern(files));
    speichern(); render();
  } catch (err) { alert('Foto konnte nicht gespeichert werden. Möglicherweise ist der Speicher des Browsers voll.'); }
});

function passwortAendernForm() {
  formular('App-Passwort ändern',
    `<label>Bisheriges Passwort<input type="password" name="alt" autocomplete="current-password" required autofocus></label>
     <label>Neues Passwort (mind. ${MIN_PASSWORT} Zeichen)<input type="password" name="neu" autocomplete="new-password" minlength="${MIN_PASSWORT}" required></label>
     <label>Neues Passwort wiederholen<input type="password" name="neu2" autocomplete="new-password" required></label>
     <p class="sub">Auf deinen anderen Geräten gilt das neue Passwort, sobald sie das nächste Mal mit Google Drive abgeglichen haben.</p>`,
    async d => {
      if (d.neu.length < MIN_PASSWORT) throw meldung(`Das neue Passwort muss mindestens ${MIN_PASSWORT} Zeichen haben.`);
      if (d.neu !== d.neu2) throw meldung('Die beiden neuen Passwörter stimmen nicht überein.');
      let dekX;
      try { dekX = await schluesselOeffnen(schluessel, d.alt, true); }
      catch (e) { throw meldung('Das bisherige Passwort ist falsch.'); }
      const s = await schluesselVerpacken(dekX, d.neu, schluessel);
      localStorage.setItem(SKEY, JSON.stringify(s)); schluessel = s;
      syncPlanen();
      alert('Das App-Passwort wurde geändert.');
      return 'ohneSpeichern';   // an den Kundendaten hat sich nichts geändert
    }, 'Passwort ändern');
}
function passwortAbfragen(titel, text) {
  return new Promise((res, rej) => {
    dlg.innerHTML = `<form method="dialog"><h2>${esc(titel)}</h2><p class="sub">${esc(text)}</p>
      <label>Passwort<input type="password" name="pw" required autofocus></label>
      <div class="dlg-actions"><button type="button" data-close>Abbrechen</button><button class="primary" type="submit">Weiter</button></div></form>`;
    const form = dlg.querySelector('form');
    dlg.querySelector('[data-close]').onclick = () => { dlg.close(); rej(meldung('Abgebrochen.')); };
    form.onsubmit = e => { e.preventDefault(); const pw = form.pw.value; dlg.close(); res(pw); };
    dlg.classList.remove('breit');
    dlg.showModal();
  });
}

/* ---------- Aktionen ---------- */
app.addEventListener('click', e => {
  if (!entsperrt()) return;
  const b = e.target.closest('[data-act]'); if (!b) return;
  const p = location.hash.replace(/^#\/?/, '').split('/');
  const kunde = db.kunden.find(k => k.id === p[1]);
  const geb = kunde?.gebaeude.find(g => g.id === p[3]);
  const kt = KATS.find(k => k.id === p[4]);
  const item = geb?.items.find(i => i.id === p[5]);
  const id = b.dataset.id;
  const weg = (liste, text, istDatei = false) => {
    const i = liste.findIndex(x => x.id === id);
    if (i >= 0 && confirm(text(liste[i]))) {
      const dateien = dateiEintraege(liste[i]);   // zugehörige Fotos/Dokumente mit entfernen
      if (istDatei) dateien.push(liste[i]);
      liste.splice(i, 1); speichern(); render(); dateienEntfernen(dateien);
    }
  };
  switch (b.dataset.act) {
    case 'kunde-neu': return kundeForm();
    case 'kunde-edit': return kundeForm(db.kunden.find(k => k.id === id));
    case 'kunde-del': return weg(db.kunden, k => `Kunde „${k.name}“ mit allen Gebäudeteilen und Einträgen löschen?`);
    case 'geb-neu': return gebForm(kunde);
    case 'geb-edit': return gebForm(kunde, kunde.gebaeude.find(g => g.id === id));
    case 'geb-del': return weg(kunde.gebaeude, g => `Gebäudeteil „${g.name}“ mit allen Einträgen löschen?`);
    case 'item-neu': return itemForm(geb, kt);
    case 'item-edit': return itemForm(geb, kt, geb.items.find(i => i.id === id));
    case 'item-del': return weg(geb.items, i => `„${i.name}“ löschen?`);
    case 'mangel-neu': return mangelForm(item);
    case 'mangel-del': return weg(item.maengel, m => `Mangel „${m.text}“ löschen?`);
    case 'foto-neu': fotoZiel = item.maengel.find(x => x.id === id); return document.getElementById('fotoFile').click();
    case 'foto-zeigen': return fotoDialog(item.maengel.find(x => x.id === b.dataset.mangel), id);
    case 'dok-neu': return dokForm(item, kt);
    case 'dok-open': return dokOeffnen(id);
    case 'dok-del': return weg(item.dokumente, d => `Dokument „${d.name}“ löschen?`, true);
    case 'mangel-toggle': {
      const m = item.maengel.find(x => x.id === id);
      m.behoben = !m.behoben; m.behobenAm = m.behoben ? heute() : '';
      speichern(); return render();
    }
    case 'export': return exportieren();
    case 'import': return document.getElementById('importFile').click();
    case 'pw-aendern': return passwortAendernForm();
    case 'kunde-import': return document.getElementById('kundenImportFile').click();
  }
});

/* ---------- Datensicherung (verschlüsselt) ---------- */
const SICHERUNG_FORMAT = 'dguv-v3-sicherung-verschluesselt';
const alsDataUrl = blob => new Promise((res, rej) => {
  const r = new FileReader(); r.onload = () => res(r.result); r.onerror = () => rej(r.error); r.readAsDataURL(blob);
});
async function exportieren() {
  // Fotos und Dokumente werden eingebettet; die ganze Datei ist mit dem App-Passwort verschlüsselt
  const dateien = {};
  for (const id of dateiIds(db)) { const b = await dateiHolen(id); if (b) dateien[id] = await alsDataUrl(b); }
  const inhalt = await jsonVer({ ...db, dateien });
  const datei = { format: SICHERUNG_FORMAT, version: 1, schluessel, daten: zuB64(inhalt) };
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(datei)], { type: 'application/json' }));
  a.download = `dguv-v3-sicherung-${new Date().toISOString().slice(0, 10)}.json`;
  a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 60000);
}
document.getElementById('importFile').addEventListener('change', async e => {
  const f = e.target.files[0]; e.target.value = ''; if (!f || !entsperrt()) return;
  let d;
  try { d = JSON.parse(await f.text()); } catch (err) { return alert('Die Datei ist keine gültige DGUV-V3-Sicherung.'); }
  let inhalt;
  try {
    if (d?.format === SICHERUNG_FORMAT) {
      let key = dek;
      if (d.schluessel?.id !== schluessel.id) {
        const pw = await passwortAbfragen('Passwort der Sicherung',
          'Diese Sicherung wurde mit einem anderen App-Passwort erstellt. Gib das Passwort ein, das beim Erstellen galt.');
        key = await schluesselOeffnen(d.schluessel, pw);
      }
      inhalt = await jsonEnt(vonB64(d.daten), key);
    } else if (Array.isArray(d?.kunden)) inhalt = d;   // ältere, unverschlüsselte Sicherung
    else throw meldung('Die Datei ist keine gültige DGUV-V3-Sicherung.');
  } catch (err) {
    return alert(err.nachricht || 'Die Sicherung konnte nicht entschlüsselt werden. Ist das Passwort richtig?');
  }
  if (!confirm('Die aktuellen Daten werden durch die Sicherung ersetzt. Fortfahren?')) return;
  try {
    const dateien = inhalt.dateien || {}; delete inhalt.dateien;
    for (const [id, url] of Object.entries(dateien)) await dateiPut(id, await (await fetch(url)).blob());
    // alte Drive-Dateien entfernen; die Dateien der Sicherung werden neu (verschlüsselt) hochgeladen
    const alteDriveIds = dateiEintraege(db).map(x => x.driveId).filter(Boolean);
    if (alteDriveIds.length) { cloud.loeschen = [...(cloud.loeschen || []), ...alteDriveIds]; cloudSave(); }
    dateiEintraege(inhalt).forEach(x => delete x.driveId);
    db = migrieren(inhalt); speichern(); location.hash = '#/'; render();
  } catch (err) { alert('Die Sicherung konnte nicht vollständig eingelesen werden.'); }
});

/* ---------- Kunden aus einer Importdatei hinzufügen (ergänzt, ersetzt nichts) ---------- */
const KUNDEN_IMPORT_FORMAT = 'dguv-v3-kunden-import';
const text = (v, max = 500) => String(v ?? '').trim().slice(0, max);
const isoDatum = v => /^\d{4}-\d{2}-\d{2}$/.test(v) ? v : '';
// Nur bekannte Felder übernehmen und überall neue IDs vergeben – so kann eine Datei auch zweimal eingelesen werden
function importKunde(k) {
  if (!text(k?.name) || !Array.isArray(k.gebaeude)) throw new Error('ungültig');
  return {
    id: uid(), name: text(k.name, 200), ort: text(k.ort, 200),
    gebaeude: k.gebaeude.map(g => ({
      id: uid(), name: text(g.name, 200) || 'Ohne Bezeichnung',
      items: (Array.isArray(g.items) ? g.items : []).filter(it => KATS.some(kt => kt.id === it.typ)).map(it => ({
        id: uid(), typ: it.typ, name: text(it.name, 200) || 'Ohne Bezeichnung', standort: text(it.standort, 200),
        letztePruefung: isoDatum(it.letztePruefung),
        intervall: String(Math.min(120, Math.max(1, parseInt(it.intervall, 10) || KATS.find(kt => kt.id === it.typ).intervall))),
        bemerkung: text(it.bemerkung, 2000), maengel: [], dokumente: [],
      })),
    })),
  };
}
document.getElementById('kundenImportFile').addEventListener('change', async e => {
  const f = e.target.files[0]; e.target.value = ''; if (!f || !entsperrt()) return;
  let neu;
  try {
    const d = JSON.parse(await f.text());
    if (d?.format !== KUNDEN_IMPORT_FORMAT || !Array.isArray(d.kunden) || !d.kunden.length) throw new Error();
    neu = d.kunden.map(importKunde);
  } catch (err) { return alert('Die Datei ist keine gültige Importdatei für Kunden.'); }
  for (const k of neu) {
    const items = k.gebaeude.flatMap(g => g.items);
    const zahlen = KATS.map(kt => `${items.filter(i => i.typ === kt.id).length} ${kt.name}`).join(', ');
    const umfang = `${k.gebaeude.length} Gebäudeteile, ${zahlen}`;
    const alt = db.kunden.find(x => x.name.trim().toLowerCase() === k.name.toLowerCase());
    let aktion = 'neu';
    if (alt) {
      aktion = await auswahlDialog(`Kunde „${k.name}“ gibt es schon`,
        `Die Importdatei enthält ${umfang}.\n\n„Ersetzen“ baut den Kunden nach der neuen Liste auf. Mängel, Fotos und Dokumente, ` +
        `die du in der App erfasst hast, werden zu den passenden Geräten übernommen – ebenso neuere Prüfdaten aus der App.`,
        [{ wert: 'ersetzen', label: 'Ersetzen', klasse: 'primary' }, { wert: 'neu', label: 'Zusätzlich anlegen' }, { wert: 'abbrechen', label: 'Abbrechen' }]);
    } else if (!confirm(`Kunde „${k.name}“ hinzufügen?\n\n${umfang}\n\nDeine übrigen Kunden bleiben unverändert.`)) aktion = 'abbrechen';
    if (aktion === 'abbrechen') continue;
    if (aktion === 'ersetzen') {
      const b = kundeErsetzen(alt, k);
      db.kunden[db.kunden.indexOf(alt)] = k;
      alert(`Kunde „${k.name}“ wurde nach der neuen Liste aufgebaut.\n\n` +
        `• ${b.uebernommen} Geräte mit Mängeln, Dokumenten oder neuerem Prüfdatum aus der App übernommen` +
        (b.geparkt ? `\n• ${b.geparkt} Geräte mit Mängeln oder Dokumenten passten zu keinem Gerät der neuen Liste – sie stehen im Gebäudeteil „${PARKPLATZ}“` : '') +
        (b.weg ? `\n• ${b.weg} Geräte ohne eigene Einträge, die in der neuen Liste nicht mehr vorkommen, wurden entfernt` : ''));
    } else db.kunden.push(k);
    speichern();
    location.hash = '#/k/' + k.id;
  }
  render();
});

// Bestehenden Kunden durch die neue Liste ersetzen, ohne in der App erfasste Daten zu verlieren
const PARKPLATZ = 'Nicht zugeordnet (alte Liste)';
function kundeErsetzen(alt, neu) {
  neu.id = alt.id; neu.ort ||= alt.ort;
  const ort = (it, g) => (it.standort || g.name || '').trim().toLowerCase();
  const name = it => it.name.trim().toLowerCase();
  const altListe = alt.gebaeude.flatMap(g => g.items.map(it => ({ it, ort: ort(it, g), frei: true })));
  const hatDaten = it => (it.maengel || []).length || (it.dokumente || []).length;
  const b = { uebernommen: 0, geparkt: 0, weg: 0 };
  const neuListe = neu.gebaeude.flatMap(g => g.items.map(it => ({ it, ort: ort(it, g), treffer: null })));
  // Durchgang 1: gleiches Gerät am gleichen Ort
  for (const n of neuListe) {
    n.treffer = altListe.find(a => a.frei && a.it.typ === n.it.typ && name(a.it) === name(n.it) && a.ort === n.ort) || null;
    if (n.treffer) n.treffer.frei = false;
  }
  // Durchgang 2: übrige Geräte nur zuordnen, wenn der Name auf beiden Seiten eindeutig ist
  for (const n of neuListe.filter(x => !x.treffer)) {
    const passt = x => x.it.typ === n.it.typ && name(x.it) === name(n.it);
    const kandidaten = altListe.filter(a => a.frei && passt(a));
    if (kandidaten.length === 1 && neuListe.filter(x => !x.treffer && passt(x)).length === 1) { n.treffer = kandidaten[0]; n.treffer.frei = false; }
  }
  for (const { it, treffer } of neuListe) {
    if (!treffer) continue;
    const a = treffer.it;
    let geaendert = false;
    if (hatDaten(a)) { it.maengel = a.maengel || []; it.dokumente = a.dokumente || []; geaendert = true; }
    if (a.letztePruefung && a.letztePruefung > (it.letztePruefung || '')) { it.letztePruefung = a.letztePruefung; it.intervall = a.intervall; geaendert = true; }
    if (a.bemerkung && !it.bemerkung.includes(a.bemerkung)) it.bemerkung = [it.bemerkung, a.bemerkung].filter(Boolean).join(' · ');
    if (geaendert) b.uebernommen++;
  }
  const rest = altListe.filter(a => a.frei);
  const behalten = rest.filter(a => hatDaten(a.it)).map(a => a.it);
  b.geparkt = behalten.length; b.weg = rest.length - behalten.length;
  if (behalten.length) neu.gebaeude.push({ id: uid(), name: PARKPLATZ, items: behalten });
  return b;
}
function auswahlDialog(titel, text, optionen) {
  return new Promise(res => {
    dlg.innerHTML = `<h2>${esc(titel)}</h2><p class="sub" style="white-space:pre-line">${esc(text)}</p>
      <div class="dlg-actions">${optionen.map((o, i) => `<button class="${o.klasse || ''}" data-i="${i}">${esc(o.label)}</button>`).join('')}</div>`;
    dlg.querySelectorAll('[data-i]').forEach(b => b.onclick = () => { dlg.oncancel = null; dlg.close(); res(optionen[b.dataset.i].wert); });
    dlg.oncancel = () => { dlg.oncancel = null; res('abbrechen'); };
    dlg.classList.remove('breit');
    dlg.showModal();
  });
}

/* ---------- Google Drive: verschlüsselte Daten und Dateien im Ordner "DGUV-V3 App" ---------- */
const CKEY = 'dguv-v3-cloud', TKEY = 'dguv-v3-token', ORDNER = 'DGUV-V3 App';
const DATEN_NAME = 'daten.enc', SCHLUESSEL_NAME = 'schluessel.json';
// cloud = { clientId, folderId, dataId, basis (Stand der letzten Synchronisierung), loeschen: [driveIds], migriert }
// Client-ID des Google-Cloud-Projekts "DGUV-V3 App" (kein Geheimnis; nur für die eingetragenen Adressen gültig)
const STANDARD_CLIENT_ID = '320985002204-p6bduac3buscdah9u36qn995r9i4ha7c.apps.googleusercontent.com';
let cloud = lesenJson(CKEY) || { clientId: STANDARD_CLIENT_ID, loeschen: [] };
function cloudSave() { localStorage.setItem(CKEY, JSON.stringify(cloud)); }
let token = null, tokenBis = 0, syncLaeuft = false, syncNochmal = false, syncTimer, cloudFehler = '';
try {
  const t = JSON.parse(sessionStorage.getItem(TKEY));
  if (t && t.bis > Date.now() + 60000) { token = t.token; tokenBis = t.bis; }
} catch (e) {}
function angemeldet() { return !!token && tokenBis > Date.now() + 30000; }

const cloudBtn = document.getElementById('cloudBtn');
function setStatus(s, text = '') {
  cloudFehler = s === 'fehler' ? text : '';
  cloudBtn.className = 'small ' + s;
  cloudBtn.textContent = { aus: '☁ Cloud einrichten', abgemeldet: '☁ Anmelden', sync: '☁ Synchronisiere …', ok: '☁ Synchron', fehler: '☁ Fehler' }[s];
  cloudBtn.title = text;
}

let gisP;
function gisLaden() {
  return gisP ||= new Promise((res, rej) => {
    const s = document.createElement('script');
    s.src = 'https://accounts.google.com/gsi/client';
    s.onload = res;
    s.onerror = () => { gisP = null; rej(new Error('Google-Anmeldung konnte nicht geladen werden (keine Internetverbindung?).')); };
    document.head.append(s);
  });
}
async function anmelden() {
  await gisLaden();
  const r = await new Promise((res, rej) => {
    google.accounts.oauth2.initTokenClient({
      client_id: cloud.clientId,
      scope: 'https://www.googleapis.com/auth/drive.file',   // nur Dateien, die diese App selbst angelegt hat
      callback: res,
      error_callback: e => rej(new Error(e.message || 'Anmeldung abgebrochen.')),
    }).requestAccessToken();
  });
  if (r.error) throw new Error(r.error_description || r.error);
  token = r.access_token; tokenBis = Date.now() + r.expires_in * 1000;
  sessionStorage.setItem(TKEY, JSON.stringify({ token, bis: tokenBis }));
}

async function drive(pfad, opt = {}) {
  if (!angemeldet()) throw new Error('abgemeldet');
  const r = await fetch('https://www.googleapis.com' + pfad, { ...opt, headers: { Authorization: 'Bearer ' + token, ...(opt.headers || {}) } });
  if (r.status === 401) { token = null; sessionStorage.removeItem(TKEY); throw new Error('abgemeldet'); }
  if (!r.ok) { const e = new Error('Google Drive meldet Fehler ' + r.status + '.'); e.status = r.status; throw e; }
  return r;
}
async function driveJson(pfad, opt) { return (await drive(pfad, opt)).json(); }
// Neue Datei anlegen (ohne id) oder bestehende ersetzen (mit id)
async function driveUpload(blob, meta, id) {
  const ziel = `/upload/drive/v3/files${id ? '/' + id : ''}`, method = id ? 'PATCH' : 'POST';
  if (blob.size < 4.5e6) {
    const f = new FormData();
    f.append('metadata', new Blob([JSON.stringify(meta)], { type: 'application/json' }));
    f.append('file', blob);
    return driveJson(`${ziel}?uploadType=multipart&fields=id`, { method, body: f });
  }
  // Große Dateien: zweistufiger Upload
  const start = await drive(`${ziel}?uploadType=resumable&fields=id`, { method, body: JSON.stringify(meta),
    headers: { 'Content-Type': 'application/json; charset=UTF-8', 'X-Upload-Content-Type': meta.mimeType || 'application/octet-stream' } });
  const r = await fetch(start.headers.get('Location'), { method: 'PUT', body: blob });
  if (!r.ok) throw new Error('Upload fehlgeschlagen (' + r.status + ').');
  return r.json();
}
const binaer = bytes => new Blob([bytes], { type: 'application/octet-stream' });

async function ordnerSichern() {
  if (cloud.folderId) {
    try { if (!(await driveJson(`/drive/v3/files/${cloud.folderId}?fields=id,trashed`)).trashed) return; }
    catch (e) { if (e.status !== 404) throw e; }
    cloud.folderId = cloud.dataId = null;
  }
  const q = encodeURIComponent(`name='${ORDNER}' and mimeType='application/vnd.google-apps.folder' and trashed=false`);
  const gefunden = (await driveJson(`/drive/v3/files?q=${q}&fields=files(id)`)).files[0];
  cloud.folderId = gefunden?.id || (await driveJson('/drive/v3/files?fields=id', { method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: ORDNER, mimeType: 'application/vnd.google-apps.folder' }) })).id;
  cloudSave();
}
async function dateiImOrdner(name, felder = 'id,appProperties') {
  const q = encodeURIComponent(`name='${name}' and '${cloud.folderId}' in parents and trashed=false`);
  return (await driveJson(`/drive/v3/files?q=${q}&fields=files(${felder})`)).files[0] || null;
}
// Den passwortgeschützten Schlüssel in Drive ablegen bzw. mit dem dortigen abgleichen
async function schluesselAbgleichen() {
  const neuHochladen = () => driveUpload(new Blob([JSON.stringify(schluessel)], { type: 'application/json' }),
    { name: SCHLUESSEL_NAME, parents: [cloud.folderId], mimeType: 'application/json' });
  const f = await dateiImOrdner(SCHLUESSEL_NAME, 'id');
  if (!f) { await neuHochladen(); return; }
  const fern = await driveJson(`/drive/v3/files/${f.id}?alt=media`);
  if (fern.id !== schluessel.id) {
    throw new Error('In Google Drive liegen Daten, die mit einem anderen App-Passwort verschlüsselt sind. ' +
      'Dieses Gerät wird deshalb nicht abgeglichen.');
  }
  if ((fern.geaendert || 0) > (schluessel.geaendert || 0)) {
    schluessel = fern; localStorage.setItem(SKEY, JSON.stringify(fern));          // Passwort wurde woanders geändert
  } else if ((schluessel.geaendert || 0) > (fern.geaendert || 0)) {
    await neuHochladen();                                                          // Passwort wurde hier geändert:
    await drive(`/drive/v3/files/${f.id}`, { method: 'DELETE' });                  // alte Fassung ganz entfernen
  }
}
// Einmalig: unverschlüsselte Altdaten in Drive durch verschlüsselte ersetzen
async function altdatenMigrieren() {
  cloud.loeschen ||= [];
  const alt = await dateiImOrdner('daten.json', 'id');
  if (alt) {
    if (!db.kunden.length) db = migrieren(await driveJson(`/drive/v3/files/${alt.id}?alt=media`));
    cloud.loeschen.push(alt.id);
  }
  for (const f of dateiEintraege(db)) {
    if (!f.driveId) continue;
    const rec = await dateiRoh(f.id);
    if (!rec) {
      try {
        const blob = await (await drive(`/drive/v3/files/${f.driveId}?alt=media`)).blob();
        await dateiPut(f.id, blob); f.typ ||= blob.type;
      } catch (e) { if (e.status !== 404) throw e; }
    } else f.typ ||= rec instanceof Blob ? rec.type : rec.typ;
    cloud.loeschen.push(f.driveId);
    delete f.driveId;
  }
  cloud.dataId = null; cloud.basis = 0; cloud.migriert = true;
  db.stand = Math.max(Date.now(), (db.stand || 0) + 1);
  await speichernRoh(); cloudSave(); render();
}
// Stand der Daten in Drive: { id, stand } oder null, wenn noch nichts hochgeladen wurde
async function fernStand() {
  const lesen = f => ({ id: f.id, stand: Number(f.appProperties?.stand) || 0 });
  if (cloud.dataId) {
    try { const f = await driveJson(`/drive/v3/files/${cloud.dataId}?fields=id,trashed,appProperties`); if (!f.trashed) return lesen(f); }
    catch (e) { if (e.status !== 404) throw e; }
  }
  const f = await dateiImOrdner(DATEN_NAME);
  cloud.dataId = f?.id || null;
  return f ? lesen(f) : null;
}
async function dateienHochladen() {
  for (const f of dateiEintraege(db)) {
    if (f.driveId) continue;
    let rec = await dateiRoh(f.id);
    if (rec instanceof Blob) { await dateiPut(f.id, rec); rec = await dateiRoh(f.id); }
    if (!rec) continue;
    // Dateiname in Drive verrät nichts über den Inhalt; der Inhalt ist verschlüsselt
    f.driveId = (await driveUpload(binaer(rec.daten), { name: `${f.id}.bin`, parents: [cloud.folderId], mimeType: 'application/octet-stream' })).id;
    speichernRoh();
  }
}

function syncPlanen() { clearTimeout(syncTimer); if (cloud.clientId && entsperrt()) syncTimer = setTimeout(sync, 1500); }
async function sync() {
  if (!entsperrt()) return;
  if (!cloud.clientId) return setStatus('aus');
  if (!angemeldet()) return setStatus('abgemeldet', 'Zum Synchronisieren bei Google anmelden');
  if (syncLaeuft) { syncNochmal = true; return; }
  syncLaeuft = true; setStatus('sync');
  try {
    await ordnerSichern();
    await schluesselAbgleichen();
    if (!cloud.migriert) await altdatenMigrieren();
    const fern = await fernStand();
    const basis = cloud.basis || 0, lokal = db.stand || 0;
    const fernNeu = !!fern && fern.stand > basis, lokalNeu = lokal > basis;
    let laden = fernNeu && (!lokalNeu || !db.kunden.length);
    if (fernNeu && lokalNeu && db.kunden.length) {
      laden = confirm('Die Daten wurden auf einem anderen Gerät geändert, und auch hier gibt es ungesicherte Änderungen.\n\n' +
        'OK = Stand aus Google Drive laden (Änderungen auf diesem Gerät gehen verloren)\n' +
        'Abbrechen = Stand dieses Geräts hochladen (Änderungen des anderen Geräts gehen verloren)');
    }
    if (laden) {
      const bytes = await (await drive(`/drive/v3/files/${fern.id}?alt=media`)).arrayBuffer();
      db = migrieren(await jsonEnt(bytes));
      db.stand = fern.stand; await speichernRoh();
      cloud.basis = fern.stand; cloudSave(); render();
    } else if (!fern || lokalNeu || fernNeu) {
      await dateienHochladen();
      if (!db.stand) db.stand = Date.now();
      await speichernRoh();
      const stand = db.stand;
      const meta = { name: DATEN_NAME, mimeType: 'application/octet-stream', appProperties: { stand: String(stand) } };
      if (!fern) meta.parents = [cloud.folderId];
      cloud.dataId = (await driveUpload(binaer(await jsonVer(db)), meta, fern?.id)).id;
      cloud.basis = stand; cloudSave();
    }
    for (const id of [...(cloud.loeschen || [])]) {
      try { await drive(`/drive/v3/files/${id}`, { method: 'DELETE' }); } catch (e) { if (e.status !== 404) throw e; }
      cloud.loeschen = cloud.loeschen.filter(x => x !== id); cloudSave();
    }
    setStatus('ok', 'Zuletzt synchronisiert: ' + new Date().toLocaleTimeString('de-DE'));
  } catch (e) {
    if (!entsperrt()) setStatus(angemeldet() ? 'ok' : 'abgemeldet');   // während des Abgleichs gesperrt
    else if (e.message === 'abgemeldet') setStatus('abgemeldet', 'Anmeldung abgelaufen – bitte erneut anmelden');
    else setStatus('fehler', e instanceof TypeError ? 'Keine Verbindung zu Google Drive.' : e.message);
  } finally {
    syncLaeuft = false;
    if (syncNochmal) { syncNochmal = false; sync(); }
  }
}

async function anmeldenUndSync() {
  try { await anmelden(); await sync(); }
  catch (e) { setStatus('fehler', e.message); cloudDialog(); }
}
cloudBtn.onclick = () => (cloud.clientId && !angemeldet()) ? anmeldenUndSync() : cloudDialog();
document.getElementById('lockBtn').onclick = sperren;

function cloudDialog() {
  const an = angemeldet();
  const statusText = !cloud.clientId ? 'Noch nicht eingerichtet. Daten und Dateien liegen nur auf diesem Gerät.'
    : cloudFehler ? 'Fehler: ' + cloudFehler
    : an ? 'Verbunden. Änderungen werden verschlüsselt im Drive-Ordner „' + ORDNER + '“ gesichert.'
    : 'Eingerichtet, aber nicht angemeldet.';
  dlg.innerHTML = `<h2>Google Drive</h2>
    <p class="sub">${esc(statusText)}</p>
    <label>Google Client-ID<input id="cid" value="${esc(cloud.clientId || STANDARD_CLIENT_ID)}" placeholder="….apps.googleusercontent.com" autocomplete="off"></label>
    <div class="dlg-actions">
      ${cloud.clientId ? '<button class="danger" data-trennen>Trennen</button>' : ''}
      <button data-close>Schließen</button>
      <button class="primary" data-los>${an ? 'Jetzt synchronisieren' : 'Mit Google anmelden'}</button>
    </div>`;
  dlg.querySelector('[data-close]').onclick = () => dlg.close();
  dlg.querySelector('[data-los]').onclick = () => {
    const cid = dlg.querySelector('#cid').value.trim();
    if (!cid.endsWith('.apps.googleusercontent.com')) return alert('Das sieht nicht nach einer Client-ID aus. Sie endet auf „.apps.googleusercontent.com“.');
    if (cid !== cloud.clientId) { cloud = { clientId: cid, loeschen: [], migriert: cloud.migriert }; token = null; sessionStorage.removeItem(TKEY); cloudSave(); }
    dlg.close();
    angemeldet() ? sync() : anmeldenUndSync();
  };
  const trennen = dlg.querySelector('[data-trennen]');
  if (trennen) trennen.onclick = () => {
    if (!confirm('Verbindung zu Google Drive trennen? Die Daten bleiben auf diesem Gerät und im Drive-Ordner erhalten.')) return;
    cloud = { migriert: cloud.migriert }; cloudSave(); token = null; sessionStorage.removeItem(TKEY); setStatus('aus'); dlg.close();
  };
  dlg.classList.remove('breit');
  dlg.showModal();
}

// Beim Zurückkehren in die App: nach längerer Pause sperren, sonst mit Drive abgleichen
document.addEventListener('visibilitychange', () => {
  if (document.hidden || !entsperrt()) return;
  if (sperrzeitAbgelaufen()) sperren(); else if (angemeldet()) sync();
});
if (cloud.clientId) gisLaden().catch(() => {});
setStatus(cloud.clientId ? (angemeldet() ? 'ok' : 'abgemeldet') : 'aus');

render();

// Installierbare App (PWA): Service Worker für den Offline-Start anmelden
if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
