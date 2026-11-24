// Hyper Ketab secure reader — one module for the PWA (iframe) and the native app (WebView).
// Flow: licence → non-extractable AES-GCM key → encrypted book → decrypt in memory → pdf.js → canvas + burned-in watermark.
import * as pdfjs from './pdf.min.js';

pdfjs.GlobalWorkerOptions.workerSrc = new URL('./pdf.worker.min.js', import.meta.url).href;

const $ = (id) => document.getElementById(id);
const FA = '۰۱۲۳۴۵۶۷۸۹';
const fa = (v) => String(v).replace(/[0-9]/g, (d) => FA[+d]);

/* Params from the host: index.html?book=1&native=1&page=3&sample=1  (legacy form: #book-1-native) */
const QS = new URLSearchParams(location.search);
const HASH = (location.hash || '').slice(1).split('-');
const flag = (k) => /^(1|true|yes)$/i.test(QS.get(k) || '') || HASH.includes(k);
const RAW_BOOK = QS.get('book') || (HASH[0] === 'book' && HASH[1]) || '1';
const BOOK = /^[A-Za-z0-9_]{1,40}$/.test(RAW_BOOK) ? RAW_BOOK : ''; // also used in fetch paths: no "../" tricks
const NATIVE = flag('native') || !!window.ReactNativeWebView;
const SAMPLE = flag('sample');
const SAMPLE_PAGES = 3;
const START_PAGE = Math.max(1, parseInt(QS.get('page') || '', 10) || 1);

const state = {
  lic: null, key: null, pdf: null, pages: [], count: 0, zoom: 1, fit: 1, hlMode: false,
  hl: loadHl(), sec: {}, blocked: 0, cached: false, current: 0,
};

/* ---------------- helpers ---------------- */
function toast(msg) { const t = $('toast'); t.textContent = msg; t.classList.add('on'); clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove('on'), 2200); }
function b64ToBytes(b64) { const s = atob(b64); const u = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i); return u; }
function loadHl() { try { return JSON.parse(localStorage.getItem('hk-hl-' + BOOK) || '[]'); } catch { return []; } }
function saveHl() { try { localStorage.setItem('hk-hl-' + BOOK, JSON.stringify(state.hl)); } catch {} }
/* To the host: same-origin parent window (PWA iframe) or the React Native WebView bridge. */
function post(msg) {
  try { window.parent !== window && window.parent.postMessage(msg, location.origin && location.origin !== 'null' ? location.origin : '*'); } catch {}
  try { window.ReactNativeWebView && window.ReactNativeWebView.postMessage(JSON.stringify(msg)); } catch {}
}
const hasHost = () => window.parent !== window || !!window.ReactNativeWebView;
// Inside the Android app the reader is bundled as an APK asset (file:///android_asset/…), where fetch()
// cannot read file: URLs — use XHR there.
function xhrJson(url, what) {
  return new Promise((res, rej) => {
    const x = new XMLHttpRequest();
    x.open('GET', url);
    x.onload = () => { try { if (x.status && x.status !== 200) throw 0; res(JSON.parse(x.responseText)); } catch { rej(new Error(`${what} این کتاب پیدا نشد.`)); } };
    x.onerror = () => rej(new Error(`${what} این کتاب پیدا نشد.`));
    x.send();
  });
}
async function getJson(url, what) {
  if (location.protocol === 'file:') return xhrJson(url, what);
  const r = await fetch(url, { cache: 'no-store' });
  if (!r.ok) throw new Error(r.status === 404 ? `${what} این کتاب پیدا نشد.` : `دریافت ${what} ممکن نشد (HTTP ${r.status}).`);
  return r.json();
}
const nowFa = () => { try { return new Date().toLocaleString('fa-IR', { dateStyle: 'short', timeStyle: 'short' }); } catch { return fa(new Date().toISOString().slice(0, 16).replace('T', ' ')); } };

/* ---------------- offline cache: only ciphertext + a NON-extractable CryptoKey ---------------- */
function idb() {
  return new Promise((res, rej) => {
    try {
      const r = indexedDB.open('hk-reader', 1);
      r.onupgradeneeded = () => r.result.createObjectStore('books');
      r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
    } catch (e) { rej(e); }
  });
}
async function cacheGet(id) { try { const db = await idb(); return await new Promise((res) => { const q = db.transaction('books').objectStore('books').get(id); q.onsuccess = () => res(q.result); q.onerror = () => res(null); }); } catch { return null; } }
async function cachePut(id, v) { try { const db = await idb(); await new Promise((res) => { const tx = db.transaction('books', 'readwrite'); tx.objectStore('books').put(v, id); tx.oncomplete = res; tx.onerror = res; }); return true; } catch { return false; } }

/* ---------------- load: licence → key → ciphertext → plaintext (memory only) ---------------- */
async function open() {
  const lt = $('loading-text');
  if (!BOOK) throw new Error('شناسه کتاب نامعتبر است.');
  if (SAMPLE) { document.body.classList.add('sample'); $('btn-close').querySelector('span').textContent = 'بازگشت'; }
  // 1) licence (mock file; real: POST /wp-json/hyperketab/v1/license with JWT + device id).
  //    Sample mode in production would fetch a separate preview file instead of the full book + key.
  lt.textContent = 'بررسی مجوز مطالعه…';
  const lic = await getJson(`../license/${BOOK}.json`, 'مجوز مطالعه');
  if (new Date(lic.expiresAt) < new Date()) throw new Error('مجوز آفلاین این کتاب تمام شده؛ یک بار آنلاین شوید.');
  state.lic = lic;
  $('book-title').textContent = lic.title;
  document.title = `${lic.title} · کتاب‌خوان امن هایپر کتاب`;

  // 2) key: imported as NON-extractable → JavaScript can use it but can never read its bytes back
  const cached = SAMPLE ? null : await cacheGet(BOOK); // samples are never stored for offline use
  // fingerprint of the licence key (SHA-256, truncated): a re-issued key / re-encrypted file replaces the offline copy
  const kid = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', b64ToBytes(lic.key))).slice(0, 8)).map((b) => b.toString(16).padStart(2, '0')).join('');
  let key, ct, env;
  if (cached && cached.exp > Date.now() && cached.kid === kid) {
    key = cached.key; ct = cached.ct; env = cached.env; state.cached = true;
  } else {
    key = await crypto.subtle.importKey('raw', b64ToBytes(lic.key), { name: 'AES-GCM' }, false, ['decrypt']);
    lt.textContent = 'دریافت فایل رمزنگاری‌شده…';
    env = await getJson(`../books/${BOOK}.enc.json`, 'فایل');
    ct = b64ToBytes(env.data).buffer;
    delete env.data;
    state.cached = SAMPLE ? false : await cachePut(BOOK, { key, ct, env, kid, exp: new Date(lic.expiresAt).getTime() });
  }
  lic.key = '[removed after import]';
  state.key = key;
  state.sec.cipherBytes = ct.byteLength;
  state.sec.hex = Array.from(new Uint8Array(ct, 0, 96)).map((b) => b.toString(16).padStart(2, '0')).join(' ');
  state.sec.extractable = key.extractable;

  // 3) decrypt in memory (AES-GCM also authenticates: a tampered file fails here)
  lt.textContent = 'رمزگشایی در حافظه…';
  const t0 = performance.now();
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBytes(env.iv), additionalData: new TextEncoder().encode(env.aad) }, key, ct);
  state.sec.decryptMs = Math.round(performance.now() - t0);
  state.sec.plainBytes = plain.byteLength;

  // 4) hand bytes to pdf.js (the buffer is transferred to the worker; nothing touches disk or cache)
  lt.textContent = 'آماده‌سازی صفحات…';
  await document.fonts.load('700 14px HK').catch(() => {});
  state.pdf = await pdfjs.getDocument({ data: new Uint8Array(plain), isEvalSupported: false, disableAutoFetch: true, disableFontFace: true, useSystemFonts: false }).promise;
  state.count = SAMPLE ? Math.min(SAMPLE_PAGES, state.pdf.numPages) : state.pdf.numPages;
  $('loading').remove();
  await buildPages();
  goTo(Math.min(START_PAGE, state.count));
  updateCurrent();
  post({ type: 'hk-reader-ready', pages: state.count });
  renderSec();
  setTimeout(() => { $('pill').style.opacity = 0; }, 3500);
}

/* ---------------- pages ---------------- */
async function buildPages() {
  const wrap = $('pages');
  wrap.innerHTML = '';
  state.pages = [];
  const first = await state.pdf.getPage(1);
  const base = first.getViewport({ scale: 1 });
  state.fit = Math.min(2, ($('viewport').clientWidth - 24) / base.width);
  for (let i = 1; i <= state.count; i++) {
    const el = document.createElement('div');
    el.className = 'page' + (state.hlMode ? ' hlmode' : '');
    el.dataset.page = i;
    el.innerHTML = '<canvas aria-hidden="true"></canvas><div class="hl-layer"></div><div class="sel-layer"></div>';
    wrap.appendChild(el);
    state.pages.push({ n: i, el, rendered: 0, vp1: null, text: null, task: null });
    bindSelection(el, i);
  }
  if (SAMPLE) wrap.appendChild(sampleEnd());
  layoutPages(base);
  observe();
}

/* Sample mode: only the first pages exist at all; a sticky banner leads to the book page to buy it. */
function sampleEnd() {
  const box = document.createElement('div');
  box.className = 'sample-end';
  box.innerHTML = `<span class="se-ic"><svg viewBox="0 0 24 24"><rect x="5" y="10.5" width="14" height="10" rx="2.5"/><path d="M8.5 10.5V8a3.5 3.5 0 0 1 7 0v2.5"/></svg></span>
    <span class="se-text"><b class="se-full">پایان نمونه رایگان</b><b class="se-peek">نمونه رایگان · ${fa(state.count)} صفحه نخست</b><span class="se-sub">برای خواندن ادامه کتاب، نسخه الکترونیک را بخرید.</span></span>
    <button class="se-buy" type="button">خرید کتاب</button>`;
  return box;
}
function buy() {
  post({ type: 'hk-reader-buy' });
  if (!hasHost()) toast('برای خرید، به صفحه کتاب در هایپر کتاب بروید');
}
document.addEventListener('click', (e) => { if (e.target.closest && e.target.closest('.se-buy')) buy(); });

function goTo(n, smooth) {
  const p = state.pages[n - 1];
  if (!p) return;
  // scroll our own viewport only (scrollIntoView would also scroll the host page around the iframe)
  $('viewport').scrollTo({ top: Math.max(0, p.el.offsetTop - 12), behavior: smooth ? 'smooth' : 'auto' });
}

function layoutPages(base) {
  const sc = state.fit * state.zoom;
  for (const p of state.pages) {
    p.el.style.width = Math.round(base.width * sc) + 'px';
    p.el.style.height = Math.round(base.height * sc) + 'px';
    p.rendered = 0;
  }
  $('z-label').textContent = fa(Math.round(state.zoom * 100)) + '٪';
}

/* lazy rendering: only pages near the viewport get a canvas bitmap */
let io;
function observe() {
  io && io.disconnect();
  io = new IntersectionObserver((ents) => {
    for (const e of ents) if (e.isIntersecting) renderPage(state.pages[+e.target.dataset.page - 1]).catch((err) => console.warn(err));
  }, { root: $('viewport'), rootMargin: '400px 0px', threshold: 0 });
  state.pages.forEach((p) => io.observe(p.el));
}

/* current page = the page under a line 35% down the viewport (works for pages taller than the screen too) */
function updateCurrent() {
  if (!state.pages.length) return;
  const vp = $('viewport');
  const probe = vp.scrollTop + vp.clientHeight * 0.35;
  let n = 1;
  for (const p of state.pages) { if (p.el.offsetTop <= probe) n = p.n; else break; }
  if (vp.scrollTop > 0 && vp.scrollTop + vp.clientHeight >= vp.scrollHeight - 2) n = state.pages.length;
  setCurrent(n);
}
let scrollRaf = 0;
$('viewport').addEventListener('scroll', () => {
  if (!scrollRaf) scrollRaf = requestAnimationFrame(() => { scrollRaf = 0; updateCurrent(); });
}, { passive: true });

let progT = 0;
function setCurrent(n) {
  if (n === state.current) return;
  state.current = n;
  $('page-label').textContent = `صفحه ${fa(n)} از ${fa(state.count)}` + (SAMPLE ? ' · نمونه رایگان' : '');
  $('prog').style.width = (n / state.count) * 100 + '%';
  const se = document.querySelector('.sample-end');
  if (se) se.classList.toggle('end', n >= state.count);
  // tell the host (progress sync), debounced so fast scrolling does not flood the bridge
  clearTimeout(progT);
  progT = setTimeout(() => post({ type: 'hk-reader-progress', page: state.current, pages: state.count }), 400);
}

async function renderPage(p) {
  const sc = state.fit * state.zoom;
  if (!p || p.rendered === sc) return;
  p.rendered = sc;
  if (p.task) { try { p.task.cancel(); } catch {} p.task = null; } // a zoom change while drawing: one render per canvas
  const page = await state.pdf.getPage(p.n);
  if (p.rendered !== sc) return;
  p.vp1 = page.getViewport({ scale: 1 });
  const dpr = Math.min(window.devicePixelRatio || 1, 2.5);
  const vp = page.getViewport({ scale: sc * dpr });
  const canvas = p.el.querySelector('canvas');
  canvas.width = Math.floor(vp.width); canvas.height = Math.floor(vp.height);
  const ctx = canvas.getContext('2d');
  const task = (p.task = page.render({ canvasContext: ctx, viewport: vp }));
  try { await task.promise; } catch (e) { if (e && e.name === 'RenderingCancelledException') return; throw e; } finally { if (p.task === task) p.task = null; }
  watermark(ctx, canvas.width, canvas.height, dpr * sc); // every bitmap that was drawn carries the watermark
  if (p.rendered !== sc) return;
  if (!p.text) p.text = await extractLines(page, p.vp1);
  drawHl(p);
}

/* Burned into the pixels: every screenshot or photo of the screen carries the buyer's identity. */
function watermark(ctx, w, h, k) {
  const L = state.lic;
  const line = `${L.userId} · ${L.phone} · هایپر کتاب`;
  ctx.save();
  ctx.globalAlpha = 0.075;
  ctx.fillStyle = '#1F1F24';
  ctx.font = `700 ${13 * k}px HK, sans-serif`;
  ctx.translate(w / 2, h / 2);
  ctx.rotate(-28 * Math.PI / 180);
  const stepX = ctx.measureText(line).width + 60 * k, stepY = 70 * k;
  for (let y = -h; y < h; y += stepY) for (let x = -w * 1.2; x < w * 1.2; x += stepX) ctx.fillText(line, x + ((y / stepY) % 2) * stepX / 2, y);
  ctx.restore();
  ctx.save();
  ctx.globalAlpha = 0.38;
  ctx.fillStyle = '#62646C';
  ctx.font = `400 ${7.5 * k}px HK, sans-serif`;
  ctx.textAlign = 'center';
  ctx.fillText(`نسخه شخصی ${L.userId} · سفارش ${L.orderId} · ${nowFa()}`, w / 2, h - 10 * k);
  ctx.restore();
}

/* pdf.js glyph items → RTL lines (used for highlight geometry, quotes and text mode) */
async function extractLines(page, vp) {
  const tc = await page.getTextContent();
  const items = [];
  for (const it of tc.items) {
    if (!it.str || !it.str.trim()) continue;
    const [, , c, d, e, f] = it.transform;
    const hgt = Math.hypot(c, d);
    items.push({ s: it.str.normalize('NFKC'), x: e, y: vp.height - f, w: it.width, h: hgt });
  }
  const lines = [];
  for (const it of items) {
    let L = lines.find((l) => Math.abs(l.y - it.y) < it.h * 0.35);
    if (!L) { L = { y: it.y, h: it.h, items: [] }; lines.push(L); }
    L.items.push(it);
  }
  lines.sort((a, b) => a.y - b.y);
  for (const L of lines) {
    L.items.sort((a, b) => b.x - a.x);
    let out = '', prev = null;
    for (const it of L.items) { if (prev && prev.x - (it.x + it.w) > it.h * 0.18) out += ' '; out += it.s; prev = it; }
    L.text = out;
    L.x0 = Math.min(...L.items.map((i) => i.x)); L.x1 = Math.max(...L.items.map((i) => i.x + i.w));
  }
  return lines;
}

/* ---------------- highlights ---------------- */
function drawHl(p) {
  if (!p) return;
  const layer = p.el.querySelector('.hl-layer');
  layer.innerHTML = '';
  for (const h of state.hl.filter((x) => x.page === p.n)) {
    for (const r of h.rects) {
      const d = document.createElement('div');
      d.className = 'hl' + (h.note ? ' noted' : '');
      Object.assign(d.style, { left: r.x * 100 + '%', top: r.y * 100 + '%', width: r.w * 100 + '%', height: r.h * 100 + '%', background: h.color });
      d.onclick = (e) => { if (state.hlMode) return; e.stopPropagation(); openMenu(e.clientY, { existing: h }); };
      layer.appendChild(d);
    }
  }
}

function bindSelection(el, n) {
  let start = null, box = null;
  const norm = (e) => { const r = el.getBoundingClientRect(); return { x: (e.clientX - r.left) / r.width, y: (e.clientY - r.top) / r.height, cy: e.clientY }; };
  el.addEventListener('pointerdown', (e) => {
    if (!state.hlMode) return;
    e.preventDefault();
    el.setPointerCapture(e.pointerId);
    start = norm(e);
    box = document.createElement('div'); box.className = 'selbox';
    el.querySelector('.sel-layer').appendChild(box);
  });
  el.addEventListener('pointermove', (e) => {
    if (!start) return;
    const c = norm(e);
    Object.assign(box.style, { left: Math.min(start.x, c.x) * 100 + '%', top: Math.min(start.y, c.y) * 100 + '%', width: Math.abs(c.x - start.x) * 100 + '%', height: Math.abs(c.y - start.y) * 100 + '%' });
  });
  el.addEventListener('pointerup', (e) => {
    if (!start) return;
    const c = norm(e), a = start; start = null;
    const p = state.pages[n - 1];
    el.querySelector('.sel-layer').innerHTML = '';
    if (!p.text || !p.vp1) return;
    const W = p.vp1.width, H = p.vp1.height;
    const R = { x0: Math.min(a.x, c.x) * W, x1: Math.max(a.x, c.x) * W, y0: Math.min(a.y, c.y) * H, y1: Math.max(a.y, c.y) * H };
    if (R.y1 - R.y0 < 3) { R.y0 -= 6; R.y1 += 6; }
    const rects = [], quote = [];
    for (const L of p.text) {
      const top = L.y - L.h * 0.85, bot = L.y + L.h * 0.3;
      if (bot < R.y0 || top > R.y1) continue;
      const sel = L.items.filter((i) => i.x + i.w > R.x0 && i.x < R.x1);
      if (!sel.length) continue;
      const x0 = Math.min(...sel.map((i) => i.x)), x1 = Math.max(...sel.map((i) => i.x + i.w));
      rects.push({ x: x0 / W, y: top / H, w: (x1 - x0) / W, h: (bot - top) / H });
      let out = '', prev = null;
      for (const it of sel) { if (prev && prev.x - (it.x + it.w) > it.h * 0.18) out += ' '; out += it.s; prev = it; }
      quote.push(out);
    }
    if (!rects.length) { toast('روی خطوط متن انگشت بکشید'); return; }
    const sl = el.querySelector('.sel-layer');
    for (const r of rects) { const d = document.createElement('div'); d.className = 'selline'; Object.assign(d.style, { left: r.x * 100 + '%', top: r.y * 100 + '%', width: r.w * 100 + '%', height: r.h * 100 + '%' }); sl.appendChild(d); }
    openMenu(e.clientY, { draft: { id: Date.now().toString(36), page: n, rects, quote: quote.join(' '), color: '#FCE38A', note: '', at: Date.now() } });
  });
}

let menuCtx = null;
function openMenu(y, ctx) {
  menuCtx = ctx;
  const m = $('hl-menu');
  m.hidden = false;
  const h = m.offsetHeight;
  m.style.top = Math.max(70, Math.min(window.innerHeight - h - 130, y - h - 24)) + 'px';
  $('m-del').hidden = !ctx.existing;
  m.querySelectorAll('.sw').forEach((b) => (b.style.borderColor = (ctx.existing && ctx.existing.color === b.dataset.c) ? '#fff' : 'rgba(255,255,255,.3)'));
}
function closeMenu() { $('hl-menu').hidden = true; menuCtx = null; document.querySelectorAll('.sel-layer').forEach((l) => (l.innerHTML = '')); }
function commit(h) {
  const i = state.hl.findIndex((x) => x.id === h.id);
  if (i >= 0) state.hl[i] = h; else state.hl.push(h);
  saveHl(); drawHl(state.pages[h.page - 1]);
}
$('hl-menu').querySelectorAll('.sw').forEach((b) => b.addEventListener('click', () => {
  if (!menuCtx) return;
  const h = menuCtx.existing || menuCtx.draft;
  h.color = b.dataset.c; commit(h); closeMenu(); toast('هایلایت ذخیره شد');
}));
$('m-note').onclick = () => { const h = menuCtx && (menuCtx.existing || menuCtx.draft); if (!h) return; closeMenu(); openNote(h); };
$('m-del').onclick = () => { const h = menuCtx && menuCtx.existing; if (!h) return; state.hl = state.hl.filter((x) => x.id !== h.id); saveHl(); drawHl(state.pages[h.page - 1]); closeMenu(); toast('حذف شد'); };
$('m-copy').onclick = () => { state.blocked++; toast('کپی متن برای این کتاب غیرفعال است'); };
$('m-cancel').onclick = closeMenu;

let noteFor = null;
function openNote(h) { noteFor = h; $('n-quote').textContent = '«' + h.quote + '»'; $('n-text').value = h.note || ''; $('note-sheet').hidden = false; setTimeout(() => $('n-text').focus(), 50); }
$('n-cancel').onclick = () => { $('note-sheet').hidden = true; noteFor = null; };
$('n-save').onclick = () => { if (!noteFor) return; noteFor.note = $('n-text').value.trim(); commit(noteFor); $('note-sheet').hidden = true; noteFor = null; toast('یادداشت ذخیره شد'); };

function renderNotes() {
  const box = $('notes-list');
  box.innerHTML = '';
  const list = state.hl.filter((h) => h.page <= (state.count || Infinity)).sort((a, b) => a.page - b.page);
  if (!list.length) { box.innerHTML = '<div class="empty">هنوز هایلایتی ندارید. ابزار «هایلایت» را بزنید و روی متن انگشت بکشید.</div>'; return; }
  for (const h of list) {
    const b = document.createElement('button');
    b.className = 'note-item';
    b.innerHTML = `<span class="bar-c" style="background:${h.color}"></span><span style="flex:1"><span class="meta">صفحه ${fa(h.page)}</span><br>«${escapeHtml(h.quote)}»${h.note ? `<div class="nt">${escapeHtml(h.note)}</div>` : ''}</span>`;
    b.onclick = () => { $('notes-panel').hidden = true; goTo(h.page, true); };
    box.appendChild(b);
  }
}
const escapeHtml = (s) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

/* ---------------- tools ---------------- */
const ZOOMS = [0.8, 1, 1.25, 1.5, 1.75, 2];
function zoom(dir) {
  if (!state.pdf) return;
  const i = Math.max(0, Math.min(ZOOMS.length - 1, ZOOMS.indexOf(state.zoom) + dir));
  if (ZOOMS[i] === state.zoom) return;
  const vp = $('viewport'), ratio = vp.scrollTop / Math.max(1, vp.scrollHeight);
  state.zoom = ZOOMS[i];
  state.pdf.getPage(1).then((pg) => { layoutPages(pg.getViewport({ scale: 1 })); vp.scrollTop = ratio * vp.scrollHeight; observe(); });
}
$('z-in').onclick = () => zoom(1);
$('z-out').onclick = () => zoom(-1);
$('t-hl').onclick = () => {
  state.hlMode = !state.hlMode;
  $('t-hl').setAttribute('aria-pressed', String(state.hlMode));
  state.pages.forEach((p) => p.el.classList.toggle('hlmode', state.hlMode));
  $('hint').hidden = !state.hlMode;
};
function openSheet(id) { closeMenu(); document.querySelectorAll('.sheet').forEach((s) => (s.hidden = s.id !== id)); }
$('btn-notes').onclick = () => { renderNotes(); openSheet('notes-panel'); };
$('btn-sec').onclick = () => { renderSec(); openSheet('sec-panel'); };
document.querySelectorAll('.close-sheet').forEach((b) => (b.onclick = () => (b.closest('.sheet').hidden = true)));
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  if (!$('hl-menu').hidden) closeMenu();
  else if ([...document.querySelectorAll('.sheet')].some((s) => !s.hidden)) document.querySelectorAll('.sheet').forEach((s) => (s.hidden = true));
  else if (!$('text-mode').hidden) $('text-mode').hidden = true;
});
$('btn-close').onclick = () => { post({ type: 'hk-reader-close' }); if (!hasHost()) history.back(); };

/* text mode: reflowed text with font size + themes */
const TM = { fs: 18, theme: 'light' };
const THEMES = { light: ['#fff', '#1E1E22'], sepia: ['#F7F1E3', '#2B2118'], gray: ['#E4E4E8', '#1E1E22'], dark: ['#141418', '#D9D6CF'] };
async function openText() {
  if (!state.pdf || !state.lic) return;
  if (!state.lic.allowTextMode) { toast('ناشر حالت متنی را برای این کتاب غیرفعال کرده'); return; }
  const body = $('tm-body');
  body.innerHTML = '<div class="empty">در حال بازچینی متن…</div>';
  $('text-mode').hidden = false;
  applyTm();
  for (const p of state.pages) { // state.pages is already limited to the sample pages in sample mode
    if (!p.text) { const pg = await state.pdf.getPage(p.n); p.vp1 = pg.getViewport({ scale: 1 }); p.text = await extractLines(pg, p.vp1); }
  }
  // body text size = the line height carrying most of the text; clearly bigger lines are headings
  const sizes = {};
  for (const p of state.pages) for (const L of p.text) sizes[Math.round(L.h * 2) / 2] = (sizes[Math.round(L.h * 2) / 2] || 0) + L.text.length;
  const bodyH = +Object.keys(sizes).sort((a, b) => sizes[b] - sizes[a])[0] || 12;
  let html = '';
  for (const p of state.pages) {
    if (!p.text.length) continue;
    html += `<div class="pg" id="tm-p${p.n}">صفحه ${fa(p.n)}</div>`;
    let para = '', prevY = null, prevH = 0;
    const flush = () => { if (para.trim()) html += `<p>${escapeHtml(para.trim())}</p>`; para = ''; };
    for (const L of p.text) {
      if (L.h > bodyH * 1.2) { flush(); html += `<h2>${escapeHtml(L.text)}</h2>`; prevY = L.y; prevH = L.h; continue; }
      if (prevY !== null && L.y - prevY > prevH * 2.6) flush();
      para += (para ? ' ' : '') + L.text;
      prevY = L.y; prevH = L.h;
      if (L.x0 > p.vp1.width * 0.45) flush();
    }
    flush();
  }
  if (SAMPLE) html += `<div class="tm-sample"><b>پایان نمونه رایگان</b><span>برای خواندن ادامه کتاب، نسخه الکترونیک را بخرید.</span><button class="se-buy" type="button">خرید کتاب</button></div>`;
  body.innerHTML = html;
  const at = $('tm-p' + state.current);
  body.scrollTop = at && state.current > 1 ? at.offsetTop - body.offsetTop : 0;
}
function applyTm() {
  const t = THEMES[TM.theme], el = $('text-mode');
  el.style.setProperty('--tm-bg', t[0]); el.style.setProperty('--tm-fg', t[1]); el.style.setProperty('--tm-fs', TM.fs + 'px');
  $('tm-bar').style.width = ((TM.fs - 14) / 12) * 100 + '%';
  $('tm-size').textContent = 'اندازه متن: ' + fa(TM.fs);
  document.querySelectorAll('.themes button').forEach((b) => b.classList.toggle('on', b.dataset.t === TM.theme));
}
$('t-text').onclick = openText;
$('tm-close').onclick = () => ($('text-mode').hidden = true);
$('tm-minus').onclick = () => { TM.fs = Math.max(14, TM.fs - 1); applyTm(); };
$('tm-plus').onclick = () => { TM.fs = Math.min(26, TM.fs + 1); applyTm(); };
document.querySelectorAll('.themes button').forEach((b) => (b.onclick = () => { TM.theme = b.dataset.t; applyTm(); }));

/* ---------------- anti-theft guards ---------------- */
function block(why) { state.blocked++; toast(why); }
document.addEventListener('contextmenu', (e) => { if (e.target.tagName === 'TEXTAREA') return; e.preventDefault(); block('منوی کپی و ذخیره غیرفعال است'); });
document.addEventListener('dragstart', (e) => e.preventDefault());
document.addEventListener('copy', (e) => { if (e.target.tagName !== 'TEXTAREA') { e.preventDefault(); block('کپی متن کتاب مجاز نیست'); } });
document.addEventListener('keydown', (e) => {
  const k = (e.key || '').toLowerCase();
  if ((e.ctrlKey || e.metaKey) && ['s', 'p', 'c', 'a', 'u'].includes(k) && e.target.tagName !== 'TEXTAREA') { e.preventDefault(); block('این میانبر برای کتاب غیرفعال است'); }
  if (k === 'printscreen') { shield(true, 'اسکرین‌شات ثبت شد؛ واترمارک کاربر روی تصویر است'); setTimeout(() => shield(false), 1500); }
});
function shield(on, why) { $('shield').hidden = !on; if (why) $('shield-why').textContent = why; }
document.addEventListener('visibilitychange', () => shield(document.visibilityState !== 'visible', 'اپ به پس‌زمینه رفت؛ در پیش‌نمایش برنامه‌ها متنی دیده نمی‌شود'));
window.addEventListener('pagehide', () => shield(true));
window.addEventListener('pageshow', () => shield(false)); // back/forward cache: do not stay covered
window.addEventListener('beforeprint', () => { state.blocked++; shield(true, 'چاپ این کتاب مجاز نیست'); });
window.addEventListener('afterprint', () => shield(false));

/* ---------------- security panel ---------------- */
function renderSec() {
  const L = state.lic || {}, S = state.sec;
  const kb = (n) => fa(((n || 0) / 1024).toFixed(1).replace('.', '٫')) + ' KB';
  const items = [
    ['فایل کتاب رمزنگاری‌شده تحویل می‌شود', `AES-256-GCM · ${kb(S.cipherBytes)} · شناسه کتاب به‌عنوان AAD به رمز گره خورده`],
    ['کلید فقط با مجوز معتبر داده می‌شود', `کاربر ${L.userId} · ${L.device} · دستگاه ${fa(L.devicesUsed)} از ${fa(L.devicesMax)} · اعتبار تا ${L.expiresAt ? new Date(L.expiresAt).toLocaleDateString('fa-IR') : '—'}`],
    ['کلید قابل خواندن نیست', `CryptoKey با extractable = ${String(S.extractable)}؛ اسکریپت می‌تواند با آن رمزگشایی کند ولی خود کلید را نمی‌تواند بیرون بکشد`],
    ['رمزگشایی فقط در حافظه', `${fa(S.decryptMs ?? '—')} میلی‌ثانیه · PDF اصلی (${kb(S.plainBytes)}) هیچ‌وقت روی دیسک یا کش ذخیره نمی‌شود`],
    ['ذخیره آفلاین فقط به‌صورت رمزشده', SAMPLE ? 'نسخه نمونه برای مطالعه آفلاین ذخیره نمی‌شود' : state.cached ? 'متن رمزشده + کلید غیرقابل‌خروج در IndexedDB ذخیره شد' : 'این مرورگر اجازه ذخیره نداد؛ هر بار آنلاین باز می‌شود'],
    ['صفحه‌ها روی canvas رسم می‌شوند', 'لایه متنی در صفحه نیست؛ انتخاب، کپی و جستجوی مرورگر روی متن کار نمی‌کند'],
    ['واترمارک در خود پیکسل‌ها', `«${L.userId} · ${L.phone}» به‌صورت مورب و کد سفارش ${L.orderId} پایین هر صفحه؛ هر اسکرین‌شات یا عکس، صاحب نسخه را نشان می‌دهد`],
    ['میانبرهای کپی، چاپ و ذخیره بسته‌اند', `راست‌کلیک، Ctrl/⌘+C/S/P، کشیدن و چاپ · ${fa(state.blocked)} تلاش مسدود شد`],
    ['پنهان شدن در پس‌زمینه', 'وقتی اپ به پس‌زمینه می‌رود یا چاپ شروع می‌شود، محتوا با پرده پوشانده می‌شود'],
    NATIVE
      ? ['محافظت سیستم‌عامل (اپ native)', 'اندروید: FLAG_SECURE (اسکرین‌شات، ضبط و Cast سیاه می‌شود) · iOS: لایه امن + تشخیص ضبط صفحه']
      : ['محافظت سیستم‌عامل', 'در وب و PWA در دسترس نیست؛ در اپ اندروید و iOS با react-native-capture-protection فعال می‌شود', 'off'],
  ];
  $('sec-list').innerHTML = items.map(([t, v, off]) => `<li class="${off ? 'off' : ''}"><span><b>${t}</b><span class="v">${escapeHtml(String(v))}</span></span></li>`).join('');
  $('hex').textContent = (S.hex || '').toUpperCase() + ' …';
  $('limits').innerHTML = [
    'روی وب و آیفون (PWA) هیچ راهی برای جلوگیری از اسکرین‌شات وجود ندارد؛ واترمارک فقط نشتی را قابل ردگیری می‌کند.',
    'کسی که مهارت فنی دارد می‌تواند با DevTools از canvas تصویر بگیرد. هدف، سخت و قابل ردگیری کردن کپی است، نه غیرممکن کردن آن.',
    'عکس گرفتن با یک گوشی دیگر را هیچ سیستمی نمی‌تواند متوقف کند.',
    'در این نسخه ماک، مجوز یک فایل ثابت است؛ در نسخه واقعی کلید از API، فقط برای مالک کتاب، کوتاه‌مدت و گره‌خورده به دستگاه صادر می‌شود.',
  ].map((x) => `<li>${x}</li>`).join('');
}
$('try-open').onclick = async () => {
  const out = $('try-result');
  try {
    const env = await getJson(`../books/${BOOK}.enc.json`, 'فایل');
    await pdfjs.getDocument({ data: b64ToBytes(env.data), isEvalSupported: false }).promise;
    out.textContent = 'باز شد (نباید این اتفاق بیفتد!)';
  } catch (e) {
    out.textContent = 'نتیجه: pdf.js نمی‌تواند فایل را باز کند — «' + (e && e.name ? e.name : 'InvalidPDF') + '». بدون کلید، این فایل فقط داده تصادفی است.';
  }
};

open().catch((e) => {
  post({ type: 'hk-reader-error', message: e && e.message ? e.message : String(e) });
  const l = $('loading');
  if (l) l.innerHTML = `<b>باز کردن کتاب ممکن نشد</b><span class="small">${escapeHtml(e.message || String(e))}</span>`;
  console.error(e);
});
