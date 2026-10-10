'use strict';
/* Ядро окна: мост в Python, точечное обновление DOM и общие поверхности —
   уведомления, подсказка, меню и поповер, лист и вопрос.

   Состояние приходит опросом раз в пару секунд. Разметку целиком не
   перерисовываем: узлы держатся по ключу (id туннеля, имя конфига), меняются
   только текст, атрибуты и классы — иначе снимались бы наведение, фокус в
   поле и открытое меню. */

// ---------------------------------------------------------------- мост
// pywebview поднимает window.pywebview.api не сразу, а скрипт страницы шлёт
// 'ready' первым делом: всё, что отправлено раньше, ждёт готовности моста в
// порядке отправки.
const bridge = () => window.pywebview && window.pywebview.api && window.pywebview.api.send
  ? window.pywebview.api : null;
const bridgeReady = new Promise(resolve => {
  if (bridge()) resolve();
  else addEventListener('pywebviewready', () => resolve(), {once: true});
});

// Команда без ответа: ответ придёт вызовом функции страницы из Python.
function send(name, arg) {
  bridgeReady.then(() => bridge().send(name, arg ?? null));
}

// Команда с ответом: pywebview возвращает результат метода промисом. Сбой
// моста — {ok: false, error}, чтобы вызывающему было одно место разбора.
function request(name, arg) {
  return bridgeReady
    .then(() => bridge().send(name, arg ?? null))
    .then(r => r ?? {ok: false, error: 'нет ответа'},
          e => ({ok: false, error: String(e && e.message || e)}));
}

// Вызовы из Python: исключение внутри evaluate_js наружу не всплывает, а
// консоли у окна нет — ловим здесь и шлём в журнал окна.
function call(fn, arg) {
  try { window[fn](arg); } catch (e) { reportError(fn, e); }
}
// Несколько аргументов (showConf, showInfo). Отдельно от call: renderLogs
// принимает массив целиком, спред разложил бы его на сотни аргументов.
function callN(fn, args) {
  try { window[fn].apply(null, args); } catch (e) { reportError(fn, e); }
}
function reportError(where, e) {
  send('jserror', `${where}: ${e && e.message} @${e && (e.stack || '').split('\n')[1]}`);
}
addEventListener('error', e => send('jserror', `${e.message} @${e.filename}:${e.lineno}`));
addEventListener('unhandledrejection', e => send('jserror', `promise: ${e.reason}`));

// Каждая ветка отрисовки отчитывается один раз: упала — сообщения нет, и
// сквозной тест это увидит.
const _ticked = {};
const tick = what => { if (!_ticked[what]) { _ticked[what] = 1; send('rendered', what); } };

// ------------------------------------------------------------- помощники
const $ = id => document.getElementById(id);
const SVG_NS = 'http://www.w3.org/2000/svg';
const REDUCED = matchMedia('(prefers-reduced-motion: reduce)');
const EASE = 'cubic-bezier(.32, .72, 0, 1)';
const FADE_MS = 200;

// el('div', {class, text, 'data-x': 1, onclick}, ...дети). Пустые и false
// атрибуты пропускаются: так условные атрибуты пишутся прямо в объекте.
function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? '' : v);
  }
  n.append(...kids.flat().filter(x => x != null && x !== false));
  return n;
}

function icon(name, cls = '') {
  const s = document.createElementNS(SVG_NS, 'svg');
  s.setAttribute('class', `ic ${cls}`.trim());
  s.setAttribute('aria-hidden', 'true');
  const u = document.createElementNS(SVG_NS, 'use');
  u.setAttribute('href', `#i-${name}`);
  s.append(u);
  return s;
}
function setIcon(svg, name) {
  const u = svg.firstChild, href = `#i-${name}`;
  if (u.getAttribute('href') !== href) u.setAttribute('href', href);
}

// Кнопка-иконка: подпись — в aria-label и подсказке.
const ibtn = (name, label, props = {}) =>
  el('button', {class: 'ibtn', 'aria-label': label, 'data-tip': label, ...props}, icon(name));

// Орб статуса: форма из спрайта по виду, цвет — классом st-<вид>.
const KINDS = ['ok', 'err', 'warn', 'busy', 'off', 'unset'];
function orb(kind = 'off', cls = '') {
  const o = el('span', {class: `orb ${cls}`.trim()}, icon(kind));
  setOrb(o, kind);
  return o;
}
function setOrb(o, kind) {
  setKind(o, kind);
  setIcon(o.firstChild, kind);
}
// Класс st-<вид> на узле, прежний снимается.
function setKind(n, kind) {
  for (const k of KINDS) n.classList.toggle(`st-${k}`, k === kind);
}

// Текст меняется, только если другой: иначе опрос снимал бы выделение. fade —
// короткий проявитель, чтобы смена статуса читалась, а не прыгала.
function setText(n, text, fade = false) {
  text = text == null ? '' : String(text);
  if (n.textContent === text) return false;
  n.textContent = text;
  if (fade && !REDUCED.matches && n.isConnected) {
    n.animate([{opacity: .25}, {opacity: 1}], {duration: FADE_MS, easing: EASE});
  }
  return true;
}
function setAttr(n, k, v) {
  if (v == null || v === false) { if (n.hasAttribute(k)) n.removeAttribute(k); return; }
  v = v === true ? '' : String(v);
  if (n.getAttribute(k) !== v) n.setAttribute(k, v);
}
const setTip = (n, text) => setAttr(n, 'data-tip', text || null);
function show(n, on) { if (n.hidden === !!on) n.hidden = !on; }
function setDisabled(n, off) { if (n.disabled !== !!off) n.disabled = !!off; }

// Ключевое обновление списка: узел на элемент по key, новые — make(item),
// у всех — update(узел, item, i); порядок — как в items, лишние удаляются.
function reconcile(box, items, key, make, update) {
  const old = new Map();
  for (const c of box.children) old.set(c.dataset.key, c);
  let prev = null;
  items.forEach((item, i) => {
    const k = String(key(item));
    let n = old.get(k);
    if (n) old.delete(k);
    else { n = make(item); n.dataset.key = k; }
    update(n, item, i);
    const want = prev ? prev.nextSibling : box.firstChild;
    if (n !== want) box.insertBefore(n, want);
    prev = n;
  });
  old.forEach(n => n.remove());
}

// «1 запись, 2 записи, 5 записей».
function plural(n, [one, few, many]) {
  const d = n % 10, h = n % 100;
  const w = d === 1 && h !== 11 ? one : d >= 2 && d <= 4 && (h < 12 || h > 14) ? few : many;
  return `${n} ${w}`;
}

function debounce(fn, ms) {
  let t = 0;
  const d = (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
  d.cancel = () => clearTimeout(t);
  d.now = (...a) => { clearTimeout(t); fn(...a); };
  return d;
}

// navigator.clipboard есть не в каждом WebView2 и может отказать — тогда
// старый путь через выделение.
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch { /* ниже */ }
  const ta = el('textarea', {class: 'mono offscreen'});
  ta.value = text;
  document.body.append(ta);
  ta.select();
  const ok = document.execCommand('copy');
  ta.remove();
  return ok;
}

// ------------------------------------------------------------ уведомления
// Разовые итоги (сохранено, скопировано, ошибка команды) — снизу справа,
// стопкой не больше трёх; старое уходит первым.
const TOAST_MS = 4000;
const TOAST_ERR_MS = 7000;
const TOAST_MAX = 3;

function toast(text, kind = 'ok', ms) {
  const box = $('toasts');
  const t = el('div', {class: 'toast', role: kind === 'err' ? 'alert' : null},
               orb(kind), el('div', {class: 'toast-text val', text}));
  const drop = () => {
    if (t.classList.contains('leaving')) return;
    t.classList.add('leaving');
    setTimeout(() => t.remove(), REDUCED.matches ? 0 : FADE_MS);
  };
  t.addEventListener('click', drop);
  box.append(t);
  while (box.children.length > TOAST_MAX) box.firstChild.remove();
  setTimeout(drop, ms ?? (kind === 'err' ? TOAST_ERR_MS : TOAST_MS));
}

// Ошибка команды из Python: операция не пошла — кнопки отпускаем (PENDING —
// в main) и говорим, что случилось.
function failed(msg) {
  if (typeof onFailed === 'function') onFailed(msg);
  toast(humanError(msg), 'err');
}
// Отказ UAC снаружи выглядит одинаково при любом действии — говорим, что делать.
function humanError(msg) {
  msg = String(msg || 'служба отказала');
  if (/запрос прав отменён/.test(msg)) {
    return 'Права администратора не получены → повтори и нажми «Да» в окне UAC';
  }
  return msg;
}

// ------------------------------------------------------------- подсказка
// Своя подсказка вместо title: та же стеклянная поверхность, что у меню, и
// не дублируется системной. Узел с .ell показывает её, только если текст
// обрезан.
const TIP_DELAY_MS = 450;
let _tipFor = null, _tipT = 0;

function tipTarget(n) {
  const t = n && n.closest && n.closest('[data-tip]');
  if (!t) return null;
  if (t.classList.contains('ell') && t.scrollWidth <= t.clientWidth) return null;
  return t;
}
function showTip(t) {
  const tip = $('tip');
  _tipFor = t;
  tip.textContent = t.dataset.tip;
  tip.hidden = false;
  const r = t.getBoundingClientRect(), w = tip.offsetWidth, h = tip.offsetHeight;
  const top = r.bottom + 6 + h > innerHeight ? r.top - 6 - h : r.bottom + 6;
  tip.style.top = `${Math.max(4, top)}px`;
  tip.style.left = `${Math.max(4, Math.min(r.left + r.width / 2 - w / 2, innerWidth - w - 4))}px`;
}
function hideTip() {
  clearTimeout(_tipT);
  _tipFor = null;
  $('tip').hidden = true;
}
document.addEventListener('pointerover', e => {
  const t = tipTarget(e.target);
  if (t === _tipFor) return;
  hideTip();
  if (t) _tipT = setTimeout(() => t.isConnected && showTip(t), TIP_DELAY_MS);
});
document.addEventListener('pointerdown', hideTip, true);
document.addEventListener('scroll', hideTip, true);
document.addEventListener('focusin', e => {
  hideTip();
  const t = document.body.classList.contains('kbd') && tipTarget(e.target);
  if (t) showTip(t);
});

// ------------------------------------------------- меню и поповер (одно на окно)
let POP = null;   // {node, anchor, onClose}

// Поверхность у кнопки: под ней, по правому краю; не влезает — над ней;
// в окно — всегда. Закрывается Esc, кликом вне и прокруткой панели.
function openPop(anchor, node, {onClose, focus = 'first', align = 'end'} = {}) {
  closePop();
  hideTip();
  node.classList.add('pop');
  document.body.append(node);
  POP = {node, anchor, onClose};
  anchor.setAttribute('aria-expanded', 'true');
  placePop(align);
  if (focus === 'first') {
    const f = node.querySelector('[role="menuitem"]:not(:disabled), button:not(:disabled), input');
    if (f) f.focus({preventScroll: true});
  }
  return node;
}
function placePop(align) {
  const {node, anchor} = POP;
  const r = anchor.getBoundingClientRect(), w = node.offsetWidth, h = node.offsetHeight;
  const below = r.bottom + 4 + h <= innerHeight - 8 || r.top < h + 12;
  const top = below ? r.bottom + 4 : r.top - 4 - h;
  const left = align === 'start' ? r.left : r.right - w;
  node.style.top = `${Math.max(8, Math.min(top, innerHeight - h - 8))}px`;
  node.style.left = `${Math.max(8, Math.min(left, innerWidth - w - 8))}px`;
  node.style.setProperty('--origin', `${below ? 'top' : 'bottom'} ${align === 'start' ? 'left' : 'right'}`);
}
function closePop(returnFocus = false) {
  if (!POP) return false;
  const {node, anchor, onClose} = POP;
  POP = null;
  anchor.setAttribute('aria-expanded', 'false');
  node.classList.add('leaving');
  setTimeout(() => node.remove(), REDUCED.matches ? 0 : 120);
  if (returnFocus && anchor.isConnected) anchor.focus({preventScroll: true});
  if (onClose) onClose();
  return true;
}
document.addEventListener('pointerdown', e => {
  if (POP && !POP.node.contains(e.target) && !POP.anchor.contains(e.target)) closePop();
}, true);
addEventListener('resize', () => closePop());

// Меню: groups — [[{label, act, icon, danger, disabled}], ...], между
// группами — разделитель. Стрелки, Home/End, Enter; Tab закрывает.
function openMenu(anchor, groups, label = 'Действия') {
  if (POP && POP.anchor === anchor) { closePop(); return; }
  const items = [];
  const m = el('div', {class: 'menu', role: 'menu', 'aria-label': label});
  groups.filter(g => g.length).forEach((g, gi) => {
    if (gi) m.append(el('hr'));
    g.forEach(it => {
      const b = el('button', {role: 'menuitem', class: it.danger ? 'danger' : null,
                              disabled: it.disabled, tabindex: '-1'},
                   it.icon ? icon(it.icon) : null, el('span', {text: it.label}));
      b.addEventListener('click', () => { closePop(true); it.act(); });
      items.push(b);
      m.append(b);
    });
  });
  m.addEventListener('keydown', e => {
    const live = items.filter(b => !b.disabled);
    const i = live.indexOf(document.activeElement);
    const go = j => { e.preventDefault(); live[(j + live.length) % live.length].focus(); };
    if (e.key === 'ArrowDown') go(i + 1);
    else if (e.key === 'ArrowUp') go(i - 1);
    else if (e.key === 'Home') go(0);
    else if (e.key === 'End') go(live.length - 1);
    else if (e.key === 'Tab') closePop(true);
  });
  anchor.setAttribute('aria-haspopup', 'menu');
  return openPop(anchor, m);
}

// ---------------------------------------------------------------- лист
// Один лист за раз: новый заменяет прежний (вопрос «Переподключить VPN?»
// встаёт поверх «Туннелирования» — тот уже сохранён).
let SHEET = null;   // {scrim, box, onClose, onEsc, back}

// buttons — [{label, act, kind: 'primary'|'danger'|'ghost', id, disabled}]:
// основное справа, вспомогательные слева (left: true).
function openSheet({title, body, buttons = [], cls = '', onClose, onEsc, role = 'dialog'}) {
  const back = SHEET ? SHEET.back : document.activeElement;
  dropSheet();
  closePop();
  hideTip();
  const head = el('div', {class: 'sheet-head'},
                  el('h2', {class: 'ell', id: 'sheet-title', text: title, 'data-tip': title}),
                  ibtn('close', 'Закрыть', {onclick: () => escSheet()}));
  const left = buttons.filter(b => b.left), right = buttons.filter(b => !b.left);
  const btn = b => el('button', {class: `btn ${b.kind || ''}`, id: b.id, disabled: b.disabled,
                                  onclick: () => b.act()}, b.icon ? icon(b.icon) : null, b.label);
  const foot = buttons.length
    ? el('div', {class: 'sheet-foot'}, left.map(btn), el('span', {class: 'grow'}), right.map(btn)) : null;
  const box = el('div', {class: `sheet ${cls}`, role, 'aria-modal': 'true', 'aria-labelledby': 'sheet-title'},
                 head, el('div', {class: 'sheet-body scroll'}, body), foot);
  const scrim = el('div', {class: 'scrim'}, box);
  scrim.addEventListener('pointerdown', e => { if (e.target === scrim) escSheet(); });
  $('layer-sheet').append(scrim);
  SHEET = {scrim, box, onClose, onEsc, back};
  const first = box.querySelector('textarea, input, .sheet-foot .btn.primary, .sheet-foot .btn, .sheet-body button')
             || head.querySelector('button');
  if (first) first.focus({preventScroll: true});
  return box;
}

function dropSheet() {
  if (!SHEET) return;
  const {scrim, onClose} = SHEET;
  SHEET = null;
  scrim.classList.add('leaving');
  setTimeout(() => scrim.remove(), REDUCED.matches ? 0 : FADE_MS);
  if (onClose) onClose();
}

// Закрыть лист: Python зовёт после удаления и переноса конфига.
function closeSheet() {
  const back = SHEET && SHEET.back;
  dropSheet();
  if (back && back.isConnected) back.focus({preventScroll: true});
}

// Esc и крестик: у листа может быть свой безопасный выход (вопрос «Отменить
// изменения?» у правил).
function escSheet() {
  if (!SHEET) return false;
  if (SHEET.onEsc) SHEET.onEsc(); else closeSheet();
  return true;
}

// Вопрос: заголовок, одно-два предложения последствий, кнопки. Основное
// справа, разрушительное — красным; Esc — безопасный вариант (safe).
function ask({title, text, buttons, safe}) {
  const body = el('div', {}, (Array.isArray(text) ? text : [text]).map(t => el('p', {text: t})));
  return openSheet({title, body, cls: 'ask', role: 'alertdialog', buttons,
                    onEsc: () => (safe ? safe() : closeSheet())});
}

// Фокус не уходит из листа: Tab по кругу внутри.
document.addEventListener('keydown', e => {
  if (e.key !== 'Tab' || !SHEET || POP) return;
  const f = [...SHEET.box.querySelectorAll('button, textarea, input, [tabindex="0"]')]
    .filter(n => !n.disabled && n.offsetParent !== null);
  if (!f.length) return;
  const i = f.indexOf(document.activeElement);
  if (e.shiftKey && i <= 0) { e.preventDefault(); f[f.length - 1].focus(); }
  else if (!e.shiftKey && i === f.length - 1) { e.preventDefault(); f[0].focus(); }
});

// ------------------------------------------------------------- состояние
// Последний статус службы (window.refresh → render). Разделы подписываются
// через onRender и получают его вместе с выводами model (js/model.js).
let LAST = {};
const RENDERERS = [];
const onRender = fn => RENDERERS.push(fn);

function render(s) {
  LAST = s || {};
  const m = typeof model === 'function' ? model(LAST) : null;
  for (const fn of RENDERERS) {
    try { fn(LAST, m); } catch (e) { reportError(`render/${fn.name}`, e); }
  }
  tick('status');
}

// ---------------------------------------------------------------- вкладки
let TAB = 'tunnels';
const TAB_HOOKS = [];   // (tab) => void: раздел узнаёт, что его открыли
function showTab(name) {
  if (name === TAB) return;
  TAB = name;
  closePop();
  document.querySelectorAll('#tabs .tab').forEach(t => setAttr(t, 'aria-selected', String(t.dataset.tab === name)));
  document.querySelectorAll('.pane').forEach(p => show(p, p.id === `pane-${name}`));
  TAB_HOOKS.forEach(fn => fn(name));
}
$('tabs').addEventListener('click', e => {
  const t = e.target.closest('.tab');
  if (t) showTab(t.dataset.tab);
});
// Стрелки по вкладкам — как у системного tablist.
$('tabs').addEventListener('keydown', e => {
  if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
  const tabs = [...document.querySelectorAll('#tabs .tab')];
  const i = tabs.findIndex(t => t.dataset.tab === TAB) + (e.key === 'ArrowRight' ? 1 : -1);
  const t = tabs[(i + tabs.length) % tabs.length];
  showTab(t.dataset.tab);
  t.focus();
});

// -------------------------------------------------------------- клавиатура
// Esc закрывает верхнее: подсказку, меню, лист. Ctrl+R — проверить все (а не
// перезагрузить страницу), Ctrl+F — поиск в журнале.
const KEYS = {};   // 'ctrl+r' → обработчик; разделы дописывают свои
addEventListener('keydown', e => {
  if (e.key === 'Tab') document.body.classList.add('kbd');
  if (e.key === 'Escape') {
    if (!$('tip').hidden) { hideTip(); return; }
    if (closePop(true) || escSheet()) { e.preventDefault(); return; }
  }
  const combo = `${e.ctrlKey ? 'ctrl+' : ''}${e.key.toLowerCase()}`;
  if (KEYS[combo]) { e.preventDefault(); KEYS[combo](e); }
});
addEventListener('mousedown', () => document.body.classList.remove('kbd'));
// Ctrl+R в WebView2 перезагрузил бы страницу и до обработчика раздела.
KEYS['ctrl+r'] = () => {};
KEYS['f5'] = () => {};
