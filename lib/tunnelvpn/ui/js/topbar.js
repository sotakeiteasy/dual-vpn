'use strict';
/* Топ-бар: состояние VPN одной фразой, адрес выхода, кнопки и пилюля
   проблем. Высота постоянная: строка выхода держит место и без адреса, а
   пилюля встаёт слева от кнопок — те не сдвигаются. */

// Команда отправлена, состояние ещё не догнало: {mode: start|stop|restart,
// at, sawDown}. Без этого кнопка выглядела мёртвой — нажал, ничего не
// изменилось, и хочется нажать снова.
let PENDING = null;
// Страховка от залипания: служба не ответила статусом — кнопки отпускаем.
const PENDING_MS = 25000;
const INSTALL_CMD = 'tunnelvpn service install';

function busyNow(s) {
  if (!PENDING) return false;
  if (Date.now() - PENDING.at > PENDING_MS) return false;
  // Рестарт нельзя ждать сравнением с желаемым: жмут его при поднятом
  // туннеле, и «уже как надо» получается сразу. Ждём полный цикл.
  if (PENDING.mode === 'restart') {
    if (!s.up) PENDING.sawDown = true;
    return !(PENDING.sawDown && s.up);
  }
  return !!s.up !== (PENDING.mode === 'start');
}

// Перезапуск ждёт и askFull (лист «Переподключить VPN?»): там тот же цикл.
function pend(mode) {
  PENDING = {mode, at: Date.now(), sawDown: false};
  render(LAST);
}

// failed (core): операция не пошла — кнопки отпускаем.
ON_FAILED.push(function releaseTop() {
  if (!PENDING) return;
  PENDING = null;
  render(LAST);
});

function toggleVpn() {
  const mode = LAST.up ? 'stop' : 'start';
  send(mode);
  pend(mode);
}
function restartVpn() {
  send('restart');
  pend('restart');
}
function checkAll() {
  if (TOP.check.disabled) return;
  CHECK_BY_HAND = true;
  checkStart();
  send('check');
}

// ------------------------------------------------------------------ разметка
// Кнопка с подписью; .cbtn на узком окне — только значок (подсказка —
// data-tip: core показывает её, лишь когда подпись скрыта).
const tbtn = (id, ic, label, onclick, cls = 'cbtn') =>
  el('button', {class: `btn ${cls}`, id, 'data-tip': label, onclick},
     icon('busy', 'spin'), icon(ic), el('span', {class: 'lbl', text: label}));

const TOP = (() => {
  const box = $('top');
  const t = {
    orb: orb('busy', 'big'),
    title: el('h1', {class: 'top-title ell'}),
    sub: el('div', {class: 'top-sub ell'}),
    ip: el('span', {class: 'val mono ell'}),
    place: el('span', {class: 'top-place ell'}),
    copy: el('button', {class: 'link', text: 'копировать', onclick: copyIp}),
    pill: el('button', {class: 'pill', id: 'pill', 'aria-haspopup': 'dialog', 'aria-expanded': 'false',
                        hidden: true, onclick: () => openProblems()}),
    toggle: tbtn('btn-toggle', 'power', 'Включить', toggleVpn, ''),
    restart: tbtn('btn-restart', 'restart', 'Перезапустить', restartVpn),
    check: ibtn('refresh', 'Проверить все', {id: 'btn-check', 'data-tip': 'Проверить все · Ctrl+R',
                                             onclick: checkAll}),
    add: tbtn('btn-add', 'plus', 'Добавить конфиг', () => send('add_config', {})),
  };
  t.exit = el('div', {class: 'top-exit'}, el('span', {text: 'выход'}), t.ip, t.place, t.copy);
  t.actions = el('div', {class: 'top-actions'}, t.pill, t.toggle, t.restart, t.check, t.add);
  t.install = el('div', {class: 'top-actions top-install', hidden: true},
                 el('code', {class: 'val', text: INSTALL_CMD}),
                 el('button', {class: 'btn', onclick: copyInstall}, icon('copy'), 'Скопировать команду'));
  box.append(t.orb, t.title, t.actions, t.install, t.sub, t.exit);
  return t;
})();

async function copyIp() {
  const ok = await copyText(TOP.ip.textContent);
  toast(ok ? 'Адрес выхода скопирован' : 'Не вышло → выдели адрес и нажми Ctrl+C', ok ? 'ok' : 'err');
}
async function copyInstall() {
  const ok = await copyText(INSTALL_CMD);
  toast(ok ? 'Команда скопирована → вставь её в терминал администратора'
           : 'Не вышло → выдели команду и нажми Ctrl+C', ok ? 'ok' : 'err');
}

// --------------------------------------------------------------- отрисовка
function paintTop(s, m) {
  const {head} = m;
  setKind($('top'), head.kind);
  setOrb(TOP.orb, head.kind);
  if (setText(TOP.title, head.title, true)) setTip(TOP.title, head.title);
  if (setText(TOP.sub, head.sub)) setTip(TOP.sub, head.sub);

  // Тот же адрес не переписываем (setText): опрос снимал бы выделение.
  const ip = s.up ? s.exit_ip || '' : '';
  setText(TOP.ip, ip);
  setTip(TOP.ip, ip);
  const place = ip ? [s.exit_country, s.exit_city].filter(Boolean).join(', ') : '';
  setText(TOP.place, place);
  setTip(TOP.place, place && [place, s.exit_org].filter(Boolean).join(' · '));
  TOP.exit.classList.toggle('vacant', !ip);

  show(TOP.actions, !m.noService);
  show(TOP.install, m.noDaemon);
  paintButtons(s, m);
  paintPill(m);
}
onRender(paintTop);

function paintButtons(s, m) {
  const wasRestart = PENDING && PENDING.mode === 'restart';
  const busy = busyNow(s);
  if (PENDING && !busy) PENDING = null;
  // Служба занята своей операцией (команда из трея, переподключение) —
  // команда из окна вернула бы только «уже идёт».
  const svc = s.busy || '';
  const off = !!s.loading || m.noService || busy || !!svc;

  let label = s.up ? 'Выключить' : 'Включить';
  let working = false;
  if (busy && !wasRestart) { label = PENDING.mode === 'start' ? 'Включаю…' : 'Выключаю…'; working = true; }
  else if (svc === 'включаю' || svc === 'выключаю') { label = `${svc[0].toUpperCase()}${svc.slice(1)}…`; working = true; }
  const t = TOP.toggle;
  setText(t.querySelector('.lbl'), label);
  setTip(t, label);
  t.classList.toggle('working', working);
  // Главная — только «Включить»: выключение не должно звать к себе цветом.
  t.classList.toggle('primary', !s.up && !working);
  setDisabled(t, off || m.missing);

  const r = TOP.restart;
  const restarting = busy && wasRestart;
  setText(r.querySelector('.lbl'), restarting ? 'Перезапускаю…' : 'Перезапустить');
  r.classList.toggle('working', restarting);
  setDisabled(r, off || !s.up);

  // Без VPN мерить нечем: проверка показывает, как туннели работают сейчас.
  TOP.check.classList.toggle('working', CHECKING);
  setDisabled(TOP.check, off || CHECKING || !s.up);
  setDisabled(TOP.add, !!s.loading || m.noService);
}

// ------------------------------------------------------------ проблемы
// Пилюля «2 ошибки · 1 предупреждение ▾», цвет — по худшей; по клику —
// панель, сгруппированная по туннелю, у каждой проблемы — кнопка действия.
let PROB_SIG = '';
const ACTS = {
  check: ['Проверить', () => checkAll()],
  rules: ['Туннелирование…', p => send('tunnel_rules', p.id)],
  log: ['Журнал', () => showTab('log')],
  card: ['Открыть карточку', p => focusCard(p.id)],   // cards.js
  restart: ['Перезапустить', () => restartVpn()],
  add: ['Добавить…', p => send('add_config', {tunnel: p.id})],
};

function paintPill(m) {
  const sig = JSON.stringify(m.problems);
  if (sig === PROB_SIG) return;
  PROB_SIG = sig;
  const pill = TOP.pill;
  show(pill, m.problems.length > 0);
  if (!m.problems.length) {
    if (POP && POP.anchor === pill) closePop();
    return;
  }
  setKind(pill, m.worst);
  const err = m.problems.filter(p => p.kind === 'err').length, warn = m.problems.length - err;
  const part = (kind, n, forms) => n ? el('span', {class: `cnt st-${kind}`}, icon(kind),
    el('span', {class: 'n', text: n}), el('span', {class: 'lbl', text: plural(n, forms).replace(/^\d+/, '')})) : null;
  pill.replaceChildren(...[part('err', err, ['ошибка', 'ошибки', 'ошибок']),
                           part('warn', warn, ['предупреждение', 'предупреждения', 'предупреждений']),
                           icon('chev', 'chev')].filter(Boolean));
  const text = problemCount(m.problems);
  setAttr(pill, 'aria-label', `${text} — показать`);
  setTip(pill, text);
  if (POP && POP.anchor === pill) fillProblems(POP.node, m.problems);
}

function openProblems() {
  const pill = TOP.pill;
  if (POP && POP.anchor === pill) { closePop(); return; }
  const node = el('div', {class: 'probs scroll', role: 'dialog', 'aria-label': 'Проблемы'});
  fillProblems(node, model(LAST).problems);
  openPop(pill, node);
}

function fillProblems(node, problems) {
  const groups = new Map();
  for (const p of problems) {
    const k = `${p.id}\n${p.where}`;
    if (!groups.has(k)) groups.set(k, {where: p.where, items: []});
    groups.get(k).items.push(p);
  }
  node.replaceChildren(...[...groups.values()].map(g => el('section', {class: 'probs-group'},
    el('h3', {class: 'probs-where ell', text: g.where, 'data-tip': g.where}),
    g.items.map(p => {
      const [label, run] = ACTS[p.act];
      return el('div', {class: 'prob'}, orb(p.kind),
        el('div', {class: 'prob-text'}, el('div', {class: 'val', text: p.text}),
           el('div', {class: 'prob-fix', text: `→ ${p.fix}`})),
        el('button', {class: 'btn sm', onclick: () => { closePop(); run(p); }}, label));
    }))));
}

// ------------------------------------------------------------ клавиатура
KEYS['ctrl+r'] = checkAll;

// До первого статуса — «Подключаюсь к службе…», кнопки недоступны.
LAST = {loading: true};
paintTop(LAST, model(LAST));
