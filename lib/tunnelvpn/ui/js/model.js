'use strict';
/* Выводы из статуса службы, общие для разделов: основной туннель, запасной
   выход, молчащие туннели, заголовок окна и список проблем. render (core)
   зовёт model(s) раз на статус и раздаёт итог разделам вторым аргументом. */

// В окне туннель зовётся своим конфигом (решение #12), имя туннеля — запасное.
const tname = t => t.active || t.name;
const hasConf = t => !!(t.confs || []).length;

// ------------------------------------------------- проверка всех туннелей
// Идёт проверка — по кнопке, при открытии окна или сама после подъёма
// туннеля. CHECK_LEFT — id туннелей, чей ответ ещё не пришёл: быстрый не
// ждёт молчащего. CHECK_BY_HAND — итог покажет уведомление (по кнопке).
let CHECKING = false;
let CHECK_LEFT = new Set();
let CHECK_BY_HAND = false;

// Python зовёт их и при сбое службы: кнопка не должна застрять.
function checkStart() {
  CHECKING = true;
  CHECK_LEFT = new Set((LAST.tunnels || []).map(t => t.id));
  render(LAST);
}
// Один туннель проверен, другие ещё ждут: перекрашивается только проверенный.
function checkSides(s, left) {
  CHECK_LEFT = new Set(left.filter(k => CHECK_LEFT.has(k)));
  render(s);
}
function checkDone() {
  CHECKING = false;
  CHECK_LEFT = new Set();
  render(LAST);
  if (CHECK_BY_HAND) {
    CHECK_BY_HAND = false;
    const m = model(LAST);
    if (LAST.up) toast(m.problems.length ? `Проверено: ${problemCount(m.problems)}` : 'Проверено: все туннели отвечают',
                       m.worst || 'ok');
  }
}

// ---------------------------------------------------------------- модель
function model(s) {
  const up = !!s.up;
  const T = s.tunnels || [];
  const main = T.find(t => t.mode === 'all');
  // Пока идёт проверка, прежний ответ устарел: «не отвечает» от прошлой
  // проверки читалось бы как свежий результат. Каждый туннель по себе.
  const checking = t => up && ((CHECKING && CHECK_LEFT.has(t.id)) || !!t.checking);
  // Основной не работает, и служба увела выход напрямую: адрес провайдера
  // тогда ожидаем, это не утечка. Без основного напрямую идёт всё — так задумано.
  const direct = !!main && (s.out === 'direct' || s.exit_state === 'direct');
  // «По списку» молчит, а остальное работает — отдельный случай, не «всё сломалось».
  const silent = up ? T.filter(t => t.mode === 'list' && t.enabled !== false
                                   && t.check === 'error' && !checking(t)) : [];
  // Без службы кнопки бессмысленны: портативной её не нужно, установленной —
  // нужна установка (daemon === false) или она не отвечает.
  const noService = !!s.no_service;
  const noDaemon = noService && s.daemon === false && !s.portable;
  // Туннель без конфига сборка пропускает, без всех — не соберёт
  // (buildconfig.py:build). Говорим заранее, а не «Не запускается» после нажатия.
  const missing = !noService && !up && !!s.tunnels && !T.some(hasConf);
  const ctx = {s, up, T, main, checking, direct, silent, noService, noDaemon, missing};
  const problems = problemsOf(ctx);
  const worst = problems.length ? problems[0].kind : '';
  return {...ctx, head: headOf(ctx), problems, worst};
}

// Заголовок: {kind, title, sub}. Порядок веток — как у значка трея
// (tray.py:_tray_state): утечка IPv6 раньше запасного выхода, на запасном
// выходе адрес провайдера ожидаем.
function headOf({s, up, T, main, direct, silent, noService, noDaemon, missing}) {
  if (s.loading) return {kind: 'busy', title: 'Подключаюсь к службе…', sub: ''};
  if (noDaemon) return {kind: 'unset', title: 'Нужна установка',
                        sub: 'служба Windows не установлена — без неё VPN не включить'};
  if (noService) return s.portable
    ? {kind: 'err', title: 'Служба не отвечает',
       sub: 'VPN держит процесс в трее → закрой окно и запусти TunnelVPN-Portable.exe заново'}
    : {kind: 'err', title: 'Служба не отвечает',
       sub: 'служба TunnelVPN остановлена → запусти её в «Службах» Windows или перезагрузи компьютер'};
  if (missing) return {kind: 'unset', title: 'Добавь конфиг', sub: 'без него VPN не включится'};
  // Служба сама снимает и поднимает туннель: на это время up ложный, и без
  // этой ветки заголовок мигал бы «Выключено» или прошлой ошибкой.
  if (s.busy === 'переподключаю') return {kind: 'busy', title: 'Переподключаю',
                                          sub: 'сменилась сеть — поднимаю туннель заново'};
  // Сторож перезапускает процесс одного туннеля: up при этом истинный, tun цел.
  if (up && (s.busy || '').startsWith('перезапускаю')) {
    return {kind: 'busy', title: 'Перезапускаю', sub: `${s.busy}, интернет работает`};
  }
  if (s.v6_leak) return {kind: 'err', title: 'Утечка IPv6',
                         sub: `часть трафика идёт мимо туннеля: ${s.v6_leak}`};
  // Не поднялся и не просто выключен — причина, а не пустота.
  if (!up && s.last_error) return {kind: 'err', title: 'Не запускается', sub: s.last_error};
  if (!up) return {kind: 'off', title: 'Выключено', sub: 'VPN не включён'};
  // Заголовок обязан отражать карточки ниже: сверху «всё работает», а у
  // основного — «мимо туннеля» было бы прямым противоречием.
  if (direct) return {kind: 'warn', title: 'Запасной выход',
                      sub: `«${tname(main)}» не работает, интернет идёт напрямую`};
  if (s.exit_state === 'leak') return {kind: 'err', title: 'Трафик мимо туннеля',
                                       sub: 'Сайты видят адрес провайдера → Перезапустить или проверь основной туннель'};
  if (silent.length) {
    return {kind: 'warn',
            title: silent.length === 1 ? `«${tname(silent[0])}» не отвечает` : 'Туннели не отвечают',
            sub: silent.length < T.length ? 'остальные туннели работают' : 'туннели подняты, но молчат'};
  }
  const live = T.filter(t => t.enabled !== false).length;
  return {kind: 'ok', title: 'Всё работает',
          sub: !main ? 'всё остальное — напрямую, без VPN' : live > 1 ? 'туннели подняты' : 'туннель поднят'};
}

// Проблемы для пилюли и панели: {kind: err|warn, id (туннель или ''), where,
// text, fix, act}. act — что предложить: check, rules, log, card, restart,
// add (topbar.js). Ошибки раньше предупреждений, внутри — по порядку туннелей.
function problemsOf({s, up, T, main, checking, direct, noService}) {
  if (noService || s.loading) return [];
  const out = [];
  const vpn = (kind, text, fix, act) => out.push({kind, id: '', where: 'VPN', text, fix, act});
  const of = (t, kind, text, fix, act) => out.push({kind, id: t.id, where: tname(t), text, fix, act});

  if (s.v6_leak) vpn('err', `Утечка IPv6: ${s.v6_leak}`, 'перезапусти VPN', 'restart');
  if (!up && s.last_error) vpn('err', `Не запускается: ${s.last_error}`, 'подробности — в журнале', 'log');
  if (up && direct) of(main, 'warn', 'не работает — интернет идёт напрямую', 'проверь конфиг или выбери запасной', 'card');
  else if (up && s.exit_state === 'leak') vpn('err', 'трафик идёт мимо туннеля', 'перезапусти VPN', 'restart');

  for (const t of T) {
    if (t.enabled === false) continue;
    if (!hasConf(t)) { of(t, 'warn', 'нет конфига', 'добавь файл .conf', 'add'); continue; }
    // Без active и с несколькими конфигами служба не выберет за человека.
    if (!t.active && t.confs.length > 1) {
      of(t, 'warn', 'не выбран конфиг — служба не поднимет туннель', 'выбери один в карточке', 'card');
      continue;
    }
    if (!up || t.mode !== 'list' || checking(t)) continue;
    if (t.check === 'error') of(t, 'warn', 'не отвечает', 'проверь ещё раз или загляни в журнал', 'check');
    else if (t.check === 'rules') {
      of(t, 'warn', `«${t.answer || ''}» через него не открывается`, 'проверь туннелирование', 'rules');
    } else if (t.check === 'none') {
      of(t, 'warn', 'нечем проверить', 'добавь домен в «Пускать через туннель»', 'rules');
    }
  }
  return out.sort((a, b) => (a.kind === b.kind ? 0 : a.kind === 'err' ? -1 : 1));
}

// «2 ошибки · 1 предупреждение».
function problemCount(problems) {
  const err = problems.filter(p => p.kind === 'err').length, warn = problems.length - err;
  return [err && plural(err, ['ошибка', 'ошибки', 'ошибок']),
          warn && plural(warn, ['предупреждение', 'предупреждения', 'предупреждений'])]
    .filter(Boolean).join(' · ');
}
