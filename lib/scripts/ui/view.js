// Что показать в окне по состоянию из Python — без DOM, чтобы проверять тестами
// (tests/test_view.js гоняет это под node).
//
// Раньше это решалось прямо в render() вперемешку с разметкой, и состояние
// кнопок угадывалось по косвенным признакам: нажали — ждём, пока `up`
// станет нужным, но не дольше 25 с. Упала служба — через 25 с кнопка молча
// отпускалась, и было непонятно, что случилось. Теперь фаза операции и её
// исход приходят из контроллера (control.py) явно.

// Язык окна выставляет window.py до разбора страницы (lang у <html>), так же
// как тему. Строки пишутся на месте парой tr(ru, en) — см. i18n.py.
let LANG = typeof document !== 'undefined' && document.documentElement.lang === 'en' ? 'en' : 'ru';
function setLang(l) { LANG = l === 'en' ? 'en' : 'ru'; }
function tr(ru, en) { return LANG === 'en' ? en : ru; }

const BUSY_TITLE = {
  starting:   ['Включаю…', 'Turning on…'],
  stopping:   ['Выключаю…', 'Turning off…'],
  restarting: ['Перезапускаю…', 'Restarting…'],
};
const busyTitle = phase => tr(...(BUSY_TITLE[phase] || ['Подожди…', 'Please wait…']));

function firstLine(t) {
  return String(t || '').trim().split('\n')[0] || '';
}

function viewModel(s) {
  s = s || {};
  const op = s.op || {phase: 'idle', step: '', busy: false};
  const up = !!s.up, corp = !!s.corp_ip, leak = s.v6_leak;
  // До первого ответа корп не «молчит», а ещё не проверен. Поля нет у службы
  // старше окна — тогда как раньше: пустой адрес значит «молчит».
  const corpPending = !corp && s.corp_state === 'unknown';
  // Туннель, выключенный кликом по строке, — не поломка: его не меряют.
  const corpOff = s.corp_state === 'off', personalOff = s.exit_state === 'off';
  const noDaemon = s.daemon === false;
  const busy = !!op.busy;
  const error = !up && !busy && s.error ? String(s.error).trim() : '';
  const direct = tr('личный выключен, интернет идёт напрямую',
                    'personal is off, internet goes direct');

  // Главная строка. Порядок важен: первым — то, что человеку делать.
  let cls = 'off', title = tr('Выключено', 'Off'), sub = tr('туннели не подняты', 'tunnels are down');
  if (noDaemon)      { cls = 'warn'; title = tr('Нужна установка', 'Setup needed');
                       sub = tr('фоновая служба ещё не поставлена',
                                'the background service isn’t installed yet'); }
  else if (busy)     { cls = 'off';  title = busyTitle(op.phase);
                       sub = op.step || ''; }
  else if (error)    { cls = 'bad';  title = tr('Не удалось включить', 'Couldn’t turn on');
                       sub = firstLine(error); }
  else if (leak)     { cls = 'bad';  title = tr('Утечка IPv6', 'IPv6 leak');
                       sub = tr('часть трафика идёт мимо туннеля: ',
                                'some traffic bypasses the tunnel: ') + leak; }
  else if (!up)      { /* выключено — значения по умолчанию */ }
  // Заголовок обязан отражать все строки ниже, иначе получается прямое
  // противоречие: сверху «всё работает», а в личном — «мимо туннеля».
  else if (s.exit_state === 'leak') { cls = 'bad';
                       title = tr('Трафик мимо туннеля', 'Traffic bypasses the tunnel');
                       sub = tr('тебя видно адресом провайдера ',
                                'you’re visible by your ISP address ') + (s.exit_ip || ''); }
  // Поднят, но трафик не идёт: без этого окно вечно писало «проверяю».
  else if (s.exit_state === 'down') { cls = 'bad';
                       title = tr('Туннель не работает', 'Tunnel is down');
                       sub = tr('личный не отвечает — перезапусти',
                                'personal isn’t responding — restart'); }
  else if (corpPending) { cls = 'off'; title = tr('Проверяю туннели…', 'Checking tunnels…');
                       sub = tr('первая проверка после включения', 'first check after turning on'); }
  else if (corpOff)  { cls = 'ok';   title = tr('Работает только личный', 'Only personal is on');
                       sub = tr('корп выключен — нажми на строку, чтобы включить',
                                'corp is off — click its row to turn it on'); }
  else if (!corp)    { cls = 'warn'; title = tr('Корп не отвечает', 'Corp isn’t responding');
                       sub = personalOff ? direct
                                         : tr('личный туннель работает, интернет есть',
                                              'personal tunnel works, internet is up'); }
  else if (personalOff) { cls = 'ok'; title = tr('Работает только корп', 'Only corp is on');
                       sub = direct; }
  // Счётчика ошибок лога здесь нет: при рабочих туннелях он пугал зря и
  // переносил строку. Ошибки видны в самом логе (фильтр «только ошибки»).
  else               { cls = 'ok';   title = tr('Всё работает', 'All working');
                       sub = tr('оба туннеля подняты', 'both tunnels are up'); }

  // Строки туннелей: имя, точка состояния, адрес, задержка. Выключено — строк
  // нет вовсе: прочерки повторяли бы заголовок. Слово состояния ушло в
  // подсказку точки — цвет его и так передаёт, а строка стала короче.
  // Пока идёт ручная проверка, вместо цифр — индикатор замера (measuring):
  // замер выдаёт почти те же числа, и без него не видно, что он вообще был.
  const manual = !!s.probing_manual;
  const ms = v => (manual ? '' : typeof v === 'number' ? v + tr(' мс', ' ms') : '');
  const off = tr('выключен', 'off'), checking = tr('проверяю…', 'checking…');
  const pname = tr('личный', 'personal'), cname = tr('корп', 'corp');
  // Строка — она же переключатель туннеля (tunnel): клик выключает его или
  // включает обратно. Выключить второй, пока первый выключен, нельзя
  // (toggleable: false) — без обоих туннелей это просто «Выключить».
  const rows = [];
  if (up) {
    const st = s.exit_state;
    rows.push(personalOff
      ? {name: pname, value: off, dot: 'off', label: off,
         ms: '', measuring: false, tunnel: 'personal', off: true, toggleable: true}
      : {name: pname,
         value: s.exit_ip ? [s.exit_ip, s.exit_country].filter(Boolean).join(' · ') : '—',
         dot: st === 'leak' || st === 'down' ? 'bad' : st === 'tunnel' ? 'ok' : 'off',
         label: st === 'leak' ? tr('мимо туннеля', 'bypassing tunnel')
              : st === 'down' ? tr('не отвечает', 'not responding')
              : st === 'tunnel' ? tr('через туннель', 'via tunnel') : checking,
         // Пинг от адреса не зависит: адрес не узнали — задержку всё равно видно.
         ms: ms(s.exit_ms), measuring: manual,
         tunnel: 'personal', off: false, toggleable: !corpOff});
    rows.push(corpOff
      ? {name: cname, value: off, dot: 'off', label: off,
         ms: '', measuring: false, tunnel: 'corp', off: true, toggleable: true}
      : {name: cname, value: s.corp_ip || '—',
         dot: corp ? 'ok' : corpPending ? 'off' : 'bad',
         label: corp ? tr('отвечает', 'responding') : corpPending ? checking
              : tr('молчит', 'silent'),
         ms: corp ? ms(s.corp_ms) : '', measuring: manual,
         tunnel: 'corp', off: false, toggleable: !personalOff});
  }

  return {
    cls, title, sub, rows,
    // Пока идёт операция, окно закрыто целиком: любое нажатие посреди
    // выключения — это гонка с уборкой маршрутов.
    busy: busy ? {title: busyTitle(op.phase), step: op.step || ''} : null,
    error: error ? {
      head: firstLine(error),
      more: error.split('\n').slice(1).join('\n').trim(),
      log: (s.error_log || []).slice(-12),
    } : null,
    install: noDaemon,
    toggle: {label: up ? tr('Выключить', 'Turn Off')
                       : (error ? tr('Повторить', 'Retry') : tr('Включить', 'Turn On')),
             primary: !up, disabled: busy},
    restart: {disabled: busy || !up},
    // Крутится только ручная проверка. Плановая (probing) идёт раз в
    // полминуты, и кнопка от неё крутилась и гасла сама по себе.
    check: {disabled: busy || !up || manual, probing: up && manual},
    // При поднятом туннеле конфиги не трогаются (см. #confs-wrap.locked).
    locked: up,
  };
}

// Подвал: версия и, если вышла новая, строка обновления с кнопкой.
// v.update.state: '' — новее нет, available, working (идёт), error.
function versionModel(v) {
  v = v || {};
  const u = v.update || {};
  const text = `DualVPN ${v.app || '?'}` + (v.singbox ? ` · sing-box ${v.singbox}` : '');
  let update = null;
  if (u.state === 'available') {
    update = {text: tr(`есть ${u.version}`, `${u.version} available`),
              action: tr('Обновить', 'Update'), bad: false};
  } else if (u.state === 'working') {
    update = {text: tr(`обновляю до ${u.version}: ${u.step}…`,
                       `updating to ${u.version}: ${u.step}…`), action: null, bad: false};
  } else if (u.state === 'error') {
    update = {text: tr(`${u.version} не встала: `, `${u.version} failed: `) + firstLine(u.error),
              action: tr('Повторить', 'Retry'), bad: true};
  }
  return {text, update};
}

// Тема окна: по кругу системная → светлая → тёмная. Незнакомое значение
// (битый файл, старая версия) — как системная.
const THEMES = ['system', 'light', 'dark'];
const THEME_TITLE = {system: ['Тема: как в системе', 'Theme: system'],
                     light: ['Тема: светлая', 'Theme: light'],
                     dark: ['Тема: тёмная', 'Theme: dark']};
const themeTitle = t => tr(...THEME_TITLE[t]);

function nextTheme(t) {
  return THEMES[(Math.max(THEMES.indexOf(t), 0) + 1) % THEMES.length];
}

if (typeof module !== 'undefined') {
  module.exports = {viewModel, versionModel, BUSY_TITLE, THEMES, THEME_TITLE, themeTitle,
                    nextTheme, setLang, tr};
}
