// Что показать в окне по состоянию из Python — без DOM, чтобы проверять тестами
// (tests/test_view.js гоняет это под node).
//
// Раньше это решалось прямо в render() вперемешку с разметкой, и состояние
// кнопок угадывалось по косвенным признакам: нажали — ждём, пока `up`
// станет нужным, но не дольше 25 с. Упала служба — через 25 с кнопка молча
// отпускалась, и было непонятно, что случилось. Теперь фаза операции и её
// исход приходят из контроллера (control.py) явно.

const BUSY_TITLE = {
  starting:   'Включаю…',
  stopping:   'Выключаю…',
  restarting: 'Перезапускаю…',
};

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
  const noDaemon = s.daemon === false;
  const busy = !!op.busy;
  const error = !up && !busy && s.error ? String(s.error).trim() : '';

  // Главная строка. Порядок важен: первым — то, что человеку делать.
  let cls = 'off', title = 'Выключено', sub = 'туннели не подняты';
  if (noDaemon)      { cls = 'warn'; title = 'Нужна установка';
                       sub = 'фоновая служба ещё не поставлена'; }
  else if (busy)     { cls = 'off';  title = BUSY_TITLE[op.phase] || 'Подожди…';
                       sub = op.step || ''; }
  else if (error)    { cls = 'bad';  title = 'Не удалось включить'; sub = firstLine(error); }
  else if (leak)     { cls = 'bad';  title = 'Утечка IPv6';
                       sub = 'часть трафика идёт мимо туннеля: ' + leak; }
  else if (!up)      { /* выключено — значения по умолчанию */ }
  // Заголовок обязан отражать все строки ниже, иначе получается прямое
  // противоречие: сверху «всё работает», а в личном — «мимо туннеля».
  else if (s.exit_state === 'leak') { cls = 'bad'; title = 'Трафик мимо туннеля';
                       sub = 'тебя видно адресом провайдера ' + (s.exit_ip || ''); }
  // Поднят, но трафик не идёт: без этого окно вечно писало «проверяю».
  else if (s.exit_state === 'down') { cls = 'bad'; title = 'Туннель не работает';
                       sub = 'личный не отвечает — перезапусти'; }
  else if (corpPending) { cls = 'off'; title = 'Проверяю туннели…';
                       sub = 'первая проверка после включения'; }
  else if (!corp)    { cls = 'warn'; title = 'Корп не отвечает';
                       sub = 'личный туннель работает, интернет есть'; }
  // Счётчика ошибок лога здесь нет: при рабочих туннелях он пугал зря и
  // переносил строку. Ошибки видны в самом логе (фильтр «только ошибки»).
  else               { cls = 'ok';   title = 'Всё работает'; sub = 'оба туннеля подняты'; }

  // Строки туннелей: имя, точка состояния, адрес, задержка. Выключено — строк
  // нет вовсе: прочерки повторяли бы заголовок. Слово состояния ушло в
  // подсказку точки — цвет его и так передаёт, а строка стала короче.
  // Пока идёт ручная проверка, вместо цифр — индикатор замера (measuring):
  // замер выдаёт почти те же числа, и без него не видно, что он вообще был.
  const manual = !!s.probing_manual;
  const ms = v => (manual ? '' : typeof v === 'number' ? v + ' мс' : '');
  const rows = [];
  if (up) {
    const st = s.exit_state;
    rows.push({name: 'личный',
               value: s.exit_ip ? [s.exit_ip, s.exit_country].filter(Boolean).join(' · ') : '—',
               dot: st === 'leak' || st === 'down' ? 'bad' : st === 'tunnel' ? 'ok' : 'off',
               label: st === 'leak' ? 'мимо туннеля' : st === 'down' ? 'не отвечает'
                    : st === 'tunnel' ? 'через туннель' : 'проверяю…',
               // Пинг от адреса не зависит: адрес не узнали — задержку всё равно видно.
               ms: ms(s.exit_ms), measuring: manual});
    rows.push({name: 'корп', value: s.corp_ip || '—',
               dot: corp ? 'ok' : corpPending ? 'off' : 'bad',
               label: corp ? 'отвечает' : corpPending ? 'проверяю…' : 'молчит',
               ms: corp ? ms(s.corp_ms) : '', measuring: manual});
  }

  return {
    cls, title, sub, rows,
    // Пока идёт операция, окно закрыто целиком: любое нажатие посреди
    // выключения — это гонка с уборкой маршрутов.
    busy: busy ? {title: BUSY_TITLE[op.phase] || 'Подожди…', step: op.step || ''} : null,
    error: error ? {
      head: firstLine(error),
      more: error.split('\n').slice(1).join('\n').trim(),
      log: (s.error_log || []).slice(-12),
    } : null,
    install: noDaemon,
    toggle: {label: up ? 'Выключить' : (error ? 'Повторить' : 'Включить'),
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
    update = {text: `есть ${u.version}`, action: 'Обновить', bad: false};
  } else if (u.state === 'working') {
    update = {text: `обновляю до ${u.version}: ${u.step}…`, action: null, bad: false};
  } else if (u.state === 'error') {
    update = {text: `${u.version} не встала: ${firstLine(u.error)}`,
              action: 'Повторить', bad: true};
  }
  return {text, update};
}

if (typeof module !== 'undefined') module.exports = {viewModel, versionModel, BUSY_TITLE};
