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
  else if (!corp)    { cls = 'warn'; title = 'Корп не отвечает';
                       sub = 'личный туннель работает, интернет есть'; }
  else               { cls = 'ok';   title = 'Всё работает'; sub = 'оба туннеля подняты';
                       // Бывшая строка «выход»: ошибки в логе при зелёных
                       // туннелях — единственный намёк, что что-то не так.
                       if (s.err_count) sub += ' · ошибок в логе: ' + s.err_count; }

  // Строки туннелей: имя, точка состояния, адрес, задержка. Выключено — строк
  // нет вовсе: прочерки повторяли бы заголовок. Слово состояния ушло в
  // подсказку точки — цвет его и так передаёт, а строка стала короче.
  const ms = v => (typeof v === 'number' ? v + ' мс' : '');
  const rows = [];
  if (up) {
    const st = s.exit_state;
    const place = [s.exit_country, s.exit_city].filter(Boolean).join(' ');
    rows.push({name: 'личный',
               value: s.exit_ip ? [s.exit_ip, place].filter(Boolean).join(' · ') : '—',
               dot: st === 'leak' ? 'bad' : st === 'tunnel' ? 'ok' : 'off',
               label: st === 'leak' ? 'мимо туннеля' : st === 'tunnel' ? 'через туннель' : 'проверяю…',
               ms: s.exit_ip ? ms(s.exit_ms) : ''});
    rows.push({name: 'корп', value: s.corp_ip || '—',
               dot: corp ? 'ok' : 'bad', label: corp ? 'отвечает' : 'молчит',
               ms: corp ? ms(s.corp_ms) : ''});
  }
  const probing = !!s.probing;

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
    // Ручная проверка: пока идёт, кнопка крутится и не нажимается.
    check: {disabled: busy || !up || probing, probing: up && probing},
    // При поднятом туннеле конфиги не трогаются (см. #confs-wrap.locked).
    locked: up,
  };
}

if (typeof module !== 'undefined') module.exports = {viewModel, BUSY_TITLE};
