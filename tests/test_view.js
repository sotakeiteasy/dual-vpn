// Что показывает окно в каждом состоянии: lib/scripts/ui/view.js под node.
//
//   node --test tests/
//
// Без DOM: view.js — чистая функция от состояния, разметку рисует index.html.

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const {viewModel} = require(path.join(__dirname, '..', 'lib', 'scripts', 'ui', 'view.js'));

const IDLE = {phase: 'idle', step: '', busy: false};
const UP = {up: true, daemon: true, op: IDLE, exit_ip: '188.241.219.116',
            exit_state: 'tunnel', corp_ip: '172.15.0.5',
            exit_country: 'DE'};
const OFF = {up: false, daemon: true, op: IDLE};

test('выключено: «Включить», без строк туннелей, конфиги открыты', () => {
  const v = viewModel(OFF);
  assert.equal(v.title, 'Выключено');
  assert.equal(v.toggle.label, 'Включить');
  assert.equal(v.toggle.primary, true);
  assert.equal(v.restart.disabled, true);
  assert.deepEqual(v.rows, []);
  assert.equal(v.locked, false);
  assert.equal(v.busy, null);
  assert.equal(v.error, null);
});

test('включено: «Выключить», перезапуск доступен, конфиги закрыты', () => {
  const v = viewModel(UP);
  assert.equal(v.cls, 'ok');
  assert.equal(v.title, 'Всё работает');
  assert.equal(v.toggle.label, 'Выключить');
  assert.equal(v.toggle.primary, false);
  assert.equal(v.restart.disabled, false);
  assert.equal(v.locked, true);
  assert.deepEqual(v.rows.map(r => r.name), ['личный', 'корп']);
  assert.equal(v.rows[0].label, 'через туннель');
  assert.deepEqual(v.rows.map(r => r.dot), ['ok', 'ok']);
  assert.equal(v.check.disabled, false);
});

test('место выхода — в строке личного, после адреса', () => {
  assert.equal(viewModel(UP).rows[0].value, '188.241.219.116 · DE');
  const bare = viewModel({...UP, exit_country: ''});
  assert.equal(bare.rows[0].value, '188.241.219.116');
  assert.equal(viewModel({...UP, exit_ip: '', exit_state: 'unknown'}).rows[0].value, '—');
});

test('точка: проверяю — серая, мимо туннеля и молчит — красная', () => {
  assert.equal(viewModel({...UP, exit_ip: '', exit_state: 'unknown'}).rows[0].dot, 'off');
  assert.equal(viewModel({...UP, exit_state: 'leak'}).rows[0].dot, 'bad');
  assert.equal(viewModel({...UP, corp_ip: ''}).rows[1].dot, 'bad');
});

test('задержка — только после замера', () => {
  const v = viewModel({...UP, exit_ms: 42, corp_ms: 18});
  assert.deepEqual(v.rows.map(r => r.ms), ['42 мс', '18 мс']);
  assert.deepEqual(viewModel(UP).rows.map(r => r.ms), ['', '']);
  // Адрес не узнали (ipinfo в лимите) — задержка от этого не зависит.
  assert.equal(viewModel({...UP, exit_ip: '', exit_ms: 48}).rows[0].ms, '48 мс');
  assert.deepEqual(viewModel({...UP, exit_ms: null, corp_ms: null}).rows.map(r => r.ms), ['', '']);
  // Корп молчит — старая цифра соврала бы, что он отвечает.
  assert.equal(viewModel({...UP, corp_ip: '', corp_ms: 18}).rows[1].ms, '');
});

test('«Проверить» выключена без туннеля и пока идёт ручная проверка', () => {
  assert.equal(viewModel(OFF).check.disabled, true);
  const p = viewModel({...UP, probing: true, probing_manual: true, exit_ms: 42, corp_ms: 18});
  assert.equal(p.check.disabled, true);
  assert.equal(p.check.probing, true);
  // Старые цифры на время замера убраны — вместо них индикатор.
  assert.deepEqual(p.rows.map(r => r.ms), ['', '']);
  assert.deepEqual(p.rows.map(r => r.measuring), [true, true]);
  assert.equal(viewModel({...UP, op: {phase: 'restarting', busy: true, step: ''}}).check.disabled, true);
});

test('плановая проверка кнопку не крутит и цифры не прячет', () => {
  const p = viewModel({...UP, probing: true, exit_ms: 42, corp_ms: 18});
  assert.equal(p.check.probing, false);
  assert.equal(p.check.disabled, false);
  assert.deepEqual(p.rows.map(r => r.ms), ['42 мс', '18 мс']);
  assert.deepEqual(p.rows.map(r => r.measuring), [false, false]);
});

test('операция идёт: окно ожидания, все кнопки заблокированы', () => {
  for (const [phase, title] of [['starting', 'Включаю…'], ['stopping', 'Выключаю…'],
                                ['restarting', 'Перезапускаю…']]) {
    for (const base of [OFF, UP]) {
      const v = viewModel({...base, op: {phase, step: 'выключаю…', busy: true}});
      assert.deepEqual(v.busy, {title, step: 'выключаю…'}, phase);
      assert.equal(v.toggle.disabled, true, phase);
      assert.equal(v.restart.disabled, true, phase);
      assert.equal(v.title, title);
    }
  }
});

test('ошибка старта: причина, подробность и лог, кнопка «Повторить»', () => {
  const v = viewModel({...OFF,
    error: 'не удалось собрать конфиг — правь conf/*.conf\nValueError: 25-35',
    error_log: ['=== старт ===', 'Traceback …', 'ValueError: 25-35']});
  assert.equal(v.cls, 'bad');
  assert.equal(v.title, 'Не удалось включить');
  assert.equal(v.sub, 'не удалось собрать конфиг — правь conf/*.conf');
  assert.equal(v.error.head, 'не удалось собрать конфиг — правь conf/*.conf');
  assert.equal(v.error.more, 'ValueError: 25-35');
  assert.equal(v.error.log.length, 3);
  assert.equal(v.toggle.label, 'Повторить');
  assert.equal(v.toggle.disabled, false);
});

test('ошибка не показывается ни при поднятом туннеле, ни посреди операции', () => {
  assert.equal(viewModel({...UP, error: 'старое'}).error, null);
  const busy = viewModel({...OFF, error: 'старое', op: {phase: 'starting', busy: true, step: ''}});
  assert.equal(busy.error, null);
  assert.equal(busy.title, 'Включаю…');
});

test('лог к ошибке урезан до 12 последних строк', () => {
  const log = Array.from({length: 40}, (_, i) => 'строка ' + i);
  const v = viewModel({...OFF, error: 'x', error_log: log});
  assert.equal(v.error.log.length, 12);
  assert.equal(v.error.log[11], 'строка 39');
});

test('корп молчит — предупреждение, а не «всё работает»', () => {
  const v = viewModel({...UP, corp_ip: ''});
  assert.equal(v.cls, 'warn');
  assert.equal(v.title, 'Корп не отвечает');
  assert.equal(v.rows[1].label, 'молчит');
});

test('утечки перекрывают остальное', () => {
  assert.equal(viewModel({...UP, v6_leak: '2a00::1'}).title, 'Утечка IPv6');
  const v = viewModel({...UP, exit_state: 'leak', exit_ip: '5.6.7.8'});
  assert.equal(v.title, 'Трафик мимо туннеля');
  assert.equal(v.rows[0].label, 'мимо туннеля');
});

test('без службы — предложение её поставить вместо кнопок', () => {
  const v = viewModel({up: false, daemon: false, op: IDLE});
  assert.equal(v.install, true);
  assert.equal(v.title, 'Нужна установка');
});

test('пустое состояние не роняет отрисовку', () => {
  const v = viewModel(undefined);
  assert.equal(v.title, 'Выключено');
  assert.equal(viewModel({}).busy, null);
});

test('ошибки лога в подзаголовок не попадают', () => {
  assert.equal(viewModel({...UP, err_count: 3}).sub, 'оба туннеля подняты');
  assert.equal(viewModel({...UP, corp_ip: '', err_count: 3}).sub,
               'личный туннель работает, интернет есть');
});
