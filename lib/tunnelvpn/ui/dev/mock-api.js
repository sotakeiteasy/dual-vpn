'use strict';
/* Предпросмотр окна без Windows: подменяет window.pywebview.api, если окно
   открыто не в pywebview и в адресе есть ?mock=<сценарий>. В сборку не идёт
   (installer/tunnelvpn.spec исключает ui/dev).

   Фикстуры — ровно то, что отдаёт window.py: render(st) — статус службы
   (service.Core._status), renderVersion, renderHowto (window.Api._howto),
   renderLogs (строки service.Core._tail_log), ответы методов моста.

     python -m http.server -d lib/tunnelvpn/ui 8765
     http://127.0.0.1:8765/index.html?mock=ok            сценарий
     …&tab=settings  …&open=rules:work  …&tick=0         вкладка, лист, без опроса */
(() => {
  const P = new URLSearchParams(location.search);
  const SCENARIO = P.get('mock') || 'ok';
  const TICK_MS = P.get('tick') === '0' ? 0 : 1000;
  const delay = ms => new Promise(r => setTimeout(r, ms));
  const page = (fn, ...args) => (args.length > 1 ? window.callN(fn, args) : window.call(fn, args[0]));
  const clone = o => JSON.parse(JSON.stringify(o));

  // ------------------------------------------------------------ фикстуры
  const tunnel = (id, name, mode, active, confs, extra = {}) => ({
    id, name, mode, active, enabled: true, confs, rules: 0, full: mode === 'all',
    check: 'up', answer: mode === 'all' ? '38 мс' : '10.1.1.5', seq: 3, last: 'up',
    checking: false, tests: {}, awg: Object.fromEntries(confs.map(c => [c, /^(nl|awg|fi)/.test(c)])),
    ...extra});

  const base = () => ({
    up: true, busy: '', checking: false, last_error: '', autostart: true,
    version: '0.3.4-beta', singbox: '1.14.0-lx', log_level: 'info',
    tun: 45, r_low: true, r_high: true, out: 'tunnel', check_seq: 3,
    exit_ip: '185.12.4.9', exit_state: 'tunnel', exit_country: 'NL', exit_city: 'Amsterdam',
    exit_org: 'AS9009 M247', v6_leak: '', v6_off: true, corp_dns: '10.1.1.5',
    tunnels: [
      tunnel('home', 'Личный', 'all', 'nl-amsterdam-1', ['nl-amsterdam-1']),
      tunnel('work', 'Работа', 'list', 'corp-msk', ['corp-msk'], {rules: 12, answer: '10.1.1.5'}),
      tunnel('lab', 'Лаборатория', 'list', 'home-lab', ['home-lab'], {rules: 3, answer: 'git.lab.local'}),
    ]});

  const LONG = ['production-eu-central-frankfurt-amsterdam-backup-node-01',
                'corp-moscow-office-datacenter-primary-with-a-very-long-name',
                'home-lab-raspberry-pi-cluster-behind-double-nat', 'de-frankfurt-hetzner-cx22',
                'fi-helsinki-awg-obfuscated-mobile-friendly', 'jp-tokyo-latency-test',
                'us-west-oregon-streaming', 'kz-almaty-relay-for-family'];

  const SCENARIOS = {
    empty: () => ({...base(), up: false, exit_ip: '', tunnels: []}),
    noservice: () => ({up: false, no_service: true, daemon: false}),
    down: () => ({up: false, no_service: true, daemon: true}),
    portabledown: () => ({up: false, no_service: true, portable: true}),
    off: () => {
      const s = base();
      s.up = false; s.exit_ip = '';
      s.tunnels[1].last = 'error';
      s.tunnels[2].enabled = false;
      return s;
    },
    ok: base,
    spares: () => {
      const s = base();
      s.tunnels[0].confs = ['nl-amsterdam-1', 'de-frankfurt', 'fi-helsinki', 'us-west'];
      s.tunnels[0].awg = {'nl-amsterdam-1': true, 'de-frankfurt': false, 'fi-helsinki': true, 'us-west': false};
      s.tunnels[0].tests = {'de-frankfurt': {result: 'up', answer: '41 мс', at: 1760100000, checking: false},
                            'fi-helsinki': {result: 'error', answer: 'нет рукопожатия', at: 1760100000, checking: false}};
      return s;
    },
    silent: () => {
      const s = base();
      Object.assign(s.tunnels[1], {check: 'error', answer: ''});
      Object.assign(s.tunnels[2], {check: 'rules', answer: 'git.lab.local'});
      return s;
    },
    direct: () => {
      const s = base();
      s.out = 'direct'; s.exit_state = 'direct'; s.exit_ip = '46.242.14.241';
      Object.assign(s.tunnels[0], {check: 'error', answer: ''});
      return s;
    },
    leak: () => ({...base(), exit_state: 'leak', exit_ip: '46.242.14.241'}),
    v6leak: () => ({...base(), v6_leak: '2a00:1450:4010:c05::71'}),
    busy: () => ({...base(), up: false, exit_ip: '', busy: 'включаю'}),
    reconnect: () => ({...base(), up: false, exit_ip: '', busy: 'переподключаю'}),
    long8: () => {
      const s = base();
      s.exit_ip = '2001:0db8:85a3:0000:0000:8a2e:0370:7334';
      s.tunnels = LONG.map((n, i) => tunnel(`t${i}`, `Туннель ${i}`, i ? 'list' : 'all', n, [n],
                                            {rules: i * 7, enabled: i !== 5}));
      return s;
    },
    errors8: () => {
      const s = base();
      s.exit_state = 'leak';
      s.v6_leak = '2a00:1450:4010:c05::71';
      s.tunnels = LONG.map((n, i) => tunnel(`t${i}`, `Туннель ${i}`, i ? 'list' : 'all', n, [n], {
        rules: i * 3,
        check: ['error', 'rules', 'none', 'error'][i % 4],
        answer: i % 4 === 1 ? `very-long-subdomain-${i}.corp.example.internal.company.ru` : ''}));
      return s;
    },
    portable: base,
    rules: base,
    log400: base,
    settings: base,
    update: base,
  };

  const SETTINGS_INFO = {
    portable: SCENARIO === 'portable',
    admin: true,
    service: SCENARIO === 'portable' ? null
      : {installed: true, running: true, start: 'auto'},
    tray_autostart: SCENARIO === 'portable' ? null : true,
    data_dir: SCENARIO === 'portable' ? 'D:\\Tools\\TunnelVPN-Data' : 'C:\\ProgramData\\TunnelVPN',
    logs_dir: 'C:\\ProgramData\\TunnelVPN\\state\\logs',
    repo: 'https://github.com/sotakeiteasy/dual-vpn',
  };

  let st = SCENARIOS[SCENARIO] ? SCENARIOS[SCENARIO]() : base();
  const T = id => (st.tunnels || []).find(t => t.id === id);

  // --------------------------------------------------------------- журнал
  function logLines(n) {
    const names = (st.tunnels || []).map(t => t.name);
    const lvls = ['INFO', 'INFO', 'INFO', 'DEBUG', 'WARN', 'INFO', 'ERROR'];
    const msgs = [
      'outbound/direct[direct]: outbound connection to 142.250.74.46:443',
      'dns: exchanged A www.google.com. 300 IN A 142.250.74.46',
      'endpoint/wireguard[wg-work]: outbound connection to 10.1.1.20:22',
      'router: match[3] domain_suffix=corp.example => wg-work',
      'endpoint/wireguard[wg-home]: handshake did not complete after 5 seconds, retrying',
      'inbound/tun[tun-in]: inbound packet connection from 172.19.0.1:53000',
      'endpoint/wireguard[wg-lab]: connection timeout: dial tcp 10.9.0.4:443: i/o timeout'];
    const out = ['=== запуск 2026-10-10 12:00:00 ==='];
    for (let i = 0; i < n - 1; i++) {
      const t = new Date(Date.UTC(2026, 9, 10, 9, 0, 0) + i * 1700);
      const stamp = t.toISOString().slice(0, 19).replace('T', ' ');
      const mark = i % 3 && names.length ? `[${names[i % names.length]}] ` : '';
      out.push(`${mark}+0300 ${stamp} ${lvls[i % lvls.length]} [${1000000 + i} ${i % 90}ms] ${msgs[i % msgs.length]}`);
    }
    return out;
  }
  let LOG = logLines(SCENARIO === 'log400' ? 400 : 60);
  let logN = LOG.length;

  // ----------------------------------------------------------- отрисовка
  const pushStatus = () => page('render', clone(st));
  function pushFull() {
    pushStatus();
    if (st.no_service) return;
    page('renderVersion', {app: st.version, singbox: st.singbox});
    page('renderHowto', {
      endpoints: st.up ? (st.tunnels || []).filter(t => t.enabled).map(t => ({
        tag: `wg-${t.id}`, address: t.mode === 'all' ? '10.8.0.2/32' : '10.1.1.77/32',
        mtu: t.awg[t.active] ? 1280 : 1420, awg: !!t.awg[t.active], peer: '203.0.113.7'})) : [],
      corp_nets: ['10.1.0.0/16', '192.168.50.0/24'], corp_domains: ['corp.example', 'git.corp.example'],
      corp_dns: st.corp_dns || ''});
    page('renderLogs', LOG.slice());
  }

  async function check() {
    if (!st.up) return;
    page('checkStart');
    const left = (st.tunnels || []).map(t => t.id);
    for (const t of st.tunnels) {
      await delay(250 + Math.random() * 400);
      left.splice(left.indexOf(t.id), 1);
      page('checkSides', clone(st), left.slice());
    }
    pushStatus();
    page('checkDone');
  }

  async function testConf({tunnel, name}) {
    const t = T(tunnel);
    if (!t) return;
    t.tests[name] = {...(t.tests[name] || {}), checking: true};
    await delay(1200);
    t.tests[name] = {result: /fi-/.test(name) ? 'error' : 'up', answer: /fi-/.test(name) ? 'нет рукопожатия' : '44 мс',
                     at: Date.now() / 1000, checking: false};
    t.seq += 1;
    pushStatus();
    page('testDone', {tunnel, name});
  }

  // ------------------------------------------------------- мост: ответы
  const ok = (extra = {}) => ({ok: true, ...extra});
  const HANDLERS = {
    ready: () => { pushFull(); check(); afterReady(); },
    check,
    test_config: testConf,
    logs: () => page('renderLogs', LOG.slice()),
    start: async () => { st.busy = 'включаю'; pushStatus(); await delay(900); st.busy = ''; st.up = true; st.exit_ip = '185.12.4.9'; pushStatus(); },
    stop: async () => { st.busy = 'выключаю'; pushStatus(); await delay(600); st.busy = ''; st.up = false; st.exit_ip = ''; pushStatus(); },
    restart: async () => { st.up = false; pushStatus(); await delay(900); st.up = true; pushStatus(); },
    use_config: ({tunnel, name}) => { T(tunnel).active = name; pushFull(); },
    set_enabled: ({tunnel, on}) => { T(tunnel).enabled = on; pushFull(); },
    set_mode: ({tunnel, mode}) => {
      st.tunnels.forEach(t => { if (mode === 'all' && t.mode === 'all') t.mode = 'list'; });
      T(tunnel).mode = mode;
      pushFull();
    },
    del_config: ({tunnel, name, drop_tunnel}) => {
      const t = T(tunnel);
      t.confs = t.confs.filter(c => c !== name);
      if (t.active === name) t.active = t.confs[0] || '';
      if (drop_tunnel && !t.confs.length) st.tunnels = st.tunnels.filter(x => x !== t);
      page('closeSheet');
      pushFull();
    },
    del_tunnel: id => { st.tunnels = st.tunnels.filter(t => t.id !== id); pushFull(); },
    move_config: () => { page('closeSheet'); pushFull(); },
    apply_full: async () => { st.up = false; pushStatus(); await delay(900); st.up = true; pushFull(); },
    add_config: () => page('askPlace', {id: 'work', name: 'Работа', conf: 'corp-msk', file: 'corp-msk-2'}),
    place_config: () => pushFull(),
    show_config: ({tunnel, name}) => page('showConf', tunnel, name,
      '[Interface]\nPrivateKey = MOCK+private+key+preview+only+not+a+real+key0=\nAddress = 10.8.0.2/32\n' +
      'DNS = 10.1.1.5\nMTU = 1420\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 68\nH1 = 1106457265\n\n' +
      '[Peer]\nPublicKey = MOCK+public+key+preview+only+not+a+real+key00=\n' +
      'PresharedKey = MOCK+preshared+key+preview+only+not+a+real+k=\nAllowedIPs = 0.0.0.0/0\n' +
      'Endpoint = vpn.example.net:51820\nPersistentKeepalive = 25\n'),
    edit_config: () => {},
    tunnel_rules: id => {
      const t = T(id);
      page('showRules', {id, name: t.name, mode: t.mode, active: t.active,
                         include: t.mode === 'all' ? [] : ['corp.example', 'git', '10.0.0.0/33', '10.20.0.0/16'],
                         exclude: ['198.51.100.7/32']});
    },
    save_rules: arg => page('rulesSaved', {include: String(arg.include || '').split(/[\s,;]+/).filter(Boolean),
                                           exclude: String(arg.exclude || '').split(/[\s,;]+/).filter(Boolean),
                                           rejected: {}, mode: ''}),
    load_rules: () => page('fillRules', {include: 'imported.example\n10.30.0.0/16', exclude: ''}),
    export_rules: () => {},
    set_autostart: async on => { await delay(400); st.autostart = !!on; page('autostartDone'); pushStatus(); },
    log_level: async on => { await delay(400); st.log_level = on ? 'debug' : 'info'; page('logLevelDone'); pushStatus(); },
    install_daemon: () => {},
    rendered: () => {},
    jserror: msg => console.error('jserror:', msg),
    settings_info: () => ok(SETTINGS_INFO),
  };

  // Сценарий сам открывает вкладку или лист: ?tab=log, ?open=rules:work.
  function afterReady() {
    const tab = P.get('tab') || (SCENARIO === 'log400' ? 'log' : SCENARIO === 'settings' || SCENARIO === 'update' ? 'settings' : '');
    if (tab && window.showTab) window.showTab(tab);
    const open = P.get('open') || (SCENARIO === 'rules' ? 'rules:work' : '');
    if (open.startsWith('rules:')) setTimeout(() => HANDLERS.tunnel_rules(open.slice(6)), 50);
  }

  // Опрос, как у window.poll: статус раз в секунду (POLL_EVERY там — 2 с;
  // здесь чаще, чтобы проверить, что обновление не сбивает меню и фокус).
  // Задержка ответа основного «дышит» — текст на карточке меняется.
  if (TICK_MS) {
    setInterval(() => {
      if (st.no_service) { pushStatus(); return; }
      const main = (st.tunnels || []).find(t => t.mode === 'all');
      if (main && main.check === 'up') main.answer = `${35 + Math.floor(Math.random() * 8)} мс`;
      if (SCENARIO === 'log400' || P.get('tab') === 'log') {
        LOG = [...LOG.slice(1), logLines(logN + 2)[logN + 1]];
        logN += 1;
        page('renderLogs', LOG.slice());
      }
      pushStatus();
    }, TICK_MS);
  }

  window.pywebview = {api: {
    send(name, arg) {
      const h = HANDLERS[name];
      if (!h) {
        console.warn('mock: нет ответа на', name, arg);
        return Promise.resolve(null);
      }
      // Как у pywebview: ответ — промисом, после текущего кадра.
      return delay(30).then(() => h(arg)).then(r => r ?? null);
    },
  }};
  window.MOCK = {get state() { return st; }, set state(v) { st = v; pushFull(); }, push: pushFull, SCENARIOS: Object.keys(SCENARIOS)};
  queueMicrotask(() => dispatchEvent(new Event('pywebviewready')));
})();
