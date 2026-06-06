/*
 * 吾爱破解 QX 手机自动化
 *
 * 用途：
 *   1. Quantumult X 重写模式下自动捕获 52pojie Cookie / User-Agent。
 *   2. Quantumult X 定时任务里直接执行吾爱破解签到，并尝试查询积分概况。
 *
 * QX 配置示例：
 *   [rewrite_local]
 *   ^https:\/\/www\.52pojie\.cn\/portal\.php(?:$|\?) url script-request-header https://raw.githubusercontent.com/xixingchao/qx-scripts/main/qx/52pj_qx.js
 *   ^https:\/\/www\.52pojie\.cn\/portal\.php(?:$|\?) url script-response-header https://raw.githubusercontent.com/xixingchao/qx-scripts/main/qx/52pj_qx.js
 *   ^https:\/\/www\.52pojie\.cn\/home\.php\?mod=task(?:&|$) url script-request-header https://raw.githubusercontent.com/xixingchao/qx-scripts/main/qx/52pj_qx.js
 *   ^https:\/\/www\.52pojie\.cn\/home\.php\?mod=task(?:&|$) url script-response-header https://raw.githubusercontent.com/xixingchao/qx-scripts/main/qx/52pj_qx.js
 *
 *   [task_local]
 *   16 8 * * * 52pj_qx.js, tag=吾爱破解签到, enabled=true
 *
 *   [mitm]
 *   hostname = www.52pojie.cn
 *
 * 注意：
 *   - 脚本不会打印 Cookie 明文，只保存到 QX 本地 $prefs。
 *   - 吾爱破解有 WAF/安全验证；手机 QX 可以减少青龙容器环境不一致的问题，但仍可能需要先用 Safari 手动过验证。
 */

const NAME = '吾爱破解签到';
const VERSION = 'QX-v1';
const BASE = 'https://www.52pojie.cn';
const PORTAL = `${BASE}/portal.php`;
const HOME = `${BASE}/home.php`;
const SIGN_URL = `${BASE}/home.php?mod=task&do=apply&id=2&referer=%2Fportal.php`;
const CREDIT_URL = `${BASE}/home.php?mod=spacecp&ac=credit&showcredit=1`;
const WAF_VERIFY_URL = `${BASE}/waf_zw_verify`;
const DEFAULT_UA =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1';
const CAPTURE_NOTIFY_INTERVAL = 6 * 60 * 60 * 1000;

main().catch((error) => {
  log(`异常：${formatError(error)}`);
  notify(NAME, '运行异常', formatError(error));
  done();
});

async function main() {
  log(`==== ${NAME} | ${VERSION} ====`);
  if (typeof $response !== 'undefined') {
    log('模式：响应头捕获');
    captureFromResponse();
    done();
    return;
  }

  if (typeof $request !== 'undefined') {
    log('模式：请求头捕获');
    captureFromRequest();
    done();
    return;
  }

  log('模式：定时签到');
  let cookie = read('PJ52_COOKIE');
  const userAgent = read('PJ52_USER_AGENT') || DEFAULT_UA;
  log(`Cookie 状态：${cookie ? `已捕获，长度 ${cookie.length}` : '未捕获'}`);

  if (!cookie) {
    const msg = '请先开启 QX 重写和 MITM，用 Safari 登录并访问 https://www.52pojie.cn/portal.php';
    log(`未捕获 Cookie：${msg}`);
    notify(NAME, '未捕获 Cookie', msg);
    done();
    return;
  }

  const hints = cookieHints(cookie);
  if (hints.length) log(`Cookie 提醒：${hints.join('，')}`);

  let portal = await fetchText(PORTAL, {
    method: 'GET',
    cookie,
    userAgent,
    referer: BASE,
  });
  log(`首页：HTTP ${portal.statusCode}`);
  cookie = mergeResponseCookieToStore(cookie, portal.headers, '首页');
  if (isSecurityCheck(portal.body)) {
    const waf = await tryOldWafChallenge(PORTAL, portal.body, cookie, userAgent, BASE, '首页');
    cookie = waf.cookie;
    if (!waf.ok) return finish(`首页：触发${securityCheckHint(portal.body)}，${waf.message}`);
    portal = waf.response;
    if (isSecurityCheck(portal.body)) return finish(`首页：自动验证后仍触发${securityCheckHint(portal.body)}，请先用 Safari 完成安全验证后刷新页面`);
  }
  if (!isLoggedIn(portal.body, cookie)) return finish('首页：未识别到登录状态，Cookie 可能失效');

  const portalStatus = getPortalSignStatus(portal.body);
  if (portalStatus === 'already') {
    log('签到：首页显示今日已签到，跳过任务入口');
    const creditResult = await queryCredit(cookie, userAgent);
    log(creditResult);
    notify(NAME, '运行完成', ['签到：今日已签到', creditResult].join('\n'));
    done();
    return;
  }

  const signUrl = findSignUrl(portal.body) || SIGN_URL;
  log(`签到入口：${shortUrl(signUrl)}`);
  let sign = await fetchText(signUrl, {
    method: 'GET',
    cookie,
    userAgent,
    referer: PORTAL,
  });
  log(`签到：HTTP ${sign.statusCode}`);
  cookie = mergeResponseCookieToStore(cookie, sign.headers, '签到');
  if (isSecurityCheck(sign.body)) {
    const waf = await tryOldWafChallenge(signUrl, sign.body, cookie, userAgent, PORTAL, '签到');
    cookie = waf.cookie;
    if (waf.ok) sign = waf.response;
    else log(`签到：自动 WAF 未通过，${waf.message}`);
  }
  const signResult = explainSign(sign.body, sign.statusCode);
  log(signResult);

  const creditResult = await queryCredit(cookie, userAgent);
  log(creditResult);

  notify(NAME, '运行完成', [signResult, creditResult].join('\n'));
  done();
}

function captureFromRequest() {
  const headers = $request.headers || {};
  const cookie = getHeader(headers, 'Cookie');
  const userAgent = getHeader(headers, 'User-Agent') || DEFAULT_UA;
  if (!cookie) {
    log('未发现 Cookie 请求头');
    return;
  }

  const oldCookie = read('PJ52_COOKIE');
  write('PJ52_COOKIE', cookie);
  write('PJ52_USER_AGENT', userAgent);

  const fields = cookie
    .split(';')
    .map((item) => item.trim().split('=')[0])
    .filter(Boolean);
  const changed = oldCookie && oldCookie !== cookie ? '已更新' : '已保存';
  const msg = `字段：${fields.join(', ')}\n长度：${cookie.length}`;
  log(`${changed}登录态：${msg.replace(/\n/g, '；')}`);
  if (shouldNotifyCapture('PJ52_CAPTURE_NOTIFY_AT', oldCookie, cookie)) {
    notify(NAME, `${changed}登录态`, msg);
  }
}

function captureFromResponse() {
  const headers = $response.headers || {};
  const setCookie = getHeader(headers, 'Set-Cookie') || getHeader(headers, 'set-cookie');
  if (!setCookie) {
    log('响应头未发现 Set-Cookie');
    return;
  }

  const oldCookie = read('PJ52_COOKIE');
  const merged = mergeCookie(oldCookie, setCookie);
  if (!merged || merged === oldCookie) {
    log('响应头 Cookie 无新增字段');
    return;
  }

  write('PJ52_COOKIE', merged);
  const added = diffCookieNames(oldCookie, merged);
  const msg = `新增字段：${added.join(', ') || '未识别'}\n长度：${merged.length}`;
  log(`已合并响应登录态：${msg.replace(/\n/g, '；')}`);
  if (shouldNotifyCapture('PJ52_CAPTURE_NOTIFY_AT', oldCookie, merged)) {
    notify(NAME, '已合并响应登录态', msg);
  }
}

async function queryCredit(cookie, userAgent) {
  const res = await fetchText(CREDIT_URL, {
    method: 'GET',
    cookie,
    userAgent,
    referer: HOME,
  });
  mergeResponseCookieToStore(cookie, res.headers, '积分页');
  if (isSecurityCheck(res.body)) return `积分页：触发${securityCheckHint(res.body)}，请先过安全验证`;
  if (res.statusCode >= 400) return `积分页：失败 HTTP ${res.statusCode}`;

  const text = stripHtml(res.body);
  const balances = [];
  const patterns = [
    /(吾爱币|热心值|技术值|贡献值|威望|违规|积分)[:：]?\s*(-?\d+)/g,
    /(吾爱币|热心值|技术值|贡献值|威望|违规|积分)\s*<\/em>\s*<span[^>]*>\s*(-?\d+)/g,
  ];
  patterns.forEach((pattern) => {
    for (const match of res.body.matchAll(pattern)) {
      const item = `${match[1]} ${match[2]}`;
      if (!balances.includes(item)) balances.push(item);
    }
  });
  if (!balances.length) {
    for (const match of text.matchAll(/(吾爱币|热心值|技术值|贡献值|威望|违规|积分)[:：]?\s*(-?\d+)/g)) {
      const item = `${match[1]} ${match[2]}`;
      if (!balances.includes(item)) balances.push(item);
    }
  }
  return balances.length ? `积分概况：${balances.slice(0, 8).join('；')}` : '积分概况：未解析到余额，请以页面为准';
}

function fetchText(url, options) {
  const headers = {
    'User-Agent': options.userAgent || DEFAULT_UA,
    Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    Referer: options.referer || BASE,
    Cookie: options.cookie || '',
  };
  if (options.contentType) headers['Content-Type'] = options.contentType;

  return $task.fetch({
    url,
    method: options.method || 'GET',
    headers,
    body: options.body,
  }).then((response) => ({
    statusCode: Number(response.statusCode || response.status || 0),
    body: response.body || '',
    headers: response.headers || {},
  }));
}

function explainSign(html, statusCode) {
  if (isSecurityCheck(html)) return `签到：触发${securityCheckHint(html)}，请先用 Safari 完成安全验证后刷新页面`;
  const text = stripHtml(html);
  if (/已完成|已签到|今日已签|下期再来|您已|ÄúÒÑ/i.test(text) || /ÄúÒÑ|ÏÂÆÚÔÙÀ´/i.test(html)) return '签到：今日已签到';
  if (/签到成功|打卡成功|恭喜|获得|吾爱币|热心值|\u606d\u559c\u60a8/i.test(text)) return `签到：成功，${text.slice(0, 100)}`;
  if (/需要先登录|请先登录|登录|ÏÈµÇÂ¼/i.test(text)) return '签到：失败，Cookie 可能失效';
  if (statusCode === 403) return '签到：失败 HTTP 403，可能被 WAF 或权限拦截';
  if (statusCode >= 400) return `签到：失败 HTTP ${statusCode}`;
  return `签到：未识别结果，${text.slice(0, 100)}`;
}

async function tryOldWafChallenge(targetUrl, html, cookie, userAgent, referer, scene) {
  const params = extractOldWafParams(html);
  if (!params) {
    return {
      ok: false,
      cookie,
      message: '未识别旧版 WAF 参数，可能是新版动态验证；请用 Safari 完成安全验证后刷新页面',
    };
  }

  log(`${scene}：识别到旧版 WAF 参数，尝试自动验证`);
  const payload = buildOldWafPayload(params, userAgent);
  const verify = await fetchText(WAF_VERIFY_URL, {
    method: 'POST',
    cookie,
    userAgent,
    referer: targetUrl,
    body: payload,
    contentType: 'text/plain;charset=UTF-8',
  });
  log(`${scene}：WAF 验证 HTTP ${verify.statusCode}`);
  cookie = mergeResponseCookieToStore(cookie, verify.headers, `${scene}验证`);

  const retry = await fetchText(targetUrl, {
    method: 'GET',
    cookie,
    userAgent,
    referer,
  });
  log(`${scene}：验证后重试 HTTP ${retry.statusCode}`);
  cookie = mergeResponseCookieToStore(cookie, retry.headers, `${scene}重试`);
  return {
    ok: retry.statusCode > 0 && !isSecurityCheck(retry.body),
    cookie,
    response: retry,
    message: '旧版 WAF 自动验证未通过，请用 Safari 完成安全验证后刷新页面',
  };
}

function extractOldWafParams(html) {
  const text = String(html || '');
  const numberPatterns = [
    /\bLZ\s*=\s*['"]([0-9]{4,})['"]\s*,\s*LJ\s*=\s*['"]?([0-9]{4,})['"]?/s,
    /\bLZ\s*=\s*['"]([0-9]{4,})['"][\s\S]{0,160}?\bLJ\s*=\s*['"]?([0-9]{4,})['"]?/s,
  ];
  let numbers = null;
  for (const pattern of numberPatterns) {
    numbers = text.match(pattern);
    if (numbers) break;
  }
  if (!numbers) return null;

  const encryptionPatterns = [
    /\bLE\s*=\s*['"]([a-zA-Z0-9/+]{40,}={0,2})['"]/s,
    /['"]([a-zA-Z0-9/+]{40,}={0,2})['"]/s,
  ];
  let encryption = null;
  for (const pattern of encryptionPatterns) {
    encryption = text.match(pattern);
    if (encryption) break;
  }
  if (!encryption) return null;
  return { lz: numbers[1], lj: numbers[2], le: encryption[1] };
}

function buildOldWafPayload(params, userAgent) {
  const encodeData = {
    fp_infos: fpInfoGenerate([
      {
        key: 'plugins',
        value: {
          details: [
            { name: 'PDF Viewer', description: 'Portable Document Format', filename: 'internal-pdf-viewer', mimetypes: [{ type: 'application/pdf', suffixes: 'pdf' }] },
            { name: 'WebKit built-in PDF', description: 'Portable Document Format', filename: 'internal-pdf-viewer', mimetypes: [{ type: 'application/pdf', suffixes: 'pdf' }] },
          ],
          names: ['PDF Viewer', 'WebKit built-in PDF'],
          fp: '9772d5556d57fcc8177f76029bfd92ef',
        },
      },
      { key: 'fonts', value: { names: ['Arial', 'Helvetica', 'Times New Roman'], fp: 'f730c0cc627b3b3d7db9f459836db692' } },
      { key: 'screenObject', value: { screenResolution: [390, 844], availableScreenResolution: [390, 844], colorDepth: 24, pixelDepth: 24, top: 0, left: 0, orientation: { angle: 0, type: 'portrait-primary' } } },
      { key: 'intlObject', value: { locale: 'zh-Hans-CN', calendar: 'gregory', numberingSystem: 'latn', timeZone: 'Asia/Shanghai', year: 'numeric', month: 'numeric', day: 'numeric', timezoneOffset: -480 } },
      { key: 'touchSupport', value: [5, true, true] },
      { key: 'audio', value: '35.749968223273754' },
      { key: 'webdriver', value: false },
      { key: 'webGL', value: { webgl_version: 'WebGL 1.0', webgl_vendor_and_renderer: 'Apple Inc.~Apple GPU', webgl_unmasked_renderer: 'Apple GPU', webgl_unmasked_vendor: 'Apple Inc.', webgl_aliased_point_size_range: [1, 1024], webgl_fragment_shader_medium_int_precision_rangeMax: 30, webgl_fragment_shader_medium_int_precision_rangeMin: 31, fp: '9631a557b3fdf1c28cfbd6500ad35bc8' } },
      { key: 'canvas', value: { canvas_winding: true, fp: 'da766c3ea7221c96d06cf280d3a4e60a' } },
      { key: 'deviceInfos', value: { deviceMemory: undefined, hardwareConcurrency: 4 } },
      { key: 'storageObject', value: { localStorage: true, openDatabase: false, indexedDb: true, sessionStorage: true, addBehavior: false } },
      { key: 'navigatorObject', value: { userAgent, platform: 'iPhone', vendor: 'Apple Computer, Inc.', language: 'zh-CN', languages: ['zh-CN', 'zh', 'en-US', 'en'], productSub: '20030107' } },
      { key: 'functions', value: { eval_tostring_length: 37 } },
    ]),
    answer: answerGenerate(params.lz, params.lj),
    hostname: 'www.52pojie.cn',
    scheme: 'https',
  };
  return encodeBody(JSON.stringify(encodeData), params.le);
}

function fpInfoGenerate(items) {
  const output = { errors: {} };
  items.forEach((item) => {
    const value = item.value;
    if (typeof value === 'string' && value.indexOf('Error: ') !== -1) output.errors[item.key] = value;
    else output[item.key] = value;
  });
  const now = new Date();
  output.dateTime = { timestamp: now.getTime() };
  output.fp = 'bd5db91d97ce71f00bf0b3eb63790c74';
  output.protocol = 'https';
  setVerify(output);
  return output;
}

function setVerify(target) {
  const multiplier = target.dateTime.timestamp % 10 || 10;
  Object.keys(target).forEach((key) => {
    const value = target[key];
    if (!value || typeof value !== 'object') return;
    let total = 0;
    Object.keys(value).forEach((childKey) => {
      const child = value[childKey];
      if (typeof child === 'number') total += parseInt(child, 10);
      else if (typeof child === 'string') total += child.length;
      else total += multiplier;
    });
    if (total) value.verify = total * multiplier;
  });
}

function answerGenerate(lz, lj) {
  let answer = 0;
  let offset = 1;
  for (let index = 0; index < lz.length; index += 1) {
    answer = 2 * (answer + lz.charCodeAt(index));
    offset = 2 * (offset + index + 1);
  }
  return `WZWS_CONFIRM_PREFIX_LABEL${answer * Number(lj) + offset}`;
}

function encodeBody(text, alphabet) {
  let output = '';
  let index = 0;
  while (index < text.length) {
    const first = text.charCodeAt(index++) & 255;
    if (index === text.length) {
      output += alphabet.charAt(first >> 2);
      output += alphabet.charAt((first & 3) << 4);
      output += '==';
      break;
    }
    const second = text.charCodeAt(index++);
    if (index === text.length) {
      output += alphabet.charAt(first >> 2);
      output += alphabet.charAt(((first & 3) << 4) | ((second & 240) >> 4));
      output += alphabet.charAt((second & 15) << 2);
      output += '=';
      break;
    }
    const third = text.charCodeAt(index++);
    output += alphabet.charAt(first >> 2);
    output += alphabet.charAt(((first & 3) << 4) | ((second & 240) >> 4));
    output += alphabet.charAt(((second & 15) << 2) | ((third & 192) >> 6));
    output += alphabet.charAt(third & 63);
  }
  return output;
}

function findSignUrl(html) {
  const patterns = [
    /href=["']([^"']*home\.php\?mod=task&do=apply&id=2[^"']*)["']/i,
    /href=["']([^"']*(?:qiandao|sign|plugin\.php\?id=dsu_paulsign|home\.php\?mod=task)[^"']*)["']/i,
  ];
  for (const pattern of patterns) {
    const match = html.match(pattern);
    if (match) return new URL(match[1].replace(/&amp;/g, '&'), BASE).href;
  }
  return '';
}

function getPortalSignStatus(html) {
  const text = stripHtml(html);
  if (/今日已签到|已签到|今日已签|已完成|下期再来|wbs\.png/.test(html) || /今日已签到|已签到|今日已签|已完成|下期再来/.test(text)) {
    return 'already';
  }
  return 'unknown';
}

function isSecurityCheck(html) {
  return /waf_zw_verify|WZWS_CONFIRM_PREFIX_LABEL|Please enable JavaScript|slidercaptcha|请完成安全验证|安全检查中|安全验证|wzws/i.test(html || '');
}

function securityCheckHint(html) {
  if (/slidercaptcha|请完成安全验证/i.test(html)) return '滑块安全验证';
  if (/waf_zw_verify|WZWS_CONFIRM_PREFIX_LABEL|Please enable JavaScript|wzws/i.test(html)) return 'JS/WAF 安全验证';
  return '安全验证';
}

function isLoggedIn(html, cookie) {
  const text = stripHtml(html);
  if (/退出|消息|提醒|积分|我的/.test(text) || /member\.php\?mod=logging(?:&amp;|&)action=logout/.test(html)) return true;
  if (/登录|立即登录|用户名|密码/.test(text.slice(0, 1500))) return false;
  return /_2132_auth=/.test(cookie || '');
}

function cookieHints(cookie) {
  const hints = [];
  if (!/_2132_auth=/.test(cookie)) hints.push('缺少 _2132_auth');
  if (!/_2132_saltkey=/.test(cookie)) hints.push('缺少 _2132_saltkey');
  if (!/wzws_cid=/.test(cookie)) hints.push('缺少 wzws_cid，可能无法通过安全验证');
  if (/wzws_cid=/.test(cookie) && !/wzws_sid=/.test(cookie)) hints.push('有 wzws_cid 但缺少 wzws_sid，可能还没完整通过 WAF');
  return hints;
}

function stripHtml(html) {
  return String(html || '')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/\s+/g, ' ')
    .trim();
}

function shortUrl(url) {
  const target = new URL(url, BASE);
  return `${target.pathname}${target.search}`;
}

function getHeader(headers, name) {
  const target = name.toLowerCase();
  const key = Object.keys(headers || {}).find((item) => item.toLowerCase() === target);
  return key ? headers[key] : '';
}

function mergeResponseCookieToStore(oldCookie, headers, scene) {
  const setCookie = getHeader(headers, 'Set-Cookie') || getHeader(headers, 'set-cookie');
  if (!setCookie) return oldCookie;

  const merged = mergeCookie(oldCookie, setCookie);
  if (!merged || merged === oldCookie) return oldCookie;

  write('PJ52_COOKIE', merged);
  const added = diffCookieNames(oldCookie, merged);
  log(`${scene}：已合并响应 Cookie 字段 ${added.join(', ') || '未识别'}，长度 ${merged.length}`);
  return merged;
}

function mergeCookie(oldCookie, setCookie) {
  const jar = parseCookiePairs(oldCookie);
  const lines = Array.isArray(setCookie) ? setCookie : String(setCookie || '').split(/,(?=\s*[^;,=\s]+=[^;,]*)/);
  lines.forEach((line) => {
    const first = String(line || '').split(';')[0].trim();
    const index = first.indexOf('=');
    if (index <= 0) return;
    const name = first.slice(0, index).trim();
    const value = first.slice(index + 1).trim();
    if (!name || !value) return;
    jar[name] = value;
  });
  return Object.keys(jar)
    .map((name) => `${name}=${jar[name]}`)
    .join('; ');
}

function parseCookiePairs(cookie) {
  const jar = {};
  String(cookie || '')
    .split(';')
    .map((item) => item.trim())
    .filter(Boolean)
    .forEach((item) => {
      const index = item.indexOf('=');
      if (index <= 0) return;
      jar[item.slice(0, index).trim()] = item.slice(index + 1).trim();
    });
  return jar;
}

function diffCookieNames(oldCookie, newCookie) {
  const oldNames = new Set(Object.keys(parseCookiePairs(oldCookie)));
  return Object.keys(parseCookiePairs(newCookie)).filter((name) => !oldNames.has(name));
}

function read(key) {
  if (typeof $prefs !== 'undefined') return $prefs.valueForKey(key) || '';
  return '';
}

function write(key, value) {
  if (typeof $prefs !== 'undefined') $prefs.setValueForKey(value, key);
}

function shouldNotifyCapture(timeKey, oldCookie, newCookie) {
  if (!oldCookie || oldCookie !== newCookie) {
    write(timeKey, String(Date.now()));
    return true;
  }
  const last = Number(read(timeKey) || 0);
  if (!last || Date.now() - last > CAPTURE_NOTIFY_INTERVAL) {
    write(timeKey, String(Date.now()));
    return true;
  }
  return false;
}

function notify(title, subtitle, message) {
  if (typeof $notify !== 'undefined') $notify(title, subtitle, message);
  else console.log([title, subtitle, message].filter(Boolean).join('\n'));
}

function log(message) {
  console.log(String(message));
}

function done(value) {
  if (typeof $done !== 'undefined') $done(value || {});
}

function finish(message) {
  log(message);
  notify(NAME, '需处理', message);
  done();
}

function formatError(error) {
  if (!error) return '未知错误';
  return [error.name, error.message].filter(Boolean).join(' ') || String(error);
}
