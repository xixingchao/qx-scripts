/*
 * NodeSeek QX 手机自动化
 *
 * 用途：
 *   1. Quantumult X 重写模式下自动捕获 NodeSeek Cookie / User-Agent。
 *   2. Quantumult X 定时任务里直接执行 NodeSeek 签到并查询账号信息。
 *
 * QX 配置示例：
 *   [rewrite_local]
 *   ^https:\/\/www\.nodeseek\.com\/(?:$|board|api\/account|api\/attendance) url script-request-header nodeseek_qx.js
 *
 *   [task_local]
 *   18 8 * * * nodeseek_qx.js, tag=NodeSeek签到, enabled=true
 *
 *   [mitm]
 *   hostname = www.nodeseek.com
 *
 * 注意：
 *   - 脚本不会打印 Cookie 明文，只保存到 QX 本地 $prefs。
 *   - Cloudflare 站点可能绑定手机网络、浏览器指纹和 UA；手机 QX 成功不代表青龙容器一定可直连成功。
 */

const NAME = 'NodeSeek签到';
const VERSION = 'QX-v1';
const BASE = 'https://www.nodeseek.com';
const BOARD = `${BASE}/board`;
const RANDOM = read('NODESEEK_RANDOM') !== 'false';
const SIGN_URL = `${BASE}/api/attendance?random=${encodeURIComponent(String(RANDOM))}`;
const DEFAULT_UA =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1';
const CAPTURE_NOTIFY_INTERVAL = 6 * 60 * 60 * 1000;

main()
  .catch((error) => {
    notify(NAME, '运行异常', formatError(error));
    done();
  });

async function main() {
  log(`==== ${NAME} | ${VERSION} ====`);
  if (typeof $request !== 'undefined') {
    log('模式：请求头捕获');
    captureFromRequest();
    done();
    return;
  }

  log('模式：定时签到');
  const cookie = read('NODESEEK_COOKIE');
  const userAgent = read('NODESEEK_USER_AGENT') || DEFAULT_UA;
  log(`Cookie 状态：${cookie ? `已捕获，长度 ${cookie.length}` : '未捕获'}`);
  if (!cookie) {
    const msg = '请先用 QX 开启重写和 MITM 后，用 Safari 访问 https://www.nodeseek.com/';
    log(`未捕获 Cookie：${msg}`);
    notify(NAME, '未捕获 Cookie', msg);
    done();
    return;
  }

  const lines = [`==== ${NAME} | ${VERSION} ====`];
  const sign = await fetchJson(SIGN_URL, {
    method: 'POST',
    cookie,
    userAgent,
    body: JSON.stringify({ random: RANDOM }),
  });

  lines.push(`签到接口：HTTP ${sign.statusCode}`);
  lines.push(explainSign(sign));
  log(lines[1]);
  log(lines[2]);

  const profile = await queryProfile(cookie, userAgent);
  lines.push(profile);
  log(profile);

  notify(NAME, '运行完成', lines.join('\n'));
  done();
}

function captureFromRequest() {
  const headers = $request.headers || {};
  const cookie = getHeader(headers, 'Cookie');
  const userAgent = getHeader(headers, 'User-Agent') || DEFAULT_UA;
  if (!cookie) return;

  const oldCookie = read('NODESEEK_COOKIE');
  write('NODESEEK_COOKIE', cookie);
  write('NODESEEK_USER_AGENT', userAgent);

  const fields = cookie
    .split(';')
    .map((item) => item.trim().split('=')[0])
    .filter(Boolean);
  const changed = oldCookie && oldCookie !== cookie ? '已更新' : '已保存';
  const msg = `字段：${fields.join(', ')}\n长度：${cookie.length}`;
  log(`${changed}登录态：${msg.replace(/\n/g, '；')}`);
  if (shouldNotifyCapture('NODESEEK_CAPTURE_NOTIFY_AT', oldCookie, cookie)) {
    notify(NAME, `${changed}登录态`, msg);
  }
}

async function queryProfile(cookie, userAgent) {
  const uid = getCurrentUid(cookie);
  const urls = [
    ...(uid ? [`${BASE}/api/account/getInfo/${uid}`] : []),
    `${BASE}/api/account/profile`,
    `${BASE}/api/account/credit`,
    `${BASE}/api/user`,
    `${BASE}/api/me`,
  ];

  for (const url of urls) {
    const res = await fetchJson(url, {
      method: 'GET',
      cookie,
      userAgent,
    });
    if (isBlocked(res)) return '账号信息：触发 Cloudflare/风控，需重新用手机浏览器过验证';
    if ([401, 403].includes(res.statusCode)) return `账号信息：失败 HTTP ${res.statusCode}，Cookie 可能失效`;
    if (res.statusCode >= 400) continue;
    const balances = extractBalances(res.data);
    if (balances.length) return `账号信息：${balances.join('，')}`;
  }

  return '账号信息：未找到可解析的积分接口';
}

function fetchJson(url, options) {
  const headers = {
    'User-Agent': options.userAgent || DEFAULT_UA,
    Accept: 'application/json, text/plain, */*',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    Origin: BASE,
    Referer: BOARD,
    Cookie: options.cookie || '',
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest',
  };

  return new Promise((resolve, reject) => {
    $task
      .fetch({
        url,
        method: options.method || 'GET',
        headers,
        body: options.body,
      })
      .then((response) => {
        const body = response.body || '';
        resolve({
          statusCode: Number(response.statusCode || response.status || 0),
          body,
          data: parseJson(body),
        });
      })
      .catch(reject);
  });
}

function explainSign(res) {
  if (isBlocked(res)) return '签到：触发 Cloudflare/风控，需重新用手机浏览器过验证';
  const data = res.data || {};
  const msg = data.message || data.msg || data.error || data.detail || data.m || '';
  if (/已完成|已签到|重复|already/i.test(msg)) return `签到：今日已签到，${msg}`;
  if (data.success === true || data.status === true || data.code === 0 || /成功|鸡腿/.test(msg)) {
    return `签到：成功，${msg || '已完成'}`;
  }
  if ([401, 403].includes(res.statusCode)) return `签到：失败 HTTP ${res.statusCode}，Cookie 可能失效`;
  if (res.statusCode >= 400 && !/已完成|已签到|重复|already/i.test(res.body)) {
    return `签到：失败 HTTP ${res.statusCode}，${String(res.body).slice(0, 120)}`;
  }
  return `签到：未识别结果 ${String(res.body).slice(0, 120)}`;
}

function extractBalances(data) {
  const root = data && typeof data.data === 'object' ? data.data : data;
  if (!root || typeof root !== 'object') return [];
  const labels = {
    member_id: '用户ID',
    member_name: '用户名',
    username: '用户名',
    nickname: '昵称',
    level: '等级',
    coin: '鸡腿',
    coins: '鸡腿',
    chicken: '鸡腿',
    chickenLeg: '鸡腿',
    chicken_leg: '鸡腿',
    credit: '积分',
    credits: '积分',
    exp: '经验',
    experience: '经验',
  };
  const results = [];
  const scan = (obj) => {
    Object.entries(obj || {}).forEach(([key, value]) => {
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        scan(value);
        return;
      }
      const label = labels[key] || (/chicken|credit|coin|exp|level/i.test(key) ? key : '');
      if (label && ['string', 'number', 'boolean'].includes(typeof value)) results.push(`${label} ${value}`);
    });
  };
  scan(root);
  return [...new Set(results)].slice(0, 10);
}

function getCurrentUid(cookie) {
  const parsed = parseCookie(cookie);
  const payload = decodePayload(parsed.pjwt);
  if (!payload || typeof payload !== 'object') return '';
  for (const key of ['id', 'uid', 'member_id', 'memberId', 'account_id', 'user_id', 'sub']) {
    if (payload[key] && /^\d+$/.test(String(payload[key]))) return String(payload[key]);
  }
  return '';
}

function decodePayload(value) {
  const raw = decodeURIComponent(String(value || ''));
  const candidates = [raw, raw.split('.')[1], raw.split('.')[0]]
    .filter(Boolean)
    .map((item) => item.replace(/-/g, '+').replace(/_/g, '/'));
  for (const item of candidates) {
    try {
      const text = atob(item);
      if (/^\s*[{[]/.test(text)) return JSON.parse(text);
    } catch (error) {
      // Try the next candidate.
    }
  }
  return null;
}

function parseCookie(cookie) {
  const result = {};
  String(cookie || '')
    .split(';')
    .forEach((part) => {
      const index = part.indexOf('=');
      if (index <= 0) return;
      result[part.slice(0, index).trim()] = part.slice(index + 1).trim();
    });
  return result;
}

function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch (error) {
    return null;
  }
}

function isBlocked(res) {
  return res.statusCode === 403 || /Cloudflare|Just a moment|cf-chl|captcha|Forbidden/i.test(res.body || '');
}

function getHeader(headers, name) {
  const target = name.toLowerCase();
  const key = Object.keys(headers || {}).find((item) => item.toLowerCase() === target);
  return key ? headers[key] : '';
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

function formatError(error) {
  if (!error) return '未知错误';
  return [error.name, error.message].filter(Boolean).join(' ') || String(error);
}
