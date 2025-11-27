// 后台服务脚本 - 负责URL检测、请求拦截和状态管理

// 默认配置
const DEFAULT_CONFIG = {
  urlDetection: {
    enabled: true,
    dataSource: 'local', // 'google', 'thirdParty', 'local'
    checkFrequency: 'realtime',
    // 新增：恶意库在线源与刷新间隔（小时）
    sources: [],
    refreshIntervalHours: 24,
    // 新增：上报相关配置（可选）
    reportEndpoint: "",
    reportFlushIntervalMinutes: 1,
    maxReportQueue: 200
  },
  xssProtection: {
    enabled: true,
    level: 'standard', // 'standard', 'strict', 'custom'
    autoBlock: true,
    showConfirm: false
  },
  trackerBlocking: {
    enabled: true,
    blockTypes: {
      ads: true,
      social: true,
      dataCollection: true,
      fingerprinting: true
    },
    thirdPartyCookies: true,
    canvasProtection: true,
    webrtcProtection: true
  },
  whitelist: [],
  stats: {
    threatsBlocked: 0,
    trackersBlocked: 0,
    xssIntercepted: 0
  }
};

// 本地恶意URL数据库（示例数据）
const MALICIOUS_URLS = [
  'phishing-site.com',
  'malware-distribution.com',
  'scam-website.net'
];

// 追踪器域名列表
const TRACKER_DOMAINS = [
  'google-analytics.com',
  'googletagmanager.com',
  'facebook.com',
  'doubleclick.net',
  'scorecardresearch.com',
  'adservice.google',
  'adservice.google.com',
  'ads.facebook.com',
  'analytics.twitter.com'
];

// ================= 恶意URL动态数据库（可更新） =================
const DEFAULT_MALICIOUS_DB = {
  version: 1,
  updatedAt: 0,
  sources: [], // 远程源列表（URL 数组），从 config.urlDetection.sources 同步
  domains: [], // 纯域名黑名单
  patterns: [] // 针对整条URL的正则字符串（不含分隔符）
};

let maliciousDb = null; // 内存缓存
let reportQueue = []; // 上报持久队列（内存镜像）
const REPORT_QUEUE_KEY = 'reportQueue';

async function loadReportQueue() {
  try {
    const { reportQueue: stored } = await chrome.storage.local.get([REPORT_QUEUE_KEY]);
    reportQueue = Array.isArray(stored) ? stored : [];
  } catch { reportQueue = []; }
}

async function saveReportQueue() {
  try { await chrome.storage.local.set({ [REPORT_QUEUE_KEY]: reportQueue }); } catch {}
}

function scheduleReportFlushAlarm(intervalMinutes) {
  const minutes = Math.max(0.5, Number(intervalMinutes || 1));
  try { chrome.alarms.create('flushReportQueue', { periodInMinutes: minutes }); } catch {}
}

function enqueueReport(item, cfg) {
  const now = Date.now();
  const base = {
    id: `${now}-${Math.random().toString(36).slice(2)}`,
    tries: 0,
    nextAttemptAt: now,
  };
  const rec = { ...base, ...item };
  reportQueue.push(rec);

  // 仅在未配置上报端点时做队列长度限制，避免无限增长
  const max = Number(cfg?.urlDetection?.maxReportQueue || DEFAULT_CONFIG.urlDetection.maxReportQueue || 200);
  if (!cfg?.urlDetection?.reportEndpoint) {
    if (reportQueue.length > max) {
      reportQueue = reportQueue.slice(reportQueue.length - max);
    }
  }
}

async function flushReportQueue() {
  let cfg;
  try {
    const r = await chrome.storage.local.get(['config']);
    cfg = r.config || DEFAULT_CONFIG;
  } catch { cfg = DEFAULT_CONFIG; }
  const endpoint = cfg?.urlDetection?.reportEndpoint;
  const now = Date.now();
  if (!Array.isArray(reportQueue) || reportQueue.length === 0) return;

  // 若未配置端点，则不尝试发送，仅保留有限队列
  if (!endpoint) {
    const max = Number(cfg?.urlDetection?.maxReportQueue || DEFAULT_CONFIG.urlDetection.maxReportQueue || 200);
    if (reportQueue.length > max) {
      reportQueue = reportQueue.slice(reportQueue.length - max);
      await saveReportQueue();
    }
    return;
  }

  const out = [];
  for (const rec of reportQueue) {
    if (rec.nextAttemptAt && rec.nextAttemptAt > now) { out.push(rec); continue; }
    try {
      const resp = await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ type: 'suspicious_url', data: rec.report || rec })
      });
      if (resp.ok) {
        // sent: drop
      } else {
        throw new Error(`HTTP ${resp.status}`);
      }
    } catch (e) {
      const tries = (rec.tries || 0) + 1;
      const backoff = Math.min(60_000, 1_000 * Math.pow(2, Math.min(6, tries - 1))); // 1s -> 64s cap
      const jitter = Math.floor(Math.random() * 500);
      rec.tries = tries;
      rec.nextAttemptAt = Date.now() + backoff + jitter;
      out.push(rec);
    }
  }
  reportQueue = out;
  await saveReportQueue();
}

function normalizeDomain(d) {
  try {
    let s = String(d || '').trim().toLowerCase();
    if (!s) return '';
    if (/^https?:\/\//i.test(s)) {
      const u = new URL(s);
      s = u.hostname;
    }
    return s.replace(/^\.+/, '').replace(/\.+$/, '');
  } catch { return ''; }
}

async function loadMaliciousDb() {
  try {
    const { maliciousDb: stored } = await chrome.storage.local.get(['maliciousDb']);
    maliciousDb = stored && typeof stored === 'object' ? stored : { ...DEFAULT_MALICIOUS_DB };
  } catch {
    maliciousDb = { ...DEFAULT_MALICIOUS_DB };
  }
  // 基于内置示例进行一次播种（仅首次）
  if (!maliciousDb || !Array.isArray(maliciousDb.domains)) maliciousDb.domains = [];
  if (maliciousDb.domains.length === 0 && Array.isArray(MALICIOUS_URLS) && MALICIOUS_URLS.length) {
    maliciousDb.domains = Array.from(new Set([
      ...maliciousDb.domains,
      ...MALICIOUS_URLS.map(normalizeDomain).filter(Boolean)
    ]));
    maliciousDb.updatedAt = Date.now();
    await saveMaliciousDb();
  }
}

async function saveMaliciousDb() {
  try { await chrome.storage.local.set({ maliciousDb }); } catch {}
}

function compileRegexSafe(pattern) {
  try { return new RegExp(pattern, 'i'); } catch { return null; }
}

function matchByDb(url) {
  if (!maliciousDb) return false;
  let hostname = '';
  try { hostname = new URL(url).hostname.toLowerCase(); } catch { return false; }

  // 1) 域名黑名单：精确或后缀匹配
  if (Array.isArray(maliciousDb.domains)) {
    for (const d of maliciousDb.domains) {
      const dom = normalizeDomain(d);
      if (!dom) continue;
      if (hostname === dom || hostname.endsWith('.' + dom)) return true;
    }
  }

  // 2) URL 正则匹配
  if (Array.isArray(maliciousDb.patterns)) {
    for (const p of maliciousDb.patterns) {
      const re = compileRegexSafe(p);
      if (re && re.test(url)) return true;
    }
  }
  return false;
}

async function refreshMaliciousDbFromSources(sources) {
  if (!Array.isArray(sources) || sources.length === 0) return { added: 0 };
  let added = 0;
  const newDomains = new Set(maliciousDb?.domains || []);
  const newPatterns = new Set(maliciousDb?.patterns || []);

  for (const src of sources) {
    try {
      const resp = await fetch(src, { cache: 'no-cache' });
      if (!resp.ok) continue;
      const ct = resp.headers.get('content-type') || '';
      if (ct.includes('application/json')) {
        const data = await resp.json();
        if (Array.isArray(data.domains)) data.domains.forEach(d => { const nd = normalizeDomain(d); if (nd) newDomains.add(nd); });
        if (Array.isArray(data.patterns)) data.patterns.forEach(p => { if (typeof p === 'string' && p) newPatterns.add(p); });
      } else {
        // 纯文本：逐行解析，# 开头视为注释；以 /.../ 视为正则；否则视为域名
        const text = await resp.text();
        text.split(/\r?\n/).forEach(line => {
          const s = line.trim();
          if (!s || s.startsWith('#')) return;
          if (s.startsWith('/') && s.endsWith('/')) {
            const body = s.slice(1, -1);
            if (compileRegexSafe(body)) newPatterns.add(body);
          } else {
            const nd = normalizeDomain(s);
            if (nd) newDomains.add(nd);
          }
        });
      }
    } catch (e) {
      console.warn('刷新恶意库源失败：', src, e);
    }
  }

  const beforeCount = (maliciousDb?.domains?.length || 0) + (maliciousDb?.patterns?.length || 0);
  maliciousDb = maliciousDb || { ...DEFAULT_MALICIOUS_DB };
  maliciousDb.domains = Array.from(newDomains);
  maliciousDb.patterns = Array.from(newPatterns);
  maliciousDb.updatedAt = Date.now();
  await saveMaliciousDb();
  const afterCount = maliciousDb.domains.length + maliciousDb.patterns.length;
  added = Math.max(0, afterCount - beforeCount);
  return { added };
}

function scheduleMaliciousDbAlarm(intervalHours) {
  const minutes = Math.max(0.5, Number(intervalHours || 24) * 60);
  try { chrome.alarms.create('refreshMaliciousDb', { periodInMinutes: minutes }); } catch {}
}

// 简单白名单工具（与 utils/whitelist.js 一致的最小实现）
function normalizeHost(input) {
  if (!input) return '';
  let s = String(input).trim();
  if (!s) return '';
  try {
    if (/^https?:\/\//i.test(s)) {
      const u = new URL(s);
      s = u.host || u.hostname || '';
    }
  } catch (e) {}
  return s.replace(/\/+$/, '').toLowerCase();
}
function matchHostByRule(host, rule) {
  if (!host || !rule) return false;
  const h = host.toLowerCase();
  const r = rule.toLowerCase();
  if (r.includes('*')) {
    const regexStr = '^' + r.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$';
    try { return new RegExp(regexStr).test(h); } catch { return false; }
  }
  if (r.includes(':')) return h === r; // 端口要求精确
  return h === r || h.endsWith('.' + r); // 后缀匹配
}
function isWhitelisted(urlOrHost, rules) {
  if (!rules || !Array.isArray(rules) || rules.length === 0) return false;
  let host = urlOrHost;
  try {
    if (/^https?:\/\//i.test(urlOrHost)) {
      const u = new URL(urlOrHost);
      host = u.host || u.hostname || '';
    }
  } catch (e) {}
  host = normalizeHost(host);
  return rules.some(r => matchHostByRule(host, normalizeHost(r)));
}

// DNR 动态规则：构建/更新
async function rebuildDNRRules(config) {
  try {
    // 清空现有动态规则（简单策略）
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    const removeIds = existing.map(r => r.id);

    const addRules = [];
    let nextId = 1000;

    if (config.trackerBlocking && config.trackerBlocking.enabled) {
      // 添加追踪域阻断规则
      for (const domain of TRACKER_DOMAINS) {
        addRules.push({
          id: ++nextId,
          priority: 1,
          action: { type: 'block' },
          condition: { urlFilter: `||${domain}^` }
        });
      }
    }

    // 为白名单添加 allow 例外：仅对精确 host（不含 *）添加 initiator 例外
    const whitelist = Array.isArray(config.whitelist) ? config.whitelist : [];
    const allowInitiators = whitelist
      .map(normalizeHost)
      .filter(h => h && !h.includes('*'));
    if (allowInitiators.length > 0) {
      addRules.push({
        id: ++nextId,
        priority: 10000,
        action: { type: 'allow' },
        condition: {
          initiatorDomains: allowInitiators,
          resourceTypes: [
            'main_frame','sub_frame','script','xmlhttprequest','image','stylesheet','font','media','websocket','other'
          ]
        }
      });
    }

    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: removeIds, addRules });
  } catch (e) {
    console.warn('更新 DNR 动态规则失败：', e);
  }
}

// 初始化插件
chrome.runtime.onInstalled.addListener(() => {
  console.log('安全浏览器插件已安装');
  // 初始化默认配置
  chrome.storage.local.get(['config'], (result) => {
    if (!result.config) {
      chrome.storage.local.set({ config: DEFAULT_CONFIG }, async () => {
        await Promise.all([rebuildDNRRules(DEFAULT_CONFIG), loadMaliciousDb(), loadReportQueue()]);
        const sources = DEFAULT_CONFIG.urlDetection?.sources || [];
        const interval = DEFAULT_CONFIG.urlDetection?.refreshIntervalHours || 24;
        scheduleMaliciousDbAlarm(interval);
        scheduleReportFlushAlarm(DEFAULT_CONFIG.urlDetection?.reportFlushIntervalMinutes || 1);
        if (sources.length) refreshMaliciousDbFromSources(sources).catch(() => {});
      });
    } else {
      Promise.all([rebuildDNRRules(result.config), loadMaliciousDb(), loadReportQueue()]).then(() => {
        const sources = result.config.urlDetection?.sources || [];
        const interval = result.config.urlDetection?.refreshIntervalHours || 24;
        scheduleMaliciousDbAlarm(interval);
        scheduleReportFlushAlarm(result.config.urlDetection?.reportFlushIntervalMinutes || 1);
        if (sources.length) refreshMaliciousDbFromSources(sources).catch(() => {});
      }).catch(() => {});
    }
  });
});

// 浏览器启动时也重建一次规则
chrome.runtime.onStartup.addListener(() => {
  chrome.storage.local.get(['config'], (result) => {
    const cfg = result.config || DEFAULT_CONFIG;
    rebuildDNRRules(cfg).catch(() => {});
    Promise.all([loadMaliciousDb(), loadReportQueue()]).then(() => {
      const sources = cfg.urlDetection?.sources || [];
      const interval = cfg.urlDetection?.refreshIntervalHours || 24;
      scheduleMaliciousDbAlarm(interval);
      scheduleReportFlushAlarm(cfg.urlDetection?.reportFlushIntervalMinutes || 1);
      if (sources.length) refreshMaliciousDbFromSources(sources).catch(() => {});
    });
  });
});

// 定时刷新恶意库
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'refreshMaliciousDb') {
    chrome.storage.local.get(['config'], async (result) => {
      try {
        const sources = result.config?.urlDetection?.sources || [];
        if (sources.length) await refreshMaliciousDbFromSources(sources);
      } catch {}
    });
  } else if (alarm.name === 'flushReportQueue') {
    flushReportQueue().catch(() => {});
  }
});

// 监听标签页更新，检查URL
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && tab.url) {
    checkURL(tab.url, tabId);
  }
});

// 临时允许的URL（用户在警告页选择继续访问的URL，仅本次会话有效）
const temporaryAllowedUrls = new Set();

// URL检测函数
async function checkURL(url, tabId) {
  try {
    // 跳过特殊协议与非 http/https
    if (!isValidURL(url)) {
      return;
    }
    const result = await chrome.storage.local.get(['config']);
    const config = result.config || DEFAULT_CONFIG;
    
    if (!config.urlDetection.enabled) {
      return;
    }

    // 如果用户在警告页选择“仍然继续”，本会话允许该 URL，但以警告徽章显示
    if (temporaryAllowedUrls.has(url)) {
      updateBadge(tabId, 'warning');
      return;
    }

    // 检查白名单
    if (isWhitelisted(url, config.whitelist)) {
      updateBadge(tabId, 'safe');
      return;
    }

    // 检测恶意URL
    const isMalicious = await detectMaliciousURL(url, config.urlDetection);
    
    if (isMalicious) {
      // 阻止访问并显示警告页面（传递 tabId 以便按钮控制）
      chrome.tabs.update(tabId, {
        url: chrome.runtime.getURL('warning-pages/malicious-url.html') + '?url=' + encodeURIComponent(url) + '&tabId=' + tabId
      });
      
      // 更新统计
      updateStats('threatsBlocked');
      updateBadge(tabId, 'danger');
    } else {
      updateBadge(tabId, 'safe');
    }
  } catch (error) {
    console.error('URL检测错误:', error);
    if (tabId) updateBadge(tabId, 'warning');
  }
}

// 检测恶意URL
async function detectMaliciousURL(url, config) {
  try {
    const hostname = new URL(url).hostname;
    // 1) 先查动态数据库
    if (!maliciousDb) await loadMaliciousDb();
    if (matchByDb(url)) return true;

    // 2) 兼容旧静态表（若未在 DB 中播种成功）
    for (const maliciousDomain of MALICIOUS_URLS) {
      if (hostname.includes(maliciousDomain)) {
        return true;
      }
    }

    // 3) 预留：Google Safe Browsing 或第三方
    if (config.dataSource === 'google') {
      // return await checkGoogleSafeBrowsing(url);
    }
  } catch (e) {
    console.warn('恶意URL检测异常：', e);
  }
  return false;
}

// 检查是否在白名单中
function isWhitelisted(url, whitelist) {
  if (!whitelist || whitelist.length === 0) {
    return false;
  }
  
  const hostname = new URL(url).hostname;
  return whitelist.some(site => hostname.includes(site));
}

// 更新插件图标徽章
function updateBadge(tabId, status) {
  const badges = {
    safe: { text: '✓', color: '#4CAF50' },
    warning: { text: '!', color: '#FF9800' },
    danger: { text: '✗', color: '#F44336' }
  };
  
  const badge = badges[status] || badges.safe;
  chrome.action.setBadgeText({ text: badge.text, tabId });
  chrome.action.setBadgeBackgroundColor({ color: badge.color, tabId });
}

// 更新统计数据
async function updateStats(type) {
  const result = await chrome.storage.local.get(['config']);
  const config = result.config || DEFAULT_CONFIG;
  
  if (!config.stats) {
    config.stats = DEFAULT_CONFIG.stats;
  }
  
  if (type === 'threatsBlocked') {
    config.stats.threatsBlocked++;
  } else if (type === 'trackersBlocked') {
    config.stats.trackersBlocked++;
  } else if (type === 'xssIntercepted') {
    config.stats.xssIntercepted++;
  }
  
  await chrome.storage.local.set({ config });
}

// 监听来自content script的消息
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'xss_detected') {
    updateStats('xssIntercepted');
    sendResponse({ success: true });
  } else if (request.action === 'tracker_blocked') {
    updateStats('trackersBlocked');
    sendResponse({ success: true });
  } else if (request.action === 'suspicious_url') {
    // 来自内容脚本的可疑URL报告，标记徽章为警告
    if (sender.tab && sender.tab.id) {
      updateBadge(sender.tab.id, 'warning');
    }
    // 入队（持久化）
    (async () => {
      try {
        if (!reportQueue) await loadReportQueue();
        const { config: cfg } = await chrome.storage.local.get(['config']);
        const config = cfg || DEFAULT_CONFIG;
        const report = request.report || request; // 兼容旧格式
        enqueueReport({ report }, config);
        await saveReportQueue();
      } catch {}
    })();
    sendResponse({ success: true });
  } else if (request.action === 'allow_malicious_url') {
    // 用户在警告页选择“仍然继续”
    if (request.url) {
      temporaryAllowedUrls.add(request.url);
      // 5 分钟后自动移除临时允许
      setTimeout(() => temporaryAllowedUrls.delete(request.url), 5 * 60 * 1000);
    }
    sendResponse({ success: true });
  } else if (request.action === 'close_tab') {
    if (request.tabId) {
      chrome.tabs.remove(request.tabId, () => {
        sendResponse({ success: !chrome.runtime.lastError });
      });
      return true; // 异步响应
    }
    sendResponse({ success: false });
  } else if (request.action === 'close_current_tab') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        chrome.tabs.remove(tabs[0].id, () => {
          sendResponse({ success: !chrome.runtime.lastError });
        });
      } else {
        sendResponse({ success: false });
      }
    });
    return true; // 异步响应
  } else if (request.action === 'navigate_tab') {
    if (request.tabId && request.url) {
      chrome.tabs.update(request.tabId, { url: request.url }, () => {
        sendResponse({ success: !chrome.runtime.lastError });
      });
      return true; // 异步响应
    }
    sendResponse({ success: false });
  } else if (request.action === 'get_config') {
    chrome.storage.local.get(['config'], (result) => {
      sendResponse({ config: result.config || DEFAULT_CONFIG });
    });
    return true; // 异步响应
  } else if (request.action === 'update_config') {
    chrome.storage.local.set({ config: request.config }, async () => {
      // 更新 DNR 规则
      await rebuildDNRRules(request.config);
      // 重新设定恶意库刷新定时器，并根据新源立即尝试刷新
      try {
        const interval = request.config?.urlDetection?.refreshIntervalHours || 24;
        scheduleMaliciousDbAlarm(interval);
        scheduleReportFlushAlarm(request.config?.urlDetection?.reportFlushIntervalMinutes || 1);
        const sources = request.config?.urlDetection?.sources || [];
        if (sources.length) {
          if (!maliciousDb) await loadMaliciousDb();
          refreshMaliciousDbFromSources(sources).catch(() => {});
        }
      } catch {}
      // 广播配置更新给所有标签页
      try {
        chrome.tabs.query({}, (tabs) => {
          tabs.forEach(tab => {
            if (tab.id) {
              try { chrome.tabs.sendMessage(tab.id, { type: 'config_updated', config: request.config }); } catch {}
            }
          });
        });
      } catch {}
      sendResponse({ success: true });
    });
    return true;
  } else if (request.action === 'get_malicious_db') {
    (async () => {
      if (!maliciousDb) await loadMaliciousDb();
      const { domains = [], patterns = [], updatedAt = 0, sources = [] } = maliciousDb || {};
      sendResponse({ db: { count: { domains: domains.length, patterns: patterns.length }, updatedAt, sources } });
    })();
    return true;
  } else if (request.action === 'import_malicious_list') {
    (async () => {
      try {
        if (!maliciousDb) await loadMaliciousDb();
        const addDomains = Array.isArray(request.domains) ? request.domains : [];
        const addPatterns = Array.isArray(request.patterns) ? request.patterns : [];
        const domSet = new Set(maliciousDb.domains || []);
        const patSet = new Set(maliciousDb.patterns || []);
        addDomains.forEach(d => { const nd = normalizeDomain(d); if (nd) domSet.add(nd); });
        addPatterns.forEach(p => { if (typeof p === 'string' && p) patSet.add(p); });
        maliciousDb.domains = Array.from(domSet);
        maliciousDb.patterns = Array.from(patSet);
        maliciousDb.updatedAt = Date.now();
        await saveMaliciousDb();
        sendResponse({ success: true, counts: { domains: maliciousDb.domains.length, patterns: maliciousDb.patterns.length } });
      } catch (e) {
        sendResponse({ success: false, error: String(e) });
      }
    })();
    return true;
  } else if (request.action === 'refresh_malicious_db') {
    (async () => {
      try {
        const result = await chrome.storage.local.get(['config']);
        const sources = result.config?.urlDetection?.sources || [];
        if (!maliciousDb) await loadMaliciousDb();
        const out = await refreshMaliciousDbFromSources(sources);
        sendResponse({ success: true, ...out });
      } catch (e) {
        sendResponse({ success: false, error: String(e) });
      }
    })();
    return true;
  } else if (request.action === 'check_url_risk') {
    (async () => {
      try {
        const { url } = request || {};
        if (!url || !isValidURL(url)) { sendResponse({ malicious: false }); return; }
        const res = await chrome.storage.local.get(['config']);
        const cfg = res.config || DEFAULT_CONFIG;
        if (!maliciousDb) await loadMaliciousDb();
        const malicious = matchByDb(url);
        // 兼容静态表兜底
        let fallback = false;
        if (!malicious) {
          try { const hostname = new URL(url).hostname; fallback = MALICIOUS_URLS.some(d => hostname.includes(d)); } catch {}
        }
        sendResponse({ malicious: malicious || fallback, source: 'db' });
      } catch (e) {
        sendResponse({ malicious: false, error: String(e) });
      }
    })();
    return true;
  }
});

// 仅检测 http/https，跳过特殊协议和扩展内部页面
function isValidURL(url) {
  if (!url || typeof url !== 'string') return false;
  const lower = url.toLowerCase();
  const special = ['chrome:', 'chrome-extension:', 'about:', 'moz-extension:', 'edge:', 'opera:'];
  if (special.some(p => lower.startsWith(p))) return false;
  try {
    const u = new URL(url);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch { return false; }
}

// 拦截网络请求，阻止追踪器
// 注意：Manifest V3中webRequest的blocking模式需要特殊权限
// 如果无法使用，可以通过declarativeNetRequest API实现
// 使用 DNR 动态规则，移除 webRequest 阻断逻辑

// 判断是否是追踪器
function isTracker(url) {
  try {
    const hostname = new URL(url).hostname;
    return TRACKER_DOMAINS.some(domain => hostname.includes(domain));
  } catch (e) {
    return false;
  }
}

// 监听Cookie设置，阻止第三方Cookie
chrome.cookies.onChanged.addListener((changeInfo) => {
  if (!changeInfo.cookie) return;
  
  chrome.storage.local.get(['config'], (result) => {
    const config = result.config || DEFAULT_CONFIG;
    if (config.trackerBlocking.thirdPartyCookies) {
      // 检查是否是第三方Cookie（这里简化处理，实际需要更复杂的逻辑）
      if (changeInfo.cookie.domain && isTracker(changeInfo.cookie.domain)) {
        chrome.cookies.remove({
          url: 'http' + (changeInfo.cookie.secure ? 's' : '') + '://' + changeInfo.cookie.domain + changeInfo.cookie.path,
          name: changeInfo.cookie.name
        });
      }
    }
  });
});

