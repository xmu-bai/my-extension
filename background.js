// 后台服务脚本 - 负责URL检测、请求拦截和状态管理

// 默认配置
const DEFAULT_CONFIG = {
  urlDetection: {
    enabled: true,
    dataSource: 'local', // 'google', 'thirdParty', 'local'
    checkFrequency: 'realtime'
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
        await rebuildDNRRules(DEFAULT_CONFIG);
      });
    } else {
      rebuildDNRRules(result.config).catch(() => {});
    }
  });
});

// 浏览器启动时也重建一次规则
chrome.runtime.onStartup.addListener(() => {
  chrome.storage.local.get(['config'], (result) => {
    rebuildDNRRules(result.config || DEFAULT_CONFIG).catch(() => {});
  });
});

// 监听标签页更新，检查URL
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && tab.url) {
    checkURL(tab.url, tabId);
  }
});

// URL检测函数
async function checkURL(url, tabId) {
  try {
    const result = await chrome.storage.local.get(['config']);
    const config = result.config || DEFAULT_CONFIG;
    
    if (!config.urlDetection.enabled) {
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
      // 阻止访问并显示警告页面
      chrome.tabs.update(tabId, {
        url: chrome.runtime.getURL('warning-pages/malicious-url.html') + '?url=' + encodeURIComponent(url)
      });
      
      // 更新统计
      updateStats('threatsBlocked');
      updateBadge(tabId, 'danger');
    } else {
      updateBadge(tabId, 'safe');
    }
  } catch (error) {
    console.error('URL检测错误:', error);
  }
}

// 检测恶意URL
async function detectMaliciousURL(url, config) {
  const hostname = new URL(url).hostname;
  
  // 本地检测
  for (const maliciousDomain of MALICIOUS_URLS) {
    if (hostname.includes(maliciousDomain)) {
      return true;
    }
  }
  
  // 如果有Google Safe Browsing API密钥，可以在这里调用
  // 注意：实际使用时需要申请API密钥
  if (config.dataSource === 'google') {
    // return await checkGoogleSafeBrowsing(url);
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
  } else if (request.action === 'get_config') {
    chrome.storage.local.get(['config'], (result) => {
      sendResponse({ config: result.config || DEFAULT_CONFIG });
    });
    return true; // 异步响应
  } else if (request.action === 'update_config') {
    chrome.storage.local.set({ config: request.config }, async () => {
      await rebuildDNRRules(request.config);
      sendResponse({ success: true });
    });
    return true;
  }
});

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

