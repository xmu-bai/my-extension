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

// 初始化插件
chrome.runtime.onInstalled.addListener(() => {
  console.log('安全浏览器插件已安装');
  // 初始化默认配置
  chrome.storage.local.get(['config'], (result) => {
    if (!result.config) {
      chrome.storage.local.set({ config: DEFAULT_CONFIG });
    }
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

// 【新增辅助函数】标准化域名（去除www.前缀，统一小写）
function normalizeHostname(hostname) {
  if (!hostname) return '';
  // 转为小写，去除开头的www.（支持www1、www2等变体）
  return hostname.toLowerCase().replace(/^www\d*\./, '');
}

// 检测恶意URL
async function detectMaliciousURL(url, config) {
  try {
    const { hostname } = new URL(url);
    const normalizedHost = normalizeHostname(hostname); // 标准化当前域名

    for (const maliciousDomain of MALICIOUS_URLS) {
      const normalizedMalicious = normalizeHostname(maliciousDomain); // 标准化恶意域名
      
      // 匹配规则：完全一致 或 当前域名是恶意域名的子域名
      if (normalizedHost === normalizedMalicious || 
          normalizedHost.endsWith(`.${normalizedMalicious}`)) {
        return true;
      }
    }
  } catch (error) {
    console.error('检测恶意URL失败:', error);
  }
  
  // Google Safe Browsing API调用（保持注释）
  if (config.dataSource === 'google') {
    // return await checkGoogleSafeBrowsing(url);
  }
  
  return false;
}

// 检查是否在白名单中
function isWhitelisted(url, whitelist) {
  if (!whitelist || whitelist.length === 0) return false;
  
  try {
    const { hostname } = new URL(url);
    const normalizedHost = normalizeHostname(hostname);

    for (const site of whitelist) {
      const normalizedSite = normalizeHostname(site);
      // 匹配规则：完全一致 或 当前域名是白名单的子域名
      if (normalizedHost === normalizedSite || 
          normalizedHost.endsWith(`.${normalizedSite}`)) {
        return true;
      }
    }
  } catch (error) {
    console.error('检查白名单失败:', error);
  }
  return false;
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
    chrome.storage.local.set({ config: request.config }, () => {
      sendResponse({ success: true });
    });
    return true;
  }
});

// 拦截网络请求，阻止追踪器
try {
  chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
      // 检查是否是追踪器（使用优化后的isTracker）
      if (isTracker(details.url)) {
        return { cancel: true };
      }
    },
    { urls: ["<all_urls>"] },
    ["blocking"]
  );
} catch (e) {
  console.warn('webRequest blocking不可用，将使用declarativeNetRequest:', e);
}

// 判断是否是追踪器
function isTracker(url) {
  try {
    const { hostname } = new URL(url);
    const normalizedHost = normalizeHostname(hostname);

    for (const trackerDomain of TRACKER_DOMAINS) {
      const normalizedTracker = normalizeHostname(trackerDomain);
      // 匹配规则：完全一致 或 当前域名是追踪器的子域名
      if (normalizedHost === normalizedTracker || 
          normalizedHost.endsWith(`.${normalizedTracker}`)) {
        return true;
      }
    }
  } catch (e) {
    return false;
  }
  return false;
}

// 监听Cookie设置，阻止第三方Cookie
chrome.cookies.onChanged.addListener((changeInfo) => {
  if (!changeInfo.cookie) return;
  
  chrome.storage.local.get(['config'], (result) => {
    const config = result.config || DEFAULT_CONFIG;
    if (config.trackerBlocking.thirdPartyCookies) {
      // 检查是否是第三方Cookie（使用优化后的isTracker）
      if (changeInfo.cookie.domain && isTracker(changeInfo.cookie.domain)) {
        chrome.cookies.remove({
          url: 'http' + (changeInfo.cookie.secure ? 's' : '') + '://' + changeInfo.cookie.domain + changeInfo.cookie.path,
          name: changeInfo.cookie.name
        });
      }
    }
  });
});