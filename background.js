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
    chrome.storage.local.set({ config: request.config }, () => {
      sendResponse({ success: true });
    });
    return true;
  }
});

// 拦截网络请求，阻止追踪器
// 注意：Manifest V3中webRequest的blocking模式需要特殊权限
// 如果无法使用，可以通过declarativeNetRequest API实现
try {
  chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
      // 检查是否是追踪器
      if (isTracker(details.url)) {
        return { cancel: true };
      }
    },
    { urls: ["<all_urls>"] },
    ["blocking"]
  );
} catch (e) {
  console.warn('webRequest blocking不可用，将使用declarativeNetRequest:', e);
  // 可以使用declarativeNetRequest规则来阻止追踪器
}

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

