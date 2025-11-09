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

// 临时允许的URL（用户选择继续访问的恶意URL，本次会话有效）
const temporaryAllowedUrls = new Set();

// URL检测函数
async function checkURL(url, tabId) {
  try {
    // 验证URL有效性，跳过特殊协议
    if (!isValidURL(url)) {
      // 特殊协议URL（chrome://, about:等）不进行检测
      return;
    }

    const result = await chrome.storage.local.get(['config']);
    const config = result.config || DEFAULT_CONFIG;
    
    if (!config.urlDetection.enabled) {
      return;
    }

    // 检查临时允许列表（用户选择继续访问的URL）
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
      // 阻止访问并显示警告页面，传递tabId以便按钮操作
      chrome.tabs.update(tabId, {
        url: chrome.runtime.getURL('warning-pages/malicious-url.html') + 
             '?url=' + encodeURIComponent(url) + 
             '&tabId=' + tabId
      });
      
      // 更新统计
      updateStats('threatsBlocked');
      updateBadge(tabId, 'danger');
    } else {
      updateBadge(tabId, 'safe');
    }
  } catch (error) {
    console.error('URL检测错误:', error);
    // 发生错误时，标记为警告状态
    updateBadge(tabId, 'warning');
  }
}

// 检测恶意URL
async function detectMaliciousURL(url, config) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    
    // 本地检测 - 使用精确匹配或后缀匹配
    for (const maliciousDomain of MALICIOUS_URLS) {
      const domain = maliciousDomain.toLowerCase();
      
      // 精确匹配
      if (hostname === domain) {
        return true;
      }
      
      // 后缀匹配（支持子域名，如 www.phishing-site.com）
      // 但排除恶意域名被包含在其他域名中的情况（如 not-phishing-site.com）
      if (hostname.endsWith('.' + domain)) {
        return true;
      }
    }
    
    // 如果有Google Safe Browsing API密钥，可以在这里调用
    // 注意：实际使用时需要申请API密钥
    if (config.dataSource === 'google') {
      // return await checkGoogleSafeBrowsing(url);
    }
    
    return false;
  } catch (error) {
    console.error('检测恶意URL时出错:', error);
    return false;
  }
}

// 检查是否在白名单中
function isWhitelisted(url, whitelist) {
  if (!whitelist || whitelist.length === 0) {
    return false;
  }
  
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    
    return whitelist.some(site => {
      const siteDomain = site.toLowerCase().trim();
      if (!siteDomain) return false;
      
      // 精确匹配
      if (hostname === siteDomain) {
        return true;
      }
      
      // 后缀匹配（支持子域名）
      if (hostname.endsWith('.' + siteDomain)) {
        return true;
      }
      
      return false;
    });
  } catch (error) {
    console.error('检查白名单时出错:', error);
    return false;
  }
}

// 验证URL是否有效且需要检测
function isValidURL(url) {
  if (!url || typeof url !== 'string') {
    return false;
  }
  
  // 跳过特殊协议
  const specialProtocols = [
    'chrome:',
    'chrome-extension:',
    'about:',
    'moz-extension:',
    'edge:',
    'opera:'
  ];
  
  const lowerUrl = url.toLowerCase();
  if (specialProtocols.some(protocol => lowerUrl.startsWith(protocol))) {
    return false;
  }
  
  // 尝试解析URL，验证格式
  try {
    const urlObj = new URL(url);
    // 只检测http和https协议
    return urlObj.protocol === 'http:' || urlObj.protocol === 'https:';
  } catch (error) {
    return false;
  }
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
    // 处理content script检测到的可疑URL参数
    handleSuspiciousURL(request.url, sender.tab?.id);
    sendResponse({ success: true });
  } else if (request.action === 'allow_malicious_url') {
    // 用户选择继续访问恶意URL，添加到临时允许列表
    const url = request.url;
    if (url) {
      temporaryAllowedUrls.add(url);
      // 5分钟后自动移除（可选）
      setTimeout(() => temporaryAllowedUrls.delete(url), 5 * 60 * 1000);
    }
    sendResponse({ success: true });
  } else if (request.action === 'close_tab') {
    // 关闭指定标签页
    if (request.tabId) {
      chrome.tabs.remove(request.tabId, () => {
        sendResponse({ success: !chrome.runtime.lastError });
      });
    } else {
      sendResponse({ success: false });
    }
    return true; // 异步响应
  } else if (request.action === 'close_current_tab') {
    // 关闭当前标签页
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
    // 跳转指定标签页
    if (request.tabId && request.url) {
      chrome.tabs.update(request.tabId, { url: request.url }, () => {
        sendResponse({ success: !chrome.runtime.lastError });
      });
    } else {
      sendResponse({ success: false });
    }
    return true; // 异步响应
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

// 处理可疑URL参数
function handleSuspiciousURL(url, tabId) {
  console.warn('检测到可疑URL参数:', url);
  
  // 更新徽章为警告状态
  if (tabId) {
    updateBadge(tabId, 'warning');
  }
  
  // 可以选择记录到历史或统计中
  // 这里暂时只记录日志，可以根据需要扩展功能
}

// 拦截网络请求，阻止追踪器
// 注意：Manifest V3中webRequest的blocking模式需要企业策略权限
// 普通扩展无法使用，已移除。追踪器阻止功能由content-scripts/tracker-blocker.js处理
// 如果需要更强大的阻止功能，可以使用declarativeNetRequest API

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

