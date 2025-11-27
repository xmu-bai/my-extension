// 后台服务脚本 - 负责URL检测、请求拦截和状态管理

// 预设的 API 服务配置
const PRESET_API_SERVICES = {
  google: {
    name: 'Google Safe Browsing',
    apiUrl: 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=',
    description: 'Google Safe Browsing API',
    keyUrl: 'https://console.cloud.google.com/apis/credentials',
    method: 'POST',
    contentType: 'application/json'
  },
  urlhaus: {
    name: 'URLhaus',
    apiUrl: 'https://urlhaus-api.abuse.ch/v1/url/',
    description: 'URLhaus Threat Intelligence',
    keyUrl: 'https://auth.abuse.ch/',
    method: 'POST',
    contentType: 'application/x-www-form-urlencoded'
  }
};

// 默认配置
const DEFAULT_CONFIG = {
  urlDetection: {
    enabled: true,
    dataSource: 'local', // 'local', 'api'
    checkFrequency: 'realtime',
    apiService: {
      type: 'preset', // 'preset' 或 'custom'
      presetType: 'urlhaus', // 'google', 'urlhaus', 仅当 type='preset' 时有效
      apiUrl: '', // 自定义 API URL，仅当 type='custom' 时使用
      apiKey: '' // API Key
    }
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
  learningMode: {
    enabled: false
  },
  whitelist: [],
  stats: {
    threatsBlocked: 0,
    trackersBlocked: 0,
    xssIntercepted: 0
  }
};

function cloneDeep(obj) {
  if (typeof structuredClone === 'function') {
    return structuredClone(obj);
  }
  return JSON.parse(JSON.stringify(obj));
}

function normalizeConfig(config) {
  if (!config) {
    return cloneDeep(DEFAULT_CONFIG);
  }

  if (!config.urlDetection) {
    config.urlDetection = cloneDeep(DEFAULT_CONFIG.urlDetection);
  }
  // 兼容旧配置格式
  if (config.urlDetection.dataSource === 'google' || config.urlDetection.dataSource === 'thirdParty') {
    // 迁移旧配置到新格式
    if (!config.urlDetection.apiService) {
      config.urlDetection.apiService = {
        type: 'preset',
        presetType: config.urlDetection.dataSource === 'google' ? 'google' : (config.urlDetection.thirdPartySource || 'urlhaus'),
        apiUrl: '',
        apiKey: config.urlDetection.thirdPartyApiKey || ''
      };
    }
    config.urlDetection.dataSource = 'api';
  }
  if (!config.urlDetection.apiService) {
    config.urlDetection.apiService = cloneDeep(DEFAULT_CONFIG.urlDetection.apiService);
  }
  if (!config.urlDetection.apiService.type) {
    config.urlDetection.apiService.type = DEFAULT_CONFIG.urlDetection.apiService.type;
  }
  if (!config.urlDetection.apiService.presetType) {
    config.urlDetection.apiService.presetType = DEFAULT_CONFIG.urlDetection.apiService.presetType;
  }
  if (config.urlDetection.apiService.apiKey === undefined) {
    config.urlDetection.apiService.apiKey = DEFAULT_CONFIG.urlDetection.apiService.apiKey;
  }
  if (config.urlDetection.apiService.apiUrl === undefined) {
    config.urlDetection.apiService.apiUrl = DEFAULT_CONFIG.urlDetection.apiService.apiUrl;
  }
  if (!config.xssProtection) {
    config.xssProtection = cloneDeep(DEFAULT_CONFIG.xssProtection);
  }
  if (!config.trackerBlocking) {
    config.trackerBlocking = cloneDeep(DEFAULT_CONFIG.trackerBlocking);
  }
  if (!config.learningMode) {
    config.learningMode = { ...DEFAULT_CONFIG.learningMode };
  }
  if (!config.whitelist) {
    config.whitelist = [];
  }
  if (!config.stats) {
    config.stats = { ...DEFAULT_CONFIG.stats };
  }
  if (!config.privacy) {
    config.privacy = { anonymousReport: true, autoUpdate: true };
  }
  return config;
}

// 学习模式统计数据
let learningStats = {};
let learningSaveTimeout = null;
let currentConfig = cloneDeep(DEFAULT_CONFIG);

chrome.storage.local.get(['config'], (result) => {
  if (result && result.config) {
    currentConfig = normalizeConfig(result.config);
    chrome.storage.local.set({ config: currentConfig });
  } else {
    chrome.storage.local.set({ config: currentConfig });
  }
});

chrome.storage.local.get(['learningStats'], (result) => {
  if (result.learningStats && typeof result.learningStats === 'object') {
    learningStats = result.learningStats;
  }
});

function scheduleLearningStatsSave() {
  if (learningSaveTimeout) {
    return;
  }
  learningSaveTimeout = setTimeout(() => {
    chrome.storage.local.set({ learningStats }, () => {
      learningSaveTimeout = null;
    });
  }, 1000);
}

function recordLearningSample(firstParty, thirdParty) {
  if (!firstParty || !thirdParty) {
    return;
  }

  if (!learningStats[thirdParty]) {
    learningStats[thirdParty] = {
      firstParties: [],
      lastSeen: Date.now()
    };
  }

  const entry = learningStats[thirdParty];
  if (!entry.firstParties.includes(firstParty)) {
    entry.firstParties.push(firstParty);
  }
  entry.count = entry.firstParties.length;
  entry.lastSeen = Date.now();

  scheduleLearningStatsSave();
}

function resetLearningStats() {
  learningStats = {};
  chrome.storage.local.set({ learningStats });
}

function broadcastLearningMode(enabled) {
  chrome.tabs.query({}, (tabs) => {
    tabs.forEach((tab) => {
      if (tab.id !== undefined) {
        chrome.tabs.sendMessage(tab.id, {
          action: 'learning_mode_updated',
          enabled
        }, () => {
          void chrome.runtime.lastError;
        });
      }
    });
  });
}

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
  // 初始化默认配置
  chrome.storage.local.get(['config'], (result) => {
    if (!result.config) {
      chrome.storage.local.set({ config: DEFAULT_CONFIG });
    } else {
      const config = normalizeConfig(result.config);
      chrome.storage.local.set({ config });
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

// 第三方威胁情报源检测缓存（避免重复请求）
const threatIntelligenceCache = new Map();
const CACHE_EXPIRY_TIME = 5 * 60 * 1000; // 5分钟缓存

// Google Safe Browsing API 检测函数
async function checkGoogleSafeBrowsing(url, apiKey) {
  try {
    // 如果没有 API Key，记录警告并返回 false
    if (!apiKey || apiKey.trim() === '') {
      console.warn('Google Safe Browsing API 需要 API Key，请在 https://console.cloud.google.com/apis/credentials 申请并在选项中配置');
      return false;
    }

    // Google Safe Browsing API v4 需要客户端信息
    const clientId = 'security-extension';
    const clientVersion = '1.0.0';

    // 准备请求体
    const requestBody = {
      client: {
        clientId: clientId,
        clientVersion: clientVersion
      },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [
          { url: url }
        ]
      }
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000); // 5秒超时

    const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey.trim())}`;
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestBody),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      if (response.status === 400) {
        console.warn('Google Safe Browsing API 请求格式错误');
      } else if (response.status === 403) {
        console.warn('Google Safe Browsing API 认证失败，请检查 API Key 是否正确');
      } else {
        console.warn('Google Safe Browsing API 返回错误状态码:', response.status);
      }
      return false;
    }

    const data = await response.json();

    // 如果有 matches 字段且不为空，说明检测到威胁
    if (data.matches && Array.isArray(data.matches) && data.matches.length > 0) {
      return true; // 检测到恶意URL
    }

    return false; // 安全URL
  } catch (error) {
    if (error.name === 'AbortError') {
      console.warn('Google Safe Browsing API 请求超时');
    } else if (error instanceof SyntaxError) {
      console.error('Google Safe Browsing API 响应格式错误（非 JSON）:', error.message);
    } else {
      console.error('Google Safe Browsing API 检测错误:', error);
    }
    return false; // 出错时返回false，避免误报
  }
}

// URLhaus API 检测函数
async function checkURLhaus(url, apiKey) {
  try {
    // 如果没有 API Key，记录警告并返回 false
    if (!apiKey || apiKey.trim() === '') {
      console.warn('URLhaus API 需要 API Key，请在 https://auth.abuse.ch/ 免费申请并在选项中配置');
      return false;
    }

    const formData = new URLSearchParams();
    formData.append('url', url);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000); // 3秒超时

    const response = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Auth-Key': apiKey.trim()
      },
      body: formData,
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      console.warn('URLhaus API 返回错误状态码:', response.status);
      return false;
    }

    // 检查响应内容类型
    const contentType = response.headers.get('content-type');
    if (!contentType || !contentType.includes('application/json')) {
      // 如果不是 JSON，先读取文本查看内容
      const text = await response.text();
      console.warn('URLhaus API 返回非 JSON 响应:', {
        contentType: contentType,
        status: response.status,
        preview: text.substring(0, 200)
      });
      return false;
    }

    const data = await response.json();

    // 检查 API 错误响应
    if (data.error) {
      if (data.error === 'Unauthorized') {
        console.warn('URLhaus API 认证失败，请检查 API Key 是否正确');
      } else {
        console.warn('URLhaus API 返回错误:', data.error);
      }
      return false;
    }

    // URLhaus API 响应格式：
    // - query_status: "ok" 表示找到结果, "no_results" 表示未找到
    // - url_status: "online" 表示URL在线（恶意）, "offline" 表示已下线
    if (data.query_status === 'ok' && data.url_status === 'online') {
      return true; // 检测到恶意URL
    }

    return false; // 安全URL或未找到结果
  } catch (error) {
    if (error.name === 'AbortError') {
      console.warn('URLhaus API 请求超时');
    } else if (error instanceof SyntaxError) {
      // JSON 解析错误
      console.error('URLhaus API 响应格式错误（非 JSON）:', error.message);
    } else {
      console.error('URLhaus API 检测错误:', error);
    }
    return false; // 出错时返回false，避免误报
  }
}

// API 服务检测（统一接口）
async function checkApiService(url, apiServiceConfig) {
  if (!apiServiceConfig) {
    return false;
  }

  const { type, presetType, apiUrl, apiKey } = apiServiceConfig;

  // 检查是否有 API Key
  if (!apiKey || apiKey.trim() === '') {
    console.warn('API 服务需要 API Key，请在选项中配置');
    return false;
  }

  // 检查缓存
  const cacheKey = `${type}:${presetType || 'custom'}:${apiUrl || ''}:${url}`;
  const cached = threatIntelligenceCache.get(cacheKey);
  if (cached) {
    const now = Date.now();
    if (now - cached.timestamp < CACHE_EXPIRY_TIME) {
      return cached.result;
    }
    // 缓存过期，删除
    threatIntelligenceCache.delete(cacheKey);
  }

  let result = false;

  try {
    if (type === 'preset') {
      // 使用预设服务
      switch (presetType) {
        case 'google':
          result = await checkGoogleSafeBrowsing(url, apiKey);
          break;
        case 'urlhaus':
          result = await checkURLhaus(url, apiKey);
          break;
        default:
          console.warn('未知的预设 API 服务:', presetType);
          return false;
      }
    } else if (type === 'custom') {
      // 自定义 API 服务
      if (!apiUrl || apiUrl.trim() === '') {
        console.warn('自定义 API 服务需要提供 API URL');
        return false;
      }
      result = await checkCustomApi(url, apiUrl, apiKey);
    } else {
      console.warn('未知的 API 服务类型:', type);
      return false;
    }

    // 缓存结果
    threatIntelligenceCache.set(cacheKey, {
      result: result,
      timestamp: Date.now()
    });

    return result;
  } catch (error) {
    console.error('API 服务检测失败:', error);
    return false;
  }
}

// 自定义 API 服务检测（通用接口）
async function checkCustomApi(url, apiUrl, apiKey) {
  try {
    // 尝试作为 JSON API 调用
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000); // 5秒超时

    // 尝试 POST JSON
    const jsonResponse = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey.trim()}`,
        'X-API-Key': apiKey.trim()
      },
      body: JSON.stringify({ url: url }),
      signal: controller.signal
    }).catch(() => null);

    clearTimeout(timeoutId);

    if (jsonResponse && jsonResponse.ok) {
      const contentType = jsonResponse.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        const data = await jsonResponse.json();
        // 简单检测：如果响应中包含 "malicious", "threat", "danger" 等关键词，认为是恶意
        const responseText = JSON.stringify(data).toLowerCase();
        if (responseText.includes('malicious') || responseText.includes('threat') || 
            responseText.includes('danger') || responseText.includes('blocked')) {
          return true;
        }
      }
    }

    // 如果 JSON 失败，尝试表单提交
    const formController = new AbortController();
    const formTimeoutId = setTimeout(() => formController.abort(), 5000);

    const formData = new URLSearchParams();
    formData.append('url', url);

    const formResponse = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Bearer ${apiKey.trim()}`,
        'X-API-Key': apiKey.trim(),
        'Auth-Key': apiKey.trim()
      },
      body: formData,
      signal: formController.signal
    });

    clearTimeout(formTimeoutId);

    if (formResponse.ok) {
      const contentType = formResponse.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        const data = await formResponse.json();
        const responseText = JSON.stringify(data).toLowerCase();
        if (responseText.includes('malicious') || responseText.includes('threat') || 
            responseText.includes('danger') || responseText.includes('blocked')) {
          return true;
        }
      }
    }

    return false;
  } catch (error) {
    if (error.name === 'AbortError') {
      console.warn('自定义 API 请求超时');
    } else {
      console.error('自定义 API 检测错误:', error);
    }
    return false;
  }
}

// URL检测函数
async function checkURL(url, tabId) {
  try {
    // 验证URL有效性，跳过特殊协议
    if (!isValidURL(url)) {
      // 特殊协议URL（chrome://, about:等）不进行检测
      return;
    }

    const config = currentConfig ? normalizeConfig(currentConfig) : cloneDeep(DEFAULT_CONFIG);
    
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
    
    // 本地检测 - 使用精确匹配或后缀匹配（优先检测，速度快）
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
    
    // 如果本地检测未命中，根据配置的数据源进行进一步检测
    if (config.dataSource === 'api') {
      // API 服务检测
      const apiServiceConfig = config.apiService || {};
      const isMalicious = await checkApiService(url, apiServiceConfig);
      if (isMalicious) {
        return true;
      }
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
  const config = normalizeConfig(cloneDeep(currentConfig));

  if (type === 'threatsBlocked') {
    config.stats.threatsBlocked++;
  } else if (type === 'trackersBlocked') {
    config.stats.trackersBlocked++;
  } else if (type === 'xssIntercepted') {
    config.stats.xssIntercepted++;
  }

  currentConfig = config;
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
    const firstParty = sender?.tab?.url ? new URL(sender.tab.url).hostname : null;
    const domain = request.domain;
    if (firstParty && domain) {
      const cfg = normalizeConfig(currentConfig);
      if (cfg.learningMode.enabled) {
        recordLearningSample(firstParty, domain);
      }
    }
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
    const config = normalizeConfig(cloneDeep(currentConfig));
    currentConfig = config;
    sendResponse({ config });
  } else if (request.action === 'update_config') {
    const updatedConfig = normalizeConfig(request.config);
    currentConfig = updatedConfig;
    chrome.storage.local.set({ config: updatedConfig }, () => {
      broadcastLearningMode(updatedConfig.learningMode.enabled);
      sendResponse({ success: true });
    });
    return true;
  } else if (request.action === 'learning_record') {
    const cfg = normalizeConfig(currentConfig);
    if (cfg.learningMode.enabled) {
      recordLearningSample(request.firstParty, request.thirdParty);
    }
    sendResponse({ success: true });
  } else if (request.action === 'get_learning_state') {
    const cfg = normalizeConfig(cloneDeep(currentConfig));
    currentConfig = cfg;
    sendResponse({
      enabled: cfg.learningMode.enabled
    });
  } else if (request.action === 'get_learning_stats') {
    sendResponse({
      stats: learningStats
    });
  } else if (request.action === 'reset_learning_stats') {
    resetLearningStats();
    sendResponse({ success: true });
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

