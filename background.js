// 后台服务脚本 - 负责URL检测、请求拦截和状态管理

// 默认配置
const DEFAULT_CONFIG = {
  urlDetection: {
    enabled: true,
    dataSource: 'local', // 'google', 'thirdParty', 'local'
    checkFrequency: 'realtime',
    thirdPartySource: 'urlhaus', // 'urlhaus', 'openphish', 'virustotal', 'phishtank'
    thirdPartyApiKey: '' // URLhaus API Key (可选，在 https://auth.abuse.ch/ 免费申请)
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
  if (!config.urlDetection.thirdPartySource) {
    config.urlDetection.thirdPartySource = DEFAULT_CONFIG.urlDetection.thirdPartySource;
  }
  if (config.urlDetection.thirdPartyApiKey === undefined) {
    config.urlDetection.thirdPartyApiKey = DEFAULT_CONFIG.urlDetection.thirdPartyApiKey;
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

// URLDetector: 在 background 中加载并提供模型预测服务
class URLDetector {
  constructor() {
    this.modelParams = null;
    this.scalerParams = null;
    this.selectorInfo = null;
    this.initialized = false;
    this.ready = this.loadModels();
  }

  async loadModels() {
    try {
      const modelUrl = chrome.runtime.getURL('models/enhanced_lr_model_params.json');
      const scalerUrl = chrome.runtime.getURL('models/browser_scaler_params.json');
      const selectorUrl = chrome.runtime.getURL('models/feature_selector_info.json');

      console.log('Background: 尝试加载模型文件:', modelUrl, scalerUrl, selectorUrl);

      const [modelResponse, scalerResponse, selectorResponse] = await Promise.all([
        fetch(modelUrl),
        fetch(scalerUrl),
        fetch(selectorUrl)
      ]);

      if (!modelResponse.ok) throw new Error(`Failed to fetch model file: ${modelUrl} status=${modelResponse.status}`);
      if (!scalerResponse.ok) throw new Error(`Failed to fetch scaler file: ${scalerUrl} status=${scalerResponse.status}`);
      if (!selectorResponse.ok) throw new Error(`Failed to fetch selector file: ${selectorUrl} status=${selectorResponse.status}`);

      this.modelParams = await modelResponse.json();
      this.scalerParams = await scalerResponse.json();
      this.selectorInfo = await selectorResponse.json();
      this.initialized = true;
      console.log('Background: 模型加载成功');
    } catch (error) {
      this.initialized = false;
      console.error('Background: 模型加载失败:', error);
      throw error;
    }
  }

  calculateEntropy(text) {
    if (!text || text.length <= 1) return 0;
    let entropy = 0;
    const charCount = {};
    for (let char of text) {
      charCount[char] = (charCount[char] || 0) + 1;
    }
    for (let char in charCount) {
      const p = charCount[char] / text.length;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  extractAllFeatures(url) {
    const urlStr = (url || '').toLowerCase();
    let features = {};
    try {
      let processedUrl = urlStr;
      if (!urlStr.startsWith('http://') && !urlStr.startsWith('https://')) {
        processedUrl = 'http://' + urlStr;
      }
      const urlObj = new URL(processedUrl);
      const domain = urlObj.hostname;
      const path = urlObj.pathname;
      const query = urlObj.search;

      features['url_length'] = urlStr.length;
      features['domain_length'] = domain.length;
      features['path_length'] = path.length;
      features['num_subdomains'] = Math.max(0, domain.split('.').length - 2);

      features['num_dots'] = (urlStr.match(/\./g) || []).length;
      features['num_hyphens'] = (urlStr.match(/-/g) || []).length;
      features['num_underscores'] = (urlStr.match(/_/g) || []).length;
      features['num_slashes'] = (urlStr.match(/\//g) || []).length;
      features['num_question_marks'] = (urlStr.match(/\?/g) || []).length;
      features['num_equals'] = (urlStr.match(/=/g) || []).length;
      features['num_amps'] = (urlStr.match(/&/g) || []).length;

      const numDigits = (urlStr.match(/\d/g) || []).length;
      features['num_digits'] = numDigits;
      features['digit_ratio'] = numDigits / Math.max(1, urlStr.length);

      const numLetters = (urlStr.match(/[a-z]/g) || []).length;
      features['letter_ratio'] = numLetters / Math.max(1, urlStr.length);

      features['has_https'] = urlStr.startsWith('https') ? 1 : 0;
      features['has_http'] = urlStr.startsWith('http://') ? 1 : 0;
      features['has_port'] = urlObj.port !== '' ? 1 : 0;

      const suspicious_keywords = [
        'login', 'secure', 'account', 'verify', 'bank', 'pay', 'update',
        'password', 'confirm', 'signin', 'auth', 'admin', 'php', 'cgi',
        'wallet', 'bitcoin', 'crypto', 'free', 'win', 'prize', 'click'
      ];

      let keywordPresence = [];
      suspicious_keywords.forEach(keyword => {
        const hasKeyword = urlStr.includes(keyword) ? 1 : 0;
        features[`has_${keyword}`] = hasKeyword;
        keywordPresence.push(hasKeyword);
      });

      features['suspicious_keywords_count'] = keywordPresence.reduce((a, b) => a + b, 0);
      features['suspicious_keywords_ratio'] = keywordPresence.reduce((a, b) => a + b, 0) / Math.max(1, suspicious_keywords.length);

      features['is_ip'] = /^\d+\.\d+\.\d+\.\d+$/.test(domain) ? 1 : 0;
      features['has_mixed_chars'] = /[a-z][0-9]|[0-9][a-z]/.test(domain) ? 1 : 0;
      features['domain_entropy'] = this.calculateEntropy(domain);

      features['path_depth'] = (path.match(/\//g) || []).length - (path === '/' ? 0 : 1);
      features['has_extension'] = path.includes('.') && !path.endsWith('.') ? 1 : 0;
      features['has_upper_case'] = /[A-Z]/.test(urlStr) ? 1 : 0;

      features['num_params'] = query ? (query.match(/&/g) || []).length + 1 : 0;
      features['has_encoded_chars'] = urlStr.includes('%') ? 1 : 0;
    } catch (error) {
      console.error('Background: URL解析失败:', error, url);
      if (this.selectorInfo && Array.isArray(this.selectorInfo.feature_names)) {
        this.selectorInfo.feature_names.forEach(name => { features[name] = 0; });
      }
      features['url_length'] = (url || '').length;
    }

    return features;
  }

  selectFeatures(allFeatures) {
    const allFeaturesArray = (this.selectorInfo && Array.isArray(this.selectorInfo.feature_names)) ?
      this.selectorInfo.feature_names.map(name => allFeatures[name] || 0) : [];
    return (this.selectorInfo && Array.isArray(this.selectorInfo.selected_indices)) ?
      this.selectorInfo.selected_indices.map(idx => allFeaturesArray[idx]) : allFeaturesArray;
  }

  scaleFeatures(features) {
    if (!this.scalerParams) return features;
    return features.map((feature, index) => {
      const mean = (this.scalerParams.mean && this.scalerParams.mean[index]) || 0;
      const scale = (this.scalerParams.scale && this.scalerParams.scale[index]) || 1;
      return (feature - mean) / (scale || 1);
    });
  }

  predict(url) {
    if (!this.initialized) {
      throw new Error('模型未初始化');
    }
    const allFeatures = this.extractAllFeatures(url);
    const selectedFeatures = this.selectFeatures(allFeatures);
    const scaledFeatures = this.scaleFeatures(selectedFeatures);

    let score = (this.modelParams && this.modelParams.intercept) || 0;
    const coefs = (this.modelParams && this.modelParams.coef) || [];
    for (let i = 0; i < coefs.length; i++) {
      score += coefs[i] * (scaledFeatures[i] || 0);
    }
    const probability = 1 / (1 + Math.exp(-score));
    return {
      prediction: probability > 0.5 ? 1 : 0,
      probability: probability,
      isMalicious: probability > 0.5,
      confidence: Math.abs(probability - 0.5) * 2,
      features: selectedFeatures
    };
  }
}

// 在 background 中创建检测器实例
const bgDetector = new URLDetector();


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
    try {
      const url = String(tab.url || '');
      // 注入到所有 HTTP/HTTPS 页面（排除浏览器内部页和扩展页），以在页面主世界尽早覆盖网络 API
      if (/^https?:\/\//.test(url) &&
          !url.startsWith('chrome://') &&
          !url.startsWith('chrome-extension://') &&
          !url.startsWith('about:') &&
          !url.startsWith('file:')) {
        chrome.scripting.executeScript({
          target: { tabId: tabId, allFrames: false },
          files: ['tests/page-injector.js'],
          world: 'MAIN'
        }, () => {
          if (chrome.runtime.lastError) {
            console.error('注入 page-injector 失败:', chrome.runtime.lastError);
          } else {
            console.log('已向 tab', tabId, '注入 page-injector.js');
          }
        });
      }
    } catch (e) {
      console.error('tabs.onUpdated 注入异常:', e);
    }
  }
});

// 临时允许的URL（用户选择继续访问的恶意URL，本次会话有效）
const temporaryAllowedUrls = new Set();

// 第三方威胁情报源检测缓存（避免重复请求）
const threatIntelligenceCache = new Map();
const CACHE_EXPIRY_TIME = 5 * 60 * 1000; // 5分钟缓存

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

// 第三方威胁情报源检测（统一接口）
async function checkThirdPartyThreatIntelligence(url, source, apiKey) {
  // 检查缓存
  const cacheKey = `${source}:${url}`;
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
    switch (source) {
      case 'urlhaus':
        result = await checkURLhaus(url, apiKey);
        break;
      // 后续可以添加其他源
      // case 'openphish':
      //   result = await checkOpenPhish(url);
      //   break;
      // case 'virustotal':
      //   result = await checkVirusTotal(url, apiKey);
      //   break;
      default:
        console.warn('未知的第三方威胁情报源:', source);
        return false;
    }

    // 缓存结果
    threatIntelligenceCache.set(cacheKey, {
      result: result,
      timestamp: Date.now()
    });

    return result;
  } catch (error) {
    console.error('第三方威胁情报源检测失败:', error);
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
    if (config.dataSource === 'google') {
      // 如果有Google Safe Browsing API密钥，可以在这里调用
      // 注意：实际使用时需要申请API密钥
      // return await checkGoogleSafeBrowsing(url);
    } else if (config.dataSource === 'thirdParty') {
      // 第三方威胁情报源检测
      const source = config.thirdPartySource || 'urlhaus';
      const apiKey = config.thirdPartyApiKey || '';
      const isMalicious = await checkThirdPartyThreatIntelligence(url, source, apiKey);
      if (isMalicious) {
        return true;
      }
    }
    
    // 机器学习模型检测（如果模型已加载）
    // 使用概率阈值（0.7）判断：高于阈值则判为恶意
    // 阈值可以配置，目前硬编码为 0.7；可在 config 中增加字段 mlThreshold 来支持动态阈值
    if (bgDetector && bgDetector.initialized) {
      try {
        const mlResult = bgDetector.predict(url);
        const ML_THRESHOLD = 0.7; // 可自定义阈值：0-1 之间，越高越严格
        
        // 详细的调试日志：打印特征、模型输出、判定结果
        console.log(`=== 机器学习模型检测详情 ===`);
        console.log(`URL: ${url}`);
        console.log(`模型预测概率: ${(mlResult.probability * 100).toFixed(2)}%`);
        console.log(`置信度: ${(mlResult.confidence * 100).toFixed(2)}%`);
        console.log(`原始预测值: ${mlResult.prediction}`);
        if (mlResult.features && Array.isArray(mlResult.features)) {
          console.log(`特征向量(前10维): [${mlResult.features.slice(0, 10).map(f => f.toFixed(3)).join(', ')}...]`);
          console.log(`特征向量总维数: ${mlResult.features.length}`);
        }
        console.log(`判定阈值: ${(ML_THRESHOLD * 100).toFixed(1)}%`);
        console.log(`判定结果: ${mlResult.probability >= ML_THRESHOLD ? '恶意' : '安全'}`);
        console.log(`=== 机器学习模型检测详情(结束) ===`);
        
        if (mlResult && mlResult.probability >= ML_THRESHOLD) {
          console.warn(`⚠️ Background: ML检测到恶意URL，概率=${(mlResult.probability * 100).toFixed(2)}%，URL=${url}`);
          return true;
        }
      } catch (e) {
        console.warn('Background: ML预测失败:', e.message, e);
        // 失败时继续，不中断检测流程
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
  } else if (request.action === 'get_dnr_rules') {
    // 查询当前 DNR 规则（仅在 Service Worker 中可用）
    chrome.declarativeNetRequest.getDynamicRules((rules) => {
      if (chrome.runtime.lastError) {
        sendResponse({ error: chrome.runtime.lastError.message });
      } else {
        sendResponse({ rules: rules || [] });
      }
    });
    return true; // 异步响应
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
  } else if (request.action === 'predict_url') {
    const url = request.url || '';
    // 确保模型已加载，异步响应
    bgDetector.ready.then(() => {
      try {
        const result = bgDetector.predict(url);
        sendResponse({ ok: true, result });
      } catch (e) {
        sendResponse({ ok: false, error: e.message });
      }
    }).catch((err) => {
      sendResponse({ ok: false, error: '模型加载失败' });
    });
    return true; // 表示异步回复
  } else if (request.action === 'is_detector_ready') {
    sendResponse({ ready: !!(bgDetector && bgDetector.initialized) });
  } else if (request.action === 'force_update_blocklist') {
    // 手动触发更新 blocklist
    fetchRemoteBlocklistAndUpdate().then(result => {
      sendResponse({ ok: result.ok, count: result.count, error: result.error });
    }).catch(err => {
      sendResponse({ ok: false, error: err && err.message });
    });
    return true; // 异步
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

// 使用 Declarative Net Request (DNR) 动态规则来阻止已知追踪器域名
// 说明:
// - Manifest V3 推荐使用 DNR 而不是 webRequest blocking。
// - 我们把规则ID分配在1000起的范围内，便于后续更新/删除。

const TRACKER_RULE_BASE_ID = 1000;
const TRACKER_RULE_MAX_COUNT = 1000; // 支持最多1000条动态规则

// 自动更新 blocklist 配置
const BLOCKLIST_SOURCES = [
  // 优先尝试从 Disconnect 的 services.json 拉取（人类可读的追踪器数据）
  'https://raw.githubusercontent.com/disconnectme/disconnect-tracking-protection/master/services.json',
  // 备用：EasyList（纯文本，解析会做宽松匹配）
  'https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_block.txt'
];
const BLOCKLIST_AUTO_UPDATE_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24小时
let blocklistAutoUpdateTimer = null;
// 当远程列表超出 DNR 能下发的数量时，fallback 中保存的最大条目数（仅保留前 M）
const FALLBACK_SAVE_LIMIT = 5000;
function buildDNRRulesFromDomains(domains) {
  const rules = [];
  for (let i = 0; i < domains.length && i < TRACKER_RULE_MAX_COUNT; i++) {
    const id = TRACKER_RULE_BASE_ID + i;
    const domain = domains[i];
    rules.push({
      id: id,
      priority: 1,
      action: { type: 'block' },
      condition: {
        requestDomains: [domain],
        // 阻止常见的可用于追踪的资源类型
        resourceTypes: ['script', 'image', 'stylesheet', 'sub_frame', 'xmlhttprequest', 'object', 'other', 'media', 'font', 'ping']
      }
    });
  }
  return rules;
}

function getTrackerRuleIdsRange() {
  const ids = [];
  for (let i = 0; i < TRACKER_RULE_MAX_COUNT; i++) {
    ids.push(TRACKER_RULE_BASE_ID + i);
  }
  return ids;
}

function updateTrackerDNRRules(domains) {
  try {
    const addRules = buildDNRRulesFromDomains(domains);
    const removeRuleIds = getTrackerRuleIdsRange();

    chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules }, () => {
      if (chrome.runtime.lastError) {
        console.error('更新 DNR 规则失败:', chrome.runtime.lastError);
      } else {
        console.log(`已应用 ${addRules.length} 条追踪器阻止规则`);
      }
    });
  } catch (e) {
    console.error('更新追踪器 DNR 规则时出错:', e);
  }
}

// 从远程源拉取并更新 blocklist（宽松解析，优先取域名样式字符串）
async function fetchRemoteBlocklistAndUpdate() {
  try {
    console.log('开始拉取远程 blocklist...');
    const fetched = new Set(TRACKER_DOMAINS.map(d => d.toLowerCase()));

    for (const src of BLOCKLIST_SOURCES) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 8000);
        const resp = await fetch(src, { signal: controller.signal });
        clearTimeout(timeoutId);
        if (!resp.ok) {
          console.warn('拉取 blocklist 源失败:', src, resp.status);
          continue;
        }

        const text = await resp.text();
        // 提取看起来像域名的 token（宽松）
        const domainPattern = /([a-z0-9][a-z0-9\-\.]{1,}\.[a-z]{2,})/gi;
        let m;
        while ((m = domainPattern.exec(text)) !== null) {
          const d = (m[1] || '').toLowerCase();
          // 基本过滤：不要包含斜杠或协议
          if (!d || d.indexOf('/') !== -1 || d.indexOf(':') !== -1) continue;
          // 排除非常短的 TLD-like mistakes
          if (d.split('.').length < 2) continue;
          fetched.add(d);
        }
      } catch (e) {
        console.warn('处理 blocklist 源时出错:', src, e && e.message);
        continue;
      }
    }

    // 转为数组并去重
    const allDomains = Array.from(fetched.values());
    // 将内置 TRACKER_DOMAINS 放在前面以保证优先下发
    const builtin = TRACKER_DOMAINS.map(d => d.toLowerCase());
    const prioritized = [];
    for (const d of builtin) {
      if (allDomains.includes(d)) prioritized.push(d);
    }
    const rest = allDomains.filter(d => !prioritized.includes(d));

    // 计算要下发到 DNR 的域名（最多 TRACKER_RULE_MAX_COUNT）
    const finalDNR = prioritized.concat(rest).slice(0, TRACKER_RULE_MAX_COUNT);

    // 余下的域名作为 fallback 保存，但限制为 FALLBACK_SAVE_LIMIT
    const restAfterDNR = (prioritized.concat(rest)).slice(TRACKER_RULE_MAX_COUNT);
    const fallback = restAfterDNR.slice(0, FALLBACK_SAVE_LIMIT);

    // 应用 DNR 规则并保存到 storage（记录更新时间及 fallback）
    updateTrackerDNRRules(finalDNR);
    const now = Date.now();
    chrome.storage.local.set({ blocklist_last_update: now, blocklist_size: finalDNR.length, fallback_blocklist: fallback });
    console.log('blocklist 更新完成，DNR 域名数量:', finalDNR.length, 'fallback 保存数量:', fallback.length);
    return { ok: true, dnrCount: finalDNR.length, fallbackCount: fallback.length };
  } catch (e) {
    console.error('fetchRemoteBlocklistAndUpdate 错误:', e);
    return { ok: false, error: e && e.message };
  }
}

function scheduleBlocklistAutoUpdate() {
  // 清除旧 timer
  if (blocklistAutoUpdateTimer) {
    clearInterval(blocklistAutoUpdateTimer);
    blocklistAutoUpdateTimer = null;
  }
  try {
    // 立即触发一次
    fetchRemoteBlocklistAndUpdate().catch(() => {});
    blocklistAutoUpdateTimer = setInterval(() => {
      fetchRemoteBlocklistAndUpdate().catch(() => {});
    }, BLOCKLIST_AUTO_UPDATE_INTERVAL_MS);
    console.log('已调度 blocklist 自动更新，间隔 ms=', BLOCKLIST_AUTO_UPDATE_INTERVAL_MS);
  } catch (e) {
    console.warn('scheduleBlocklistAutoUpdate 失败:', e);
  }
}

// 简单判断是否命中追踪器域名（用于非网络级别的逻辑，如 cookie 移除）
function isTracker(url) {
  try {
    const hostname = new URL(url).hostname;
    return TRACKER_DOMAINS.some(domain => hostname.includes(domain));
  } catch (e) {
    return false;
  }
}

// 在扩展启动/安装时应用初始规则
chrome.runtime.onInstalled.addListener(() => {
  try {
    updateTrackerDNRRules(TRACKER_DOMAINS);
  } catch (e) {
    console.warn('onInstalled 应用 DNR 规则失败:', e);
  }
});

// 在 service worker 启动时也尝试应用（确保重启后规则存在）
try {
  updateTrackerDNRRules(TRACKER_DOMAINS);
} catch (e) {
  // 忽略启动时错误
}

// 启动自动更新调度（仅在 service worker 启动时调用一次）
try {
  scheduleBlocklistAutoUpdate();
} catch (e) {
  console.warn('启动 blocklist 自动更新失败:', e);
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

