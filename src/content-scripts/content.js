// 内容脚本 - 安全扫描功能
// 注意：此文件不使用 ES6 模块语法，直接内联依赖

// 默认配置
const DEFAULT_OPTIONS = {
  enabled: true,
  detectionLevel: 'MEDIUM',
  targetMethods: ['GET', 'POST'],
  showNotification: true,
  ignoreHttps: false,
  ignoredDomains: ['localhost', '127.0.0.1', '*.local'],
  recordHistory: true,
  historyRetentionDays: 30
};

// 存储键名
const STORAGE_KEYS = {
  DETECTOR_CONFIG: 'xss_detector_config'
};

// 简单的存储工具
const Storage = {
  async get(key) {
    return new Promise((resolve) => {
      try {
        if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.sync) {
          // chrome.storage 未就绪或不可用（例如某些内置页面），返回 undefined
          resolve(undefined);
          return;
        }

        chrome.storage.sync.get([key], (result) => {
          try {
            if (chrome.runtime && chrome.runtime.lastError) {
              // 当扩展上下文被 invalidated 时，chrome.runtime.lastError 可能包含相关信息
              console.debug('[XSS检测] storage.get lastError:', chrome.runtime.lastError.message);
              resolve(undefined);
              return;
            }
            resolve(result ? result[key] : undefined);
          } catch (e) {
            console.debug('[XSS检测] storage.get callback exception:', e && e.message);
            resolve(undefined);
          }
        });
      } catch (e) {
        // 某些极端情况下（扩展被重载/服务 worker 被终止）调用 chrome API 会抛出同步异常
        console.debug('[XSS检测] storage.get exception:', e && e.message);
        resolve(undefined);
      }
    });
  }
};

// 日志工具
const Log = {
  info(message) {
    console.log(`[XSS检测] ${message}`);
  },
  debug(message) {
    console.debug(`[XSS检测] ${message}`);
  }
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'scanPage') {
    scanPage()
      .then(result => sendResponse({ result }))
      .catch(error => {
        console.error('扫描页面时出错:', error);
        sendResponse({ error: '扫描失败: ' + error.message });
      });
    return true; // 异步响应标记
  }
  // 对于不匹配的action，返回false表示同步处理
  return false;
});

// 核心扫描逻辑
async function scanPage() {
  const config = await Storage.get(STORAGE_KEYS.DETECTOR_CONFIG) || DEFAULT_OPTIONS;
  if (!config.enabled) return '检测已禁用，请在设置中开启';

  // 若当前页面域名在忽略列表中，则跳过检测
  try {
    // 使用 host（hostname:port）以便匹配带端口的白名单条目
    const host = window.location.host || '';
    if (Array.isArray(config.ignoredDomains) && isDomainIgnored(host, config.ignoredDomains)) {
      Log.info('content', `域名 ${host} 在忽略列表中，跳过检测`);
      return '该站点已被加入白名单，已跳过检测';
    }
  } catch (e) {
    // 若判断失败则继续执行检测，以免误漏
    console.debug('[XSS检测] isDomainIgnored check failed:', e && e.message);
  }

  const issues = [];
  // 1. 协议检查
  if (!window.location.protocol.startsWith('https') && !config.ignoreHttps) {
    issues.push('非HTTPS连接（存在中间人攻击风险）');
  }

  // 2. 可疑脚本检测（增强版）
  const suspiciousScripts = findSuspiciousScripts();
  if (suspiciousScripts.length > 0) {
    issues.push(`发现${suspiciousScripts.length}个可疑脚本（可能包含恶意代码）`);
  }

  // 3. XSS向量检测（检查页面中是否存在未过滤的特殊字符）
  const inputElements = document.querySelectorAll('input, textarea');
  inputElements.forEach(el => {
    const value = el.value;
    if (value.includes('<script>') || value.includes('javascript:')) {
      issues.push(`输入框中存在潜在XSS向量: ${value.slice(0, 30)}...`);
    }
  });

  return issues.length > 0 ? issues.join('; ') : '未发现明显安全问题';
}

/**
 * 判断域名是否在忽略列表中（支持通配符）
 * @param domain 当前页面域名，如 'a.example.com'
 * @param ignoredDomains 忽略数组，如 ['*.local', 'example.com']
 */
function isDomainIgnored(domain, ignoredDomains) {
  if (!domain || !Array.isArray(ignoredDomains) || ignoredDomains.length === 0) return false;
  return ignoredDomains.some(ignored => {
    try {
      // 转为正则：转义点，* -> .*
      const regexStr = '^' + ignored.replace(/\./g, '\\.').replace(/\*/g, '.*') + '$';
      const re = new RegExp(regexStr);
      return re.test(domain);
    } catch (e) {
      return false;
    }
  });
}

/**
 * 查找页面中的可疑脚本并返回详细信息数组
 * 每个条目包含 { src, inlineSnippet }
 */
function findSuspiciousScripts() {
  const suspiciousDomains = ['unknown-domain', 'untrusted', 'malicious'];
  const scripts = Array.from(document.querySelectorAll('script'));
  const detected = [];
  scripts.forEach(script => {
    const src = script.src || '';
    let isSuspicious = false;
    if (!src) {
      const text = script.textContent || '';
      if (text.includes('eval(') || text.includes('document.write(')) isSuspicious = true;
    } else {
      if (suspiciousDomains.some(domain => src.includes(domain))) isSuspicious = true;
    }
    if (isSuspicious) {
      detected.push({
        src: src || null,
        inlineSnippet: (script.textContent || '').slice(0, 200)
      });
    }
  });
  return detected;
}

// 自动扫描（基于统一配置）
async function initAutoScan() {
  const config = await Storage.get(STORAGE_KEYS.DETECTOR_CONFIG) || DEFAULT_OPTIONS;
  if (config.enabled) {
    let issues;
    try {
      issues = await scanPage();
    } catch (e) {
      console.debug('[XSS检测] initAutoScan scanPage failed:', e && e.message);
      issues = '检测失败';
    }
    if (!String(issues).includes('未发现')) {
      // 若检测到两个或以上可疑脚本，附带具体信息
      const suspiciousDetails = findSuspiciousScripts();
      const payload = {
        action: 'securityIssue',
        details: issues,
        url: window.location.href
      };
      if (suspiciousDetails.length >= 2) {
        payload.suspiciousScriptsDetails = suspiciousDetails;
        // 在页面控制台输出详细信息，便于调试与人工审查
        console.warn('[XSS检测] 发现 >=2 个可疑脚本，详情：', suspiciousDetails);
      }

      try {
        chrome.runtime.sendMessage(payload, (resp) => {
          if (chrome.runtime.lastError) {
            console.debug('[XSS检测] sendMessage ignored:', chrome.runtime.lastError.message);
          }
        });
      } catch (e) {
        console.debug('[XSS检测] sendMessage exception:', e && e.message);
      }
    }
  }
}

// 初始化
initAutoScan();

// 监听DOM变化（增强版）
const observer = new MutationObserver(async (mutations) => {
  if (mutations.some(m => m.addedNodes.length > 0)) {
    let issues;
    try {
      issues = await scanPage();
    } catch (e) {
      console.debug('[XSS检测] MutationObserver scanPage failed:', e && e.message);
      issues = '检测失败';
    }
    if (!String(issues).includes('未发现')) {
      const suspiciousDetails = findSuspiciousScripts();
      const payload = {
        action: 'securityIssue',
        details: `动态内容更新: ${issues}`,
        url: window.location.href
      };
      if (suspiciousDetails.length >= 2) {
        payload.suspiciousScriptsDetails = suspiciousDetails;
        console.warn('[XSS检测] 发现 >=2 个可疑脚本，详情：', suspiciousDetails);
      }

      try {
        chrome.runtime.sendMessage(payload, (resp) => {
          if (chrome.runtime.lastError) {
            console.debug('[XSS检测] sendMessage ignored:', chrome.runtime.lastError.message);
          }
        });
      } catch (e) {
        console.debug('[XSS检测] sendMessage exception:', e && e.message);
      }
    }
  }
});
observer.observe(document.body, { childList: true, subtree: true });

// 清理逻辑
window.addEventListener('unload', () => observer.disconnect());