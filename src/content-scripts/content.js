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
      chrome.storage.local.get([key], (result) => {
        resolve(result[key]);
      });
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

  const issues = [];
  // 1. 协议检查
  if (!window.location.protocol.startsWith('https') && !config.ignoreHttps) {
    issues.push('非HTTPS连接（存在中间人攻击风险）');
  }

  // 2. 可疑脚本检测（增强版）
  const suspiciousScripts = Array.from(document.querySelectorAll('script')).filter(script => {
    const src = script.src;
    if (!src) return script.textContent?.includes('eval(') || script.textContent?.includes('document.write(');
    // 检测可疑域名
    const suspiciousDomains = ['unknown-domain', 'untrusted', 'malicious'];
    return suspiciousDomains.some(domain => src.includes(domain));
  });
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

// 自动扫描（基于统一配置）
async function initAutoScan() {
  const config = await Storage.get(STORAGE_KEYS.DETECTOR_CONFIG) || DEFAULT_OPTIONS;
  if (config.enabled) {
    const issues = await scanPage();
    if (!issues.includes('未发现')) {
      chrome.runtime.sendMessage({
        action: 'securityIssue',
        details: issues,
        url: window.location.href
      });
    }
  }
}

// 初始化
initAutoScan();

// 监听DOM变化（增强版）
const observer = new MutationObserver(async (mutations) => {
  if (mutations.some(m => m.addedNodes.length > 0)) {
    const issues = await scanPage();
    if (!issues.includes('未发现')) {
      chrome.runtime.sendMessage({
        action: 'securityIssue',
        details: `动态内容更新: ${issues}`,
        url: window.location.href
      });
    }
  }
});
observer.observe(document.body, { childList: true, subtree: true });

// 清理逻辑
window.addEventListener('unload', () => observer.disconnect());