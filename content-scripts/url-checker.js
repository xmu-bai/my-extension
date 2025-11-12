// URL检测内容脚本 - 在页面加载时进行URL安全检查

(async function() {
  'use strict';

  // Helper to get config as a promise
  function getConfig() {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ action: 'get_config' }, (response) => {
        resolve(response && response.config ? response.config : null);
      });
    });
  }

  const config = await getConfig();
  if (!config) {
    return; // No config, do nothing
  }

  // Whitelist check before any initialization
  try {
    const wl = Array.isArray(config.whitelist) ? config.whitelist : [];
    if (globalThis.WhitelistUtils && WhitelistUtils.isWhitelisted(location.href, wl)) {
      return; // Whitelisted, skip URL checking
    }
  } catch (e) {
    // In case of error, proceed with checking as a safeguard
  }

  if (!config.urlDetection.enabled) {
    return; // Feature disabled
  }

  checkCurrentURL();

  // 检查当前URL
  function checkCurrentURL() {
    const currentURL = window.location.href;
    const suspiciousParams = ['<script', 'javascript:', 'onerror=', 'onclick='];

    // 1. 检查原始URL（用于简单情况）
    const rawUrlCheck = suspiciousParams.some(param => 
      currentURL.toLowerCase().includes(param)
    );

    // 2. 检查解码后的查询字符串和哈希值
    let decodedString = '';
    try {
      if (window.location.search) {
        decodedString += decodeURIComponent(window.location.search);
      }
      if (window.location.hash) {
        decodedString += decodeURIComponent(window.location.hash);
      }
    } catch (e) {
      // URI格式错误可能导致解码失败，可以忽略
      console.debug('URL component decoding failed:', e);
    }
    
    const decodedCheck = suspiciousParams.some(param => 
      decodedString.toLowerCase().includes(param)
    );

    if (rawUrlCheck || decodedCheck) {
      console.warn('检测到可疑URL参数:', currentURL);
      // 向background报告
      chrome.runtime.sendMessage({
        action: 'suspicious_url',
        url: currentURL
      });
    }
  }

  // 监听URL变化（SPA应用）
  let lastURL = window.location.href;
  const observer = new MutationObserver(() => {
    if (window.location.href !== lastURL) {
      lastURL = window.location.href;
      checkCurrentURL();
    }
  });

  observer.observe(document, { subtree: true, childList: true });

})();

