// URL检测内容脚本 - 在页面加载时进行URL安全检查

(function() {
  'use strict';

  // 从background获取配置
  chrome.runtime.sendMessage({ action: 'get_config' }, (response) => {
    if (response && response.config && response.config.urlDetection.enabled) {
      checkCurrentURL();
    }
  });

  // 检查当前URL
  function checkCurrentURL() {
    const currentURL = window.location.href;
    const hostname = window.location.hostname;
    
    // 跳过 Chrome 内部页面
    if (currentURL.startsWith('chrome://') || 
        currentURL.startsWith('chrome-extension://') || 
        currentURL.startsWith('about:')) {
      return;
    }
    
    // 更全面的可疑URL参数检测
    const suspiciousPatterns = [
      /<script/i,
      /javascript:/i,
      /onerror\s*=/i,
      /onclick\s*=/i,
      /onload\s*=/i,
      /eval\s*\(/i,
      /expression\s*\(/i,
      /vbscript:/i
    ];
    
    const hasSuspiciousParams = suspiciousPatterns.some(pattern => 
      pattern.test(currentURL)
    );
    
    // 检测URL编码绕过
    let hasEncodedThreat = false;
    try {
      const decoded = decodeURIComponent(currentURL);
      hasEncodedThreat = suspiciousPatterns.some(pattern => pattern.test(decoded));
    } catch (e) {
      // 解码失败，可能是恶意构造的URL
    }
    
    if (hasSuspiciousParams || hasEncodedThreat) {
      console.warn('检测到可疑URL参数:', currentURL);
      // 向background报告
      chrome.runtime.sendMessage({
        action: 'suspicious_url',
        url: currentURL,
        timestamp: Date.now()
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

