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
    
    // 检查是否有可疑的URL参数（简单检测）
    const suspiciousParams = ['<script', 'javascript:', 'onerror=', 'onclick='];
    const hasSuspiciousParams = suspiciousParams.some(param => 
      currentURL.toLowerCase().includes(param)
    );
    
    if (hasSuspiciousParams) {
      console.warn('检测到可疑URL参数:', currentURL);
      // 可以向background报告
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

