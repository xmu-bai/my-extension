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
  
  // 使用MutationObserver监听DOM变化
  const observer = new MutationObserver(() => {
    if (window.location.href !== lastURL) {
      lastURL = window.location.href;
      checkCurrentURL();
    }
  });

  // 监听pushState和replaceState（SPA路由变化）
  const originalPushState = history.pushState;
  const originalReplaceState = history.replaceState;
  
  history.pushState = function(...args) {
    originalPushState.apply(history, args);
    if (window.location.href !== lastURL) {
      lastURL = window.location.href;
      checkCurrentURL();
    }
  };
  
  history.replaceState = function(...args) {
    originalReplaceState.apply(history, args);
    if (window.location.href !== lastURL) {
      lastURL = window.location.href;
      checkCurrentURL();
    }
  };
  
  // 监听popstate事件（浏览器前进后退）
  window.addEventListener('popstate', () => {
    if (window.location.href !== lastURL) {
      lastURL = window.location.href;
      checkCurrentURL();
    }
  });

  // 开始观察DOM变化
  if (document.body) {
    observer.observe(document.body, { subtree: true, childList: true });
  } else {
    document.addEventListener('DOMContentLoaded', () => {
      observer.observe(document.body, { subtree: true, childList: true });
    });
  }

})();

