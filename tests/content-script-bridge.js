// Content Script Bridge - 为测试页面提供与后台通信的桥梁
// 这个脚本在 test-tracker.html 页面上下文中运行，可以访问 chrome.runtime API

(function() {
  'use strict';

  // 监听来自页面脚本的消息
  window.addEventListener('message', (event) => {
    // 只接受来自同源的消息（安全检查）
    if (event.source !== window) return;

    // 检查消息格式
    if (!event.data || !event.data.type || event.data.type !== 'EXTENSION_MESSAGE') {
      return;
    }

    const { id, action, payload } = event.data;

    // 所有请求都转发到 background 脚本（background 中有所有 API 权限）
    chrome.runtime.sendMessage(
      { action, ...payload },
      (response) => {
        // 将响应返回给页面脚本
        window.postMessage(
          {
            type: 'EXTENSION_RESPONSE',
            id,
            response,
            error: chrome.runtime.lastError ? chrome.runtime.lastError.message : null
          },
          '*'
        );
      }
    );
  });

  console.log('[Content Bridge] 已加载，测试页面可以与扩展通信');
})();
