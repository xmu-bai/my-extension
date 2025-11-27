(function(){
  'use strict';

  // 统一的动作层：上报、警告、阻断
  const Actions = {
    reportRisk(payload, { maxRetries = 2, baseDelay = 120 } = {}) {
      // 将上报交给后台进行持久化队列 + 退避发送
      const msg = { action: 'suspicious_url', report: payload };
      let attempt = 0;
      const send = () => {
        try {
          chrome.runtime.sendMessage(msg, () => {
            // 即使 content 发送失败，后台也会做队列。因此这里只做轻量重试。
            if (chrome.runtime.lastError && attempt < maxRetries) {
              attempt++;
              setTimeout(send, baseDelay * attempt);
            }
          });
        } catch {}
      };
      send();
    },

    warnUser({ url, risks }) {
      try {
        alert(`检测到危险URL:\n${url}\n风险类型：${(risks||[]).map(r => r.type).join(', ')}`);
      } catch {}
    },

    blockWithWarning({ url }) {
      try { window.stop?.(); } catch {}
      try {
        const warn = chrome.runtime.getURL('warning-pages/malicious-url.html');
        window.location.href = `${warn}?url=${encodeURIComponent(url)}`;
      } catch {}
    }
  };

  // 暴露到全局（供其他内容脚本直接使用）
  try { globalThis.Actions = Actions; } catch { window.Actions = Actions; }
})();
