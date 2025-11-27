// 警告页面脚本 - 按钮交互与与后台通信

// 读取参数：目标 URL 与 tabId（用于在原标签页跳转/关闭）
const urlParams = new URLSearchParams(window.location.search);
const targetUrl = urlParams.get('url') || 'about:blank';
const tabIdParam = urlParams.get('tabId');
const tabId = tabIdParam ? parseInt(tabIdParam, 10) : null;

// 展示 URL
const urlDisplay = document.getElementById('urlDisplay');
if (urlDisplay) {
  try {
    urlDisplay.textContent = decodeURIComponent(targetUrl);
  } catch {
    urlDisplay.textContent = targetUrl;
  }
}

const backBtn = document.getElementById('backBtn');
const continueBtn = document.getElementById('continueBtn');

function safeSendMessage(payload) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(payload, (resp) => {
        // 忽略 lastError
        void chrome.runtime.lastError;
        resolve(resp);
      });
    } catch {
      resolve({ success: false });
    }
  });
}

// 返回安全：优先关闭原标签页，其次关闭当前标签或回退
backBtn && backBtn.addEventListener('click', async () => {
  if (tabId) {
    await safeSendMessage({ action: 'close_tab', tabId });
    return;
  }
  // 尝试关闭当前活动标签
  const closed = await safeSendMessage({ action: 'close_current_tab' });
  if (!closed?.success) {
    // 退一步，浏览器回退
    try { window.history.back(); } catch {}
  }
});

// 仍然继续：
continueBtn && continueBtn.addEventListener('click', async () => {
  if (!confirm('您确定要继续访问这个危险的网站吗？\n\n强烈建议不要继续！')) return;
  const decoded = (() => { try { return decodeURIComponent(targetUrl); } catch { return targetUrl; } })();

  // 通知后台临时放行该 URL（会话级，带 5 分钟失效）
  await safeSendMessage({ action: 'allow_malicious_url', url: decoded });

  if (tabId) {
    // 在原标签跳转
    const ok = await safeSendMessage({ action: 'navigate_tab', tabId, url: decoded });
    if (!ok?.success) {
      window.location.href = decoded;
    }
  } else {
    // 直接导航
    window.location.href = decoded;
  }
});
