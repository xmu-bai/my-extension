// Helper: send message to a tab and capture chrome.runtime.lastError
function sendMessageToTab(tabId, message) {
  return new Promise((resolve) => {
    chrome.tabs.sendMessage(tabId, message, (response) => {
      if (chrome.runtime.lastError) {
        resolve({ error: true, message: chrome.runtime.lastError.message });
      } else {
        resolve({ error: false, response });
      }
    });
  });
}

// 尝试通过 chrome.scripting 注入内容脚本（MV3）
function injectContentScript(tabId) {
  return new Promise((resolve) => {
    if (!chrome.scripting || !chrome.scripting.executeScript) {
      resolve(false);
      return;
    }
    try {
      chrome.scripting.executeScript({
        target: { tabId },
        files: ['src/content-scripts/content.js']
      }, (results) => {
        if (chrome.runtime.lastError) {
          resolve(false);
        } else {
          resolve(true);
        }
      });
    } catch (e) {
      resolve(false);
    }
  });
}

// 弹窗打开时检查当前页面状态
document.addEventListener('DOMContentLoaded', () => {
  // 获取当前激活标签
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs && tabs[0];

    // 获取自动扫描设置（回退为 false）
    chrome.storage.sync.get('autoScan', (data) => {
      try {
        document.getElementById('autoScan').checked = data.autoScan || false;
      } catch (e) {}
    });

    // 立即扫描按钮
    document.getElementById('scanBtn').addEventListener('click', async () => {
      await scanCurrentPage(tab);
    });

    // 设置按钮
    document.getElementById('optionsBtn').addEventListener('click', () => {
      chrome.runtime.openOptionsPage();
    });

    // 自动扫描切换
    document.getElementById('autoScan').addEventListener('change', (e) => {
      chrome.storage.sync.set({ autoScan: e.target.checked });
    });

    // 初始状态检查
    checkCurrentPageStatus(tab);
  });
});

async function scanCurrentPage(tab) {
  const scanBtn = document.getElementById('scanBtn');
  scanBtn.textContent = '扫描中...';
  scanBtn.disabled = true;

  if (!tab || !tab.id || !tab.url || !tab.url.startsWith('http')) {
    updateStatus('无法扫描此页面（可能不是HTTP/HTTPS页面）');
    scanBtn.textContent = '立即扫描页面';
    scanBtn.disabled = false;
    return;
  }

  const result = await sendMessageToTab(tab.id, { action: 'scanPage' });
  if (result.error) {
    // 处理常见错误类型
    if (result.message && result.message.includes('Receiving end does not exist')) {
      // 可能内容脚本尚未注入，尝试动态注入并重试一次
      const injected = await injectContentScript(tab.id);
      if (injected) {
        const retry = await sendMessageToTab(tab.id, { action: 'scanPage' });
        if (!retry.error) {
          updateStatus(retry.response?.result || '扫描完成，但未返回结果');
        } else {
          updateStatus('尝试注入内容脚本后仍无法建立连接，请刷新页面或检查扩展权限');
        }
      } else {
        updateStatus('无法注入内容脚本（权限不足或该页面不支持脚本注入）');
      }
    } else if (result.message && result.message.includes('Extension context invalidated')) {
      updateStatus('扩展上下文已失效，请关闭并重新打开弹窗或重新加载扩展');
    } else {
      updateStatus('无法与页面建立连接：' + (result.message || '未知错误'));
    }
  } else {
    updateStatus(result.response?.result || '扫描失败，请刷新页面重试');
  }

  scanBtn.textContent = '立即扫描页面';
  scanBtn.disabled = false;
}

function updateStatus(result) {
  const statusEl = document.getElementById('status');
  statusEl.textContent = result;

  // 根据结果类型应用不同的样式类
  statusEl.className = 'status'; // 重置类

  if (typeof result === 'string' && (result.includes('未发现') || result.includes('安全'))) {
    statusEl.classList.add('safe');
  } else if (typeof result === 'string' && (result.includes('可疑') || result.includes('警告'))) {
    statusEl.classList.add('warning');
  } else if (typeof result === 'string' && (result.includes('失败') || result.includes('错误') || result.includes('无法'))) {
    statusEl.classList.add('danger');
  } else {
    statusEl.classList.add('warning'); // 默认警告样式
  }
}

async function checkCurrentPageStatus(tab) {
  if (!tab || !tab.id || !tab.url || !tab.url.startsWith('http')) {
    updateStatus('无法扫描此页面（可能不是HTTP/HTTPS页面）');
    return;
  }

  const result = await sendMessageToTab(tab.id, { action: 'scanPage' });
  if (result.error) {
    if (result.message && result.message.includes('Receiving end does not exist')) {
      const injected = await injectContentScript(tab.id);
      if (injected) {
        const retry = await sendMessageToTab(tab.id, { action: 'scanPage' });
        if (!retry.error) {
          updateStatus(retry.response?.result || '扫描完成，但未返回结果');
          return;
        }
      }
      updateStatus('无法与页面建立连接：内容脚本未注入或该页面不支持扫描');
    } else if (result.message && result.message.includes('Extension context invalidated')) {
      updateStatus('扩展上下文已失效，请关闭并重新打开弹窗或重新加载扩展');
    } else {
      updateStatus('无法与页面建立连接：' + (result.message || '未知错误'));
    }
  } else {
    updateStatus(result.response?.result || '未能获取页面状态');
  }
}