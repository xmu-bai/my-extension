// 警告页面脚本 - 处理按钮点击事件

// 从URL参数获取目标URL和标签页ID
const urlParams = new URLSearchParams(window.location.search);
const targetUrl = urlParams.get('url') || '未知网站';
const tabId = urlParams.get('tabId');

// 显示URL
document.getElementById('urlDisplay').textContent = decodeURIComponent(targetUrl);

// 检查按钮是否存在
const backBtn = document.getElementById('backBtn');
const continueBtn = document.getElementById('continueBtn');

if (!backBtn || !continueBtn) {
  console.error('[警告页面] 错误：按钮元素未找到！');
}

// 返回安全按钮 - 关闭当前标签页
backBtn.addEventListener('click', () => {
  // 方法1: 如果有tabId，通过background关闭
  if (tabId) {
    chrome.runtime.sendMessage({
      action: 'close_tab',
      tabId: parseInt(tabId)
    }, (response) => {
      if (chrome.runtime.lastError) {
        console.error('[返回安全] 关闭标签页失败:', chrome.runtime.lastError.message);
      }
    });
  } else {
    // 方法2: 尝试获取当前标签页并关闭
    chrome.tabs.getCurrent((tab) => {
      if (tab && tab.id) {
        chrome.tabs.remove(tab.id, () => {
          if (chrome.runtime.lastError) {
            console.error('[返回安全] 关闭标签页失败:', chrome.runtime.lastError.message);
          }
        });
      } else {
        // 方法3: 通过background查询并关闭
        chrome.runtime.sendMessage({
          action: 'close_current_tab'
        }, (response) => {
          if (chrome.runtime.lastError) {
            console.error('[返回安全] 关闭标签页失败:', chrome.runtime.lastError.message);
            // 如果都失败，尝试返回上一页
            window.history.back();
          }
        });
      }
    });
  }
});

// 仍然继续按钮 - 跳转到目标URL
continueBtn.addEventListener('click', () => {
  if (confirm('您确定要继续访问这个危险的网站吗？\n\n强烈建议不要继续！')) {
    const decodedUrl = decodeURIComponent(targetUrl);
    
    // 通知background script允许访问此URL
    chrome.runtime.sendMessage({
      action: 'allow_malicious_url',
      url: decodedUrl
    }, (response) => {
      if (chrome.runtime.lastError) {
        console.error('[仍然继续] 允许URL失败:', chrome.runtime.lastError.message);
      }
      
      // 跳转到目标URL
      if (tabId) {
        // 如果有tabId，通过background更新
        chrome.runtime.sendMessage({
          action: 'navigate_tab',
          tabId: parseInt(tabId),
          url: decodedUrl
        }, (response) => {
          if (chrome.runtime.lastError) {
            console.error('[仍然继续] 跳转失败:', chrome.runtime.lastError.message);
            // 如果失败，直接跳转
            window.location.href = decodedUrl;
          }
        });
      } else {
        // 尝试获取当前标签页
        chrome.tabs.getCurrent((tab) => {
          if (tab && tab.id) {
            chrome.tabs.update(tab.id, { url: decodedUrl }, () => {
              if (chrome.runtime.lastError) {
                console.error('[仍然继续] 跳转失败:', chrome.runtime.lastError.message);
                window.location.href = decodedUrl;
              }
            });
          } else {
            // 直接跳转
            window.location.href = decodedUrl;
          }
        });
      }
    });
  }
});

