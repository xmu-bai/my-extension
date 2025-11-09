// 警告页面脚本 - 处理按钮点击事件

console.log('[警告页面] 脚本开始加载');

// 从URL参数获取目标URL和标签页ID
const urlParams = new URLSearchParams(window.location.search);
const targetUrl = urlParams.get('url') || '未知网站';
const tabId = urlParams.get('tabId');

console.log('[警告页面] URL参数:', {
  targetUrl: targetUrl,
  tabId: tabId,
  fullUrl: window.location.href
});

// 显示URL
document.getElementById('urlDisplay').textContent = decodeURIComponent(targetUrl);

// 检查按钮是否存在
const backBtn = document.getElementById('backBtn');
const continueBtn = document.getElementById('continueBtn');

console.log('[警告页面] 按钮元素:', {
  backBtn: !!backBtn,
  continueBtn: !!continueBtn
});

if (!backBtn || !continueBtn) {
  console.error('[警告页面] 错误：按钮元素未找到！');
}

// 返回安全按钮 - 关闭当前标签页
backBtn.addEventListener('click', () => {
  console.log('[返回安全] 按钮被点击');
  console.log('[返回安全] tabId:', tabId);
  
  // 方法1: 如果有tabId，通过background关闭
  if (tabId) {
    console.log('[返回安全] 方法1: 使用tabId关闭标签页');
    chrome.runtime.sendMessage({
      action: 'close_tab',
      tabId: parseInt(tabId)
    }, (response) => {
      if (chrome.runtime.lastError) {
        console.error('[返回安全] 方法1失败:', chrome.runtime.lastError.message);
      } else {
        console.log('[返回安全] 方法1成功:', response);
      }
    });
  } else {
    console.log('[返回安全] 方法2: 尝试获取当前标签页');
    // 方法2: 尝试获取当前标签页并关闭
    chrome.tabs.getCurrent((tab) => {
      console.log('[返回安全] getCurrent结果:', tab);
      if (tab && tab.id) {
        console.log('[返回安全] 方法2成功，关闭标签页:', tab.id);
        chrome.tabs.remove(tab.id, () => {
          if (chrome.runtime.lastError) {
            console.error('[返回安全] 方法2关闭失败:', chrome.runtime.lastError.message);
          } else {
            console.log('[返回安全] 方法2关闭成功');
          }
        });
      } else {
        console.log('[返回安全] 方法3: 通过background查询并关闭');
        // 方法3: 通过background查询并关闭
        chrome.runtime.sendMessage({
          action: 'close_current_tab'
        }, (response) => {
          if (chrome.runtime.lastError) {
            console.error('[返回安全] 方法3失败:', chrome.runtime.lastError.message);
            console.log('[返回安全] 方法4: 使用history.back()');
            // 如果都失败，尝试返回上一页
            window.history.back();
          } else {
            console.log('[返回安全] 方法3成功:', response);
          }
        });
      }
    });
  }
});

// 仍然继续按钮 - 跳转到目标URL
continueBtn.addEventListener('click', () => {
  console.log('[仍然继续] 按钮被点击');
  console.log('[仍然继续] targetUrl:', targetUrl);
  console.log('[仍然继续] tabId:', tabId);
  
  if (confirm('您确定要继续访问这个危险的网站吗？\n\n强烈建议不要继续！')) {
    console.log('[仍然继续] 用户确认继续');
    const decodedUrl = decodeURIComponent(targetUrl);
    console.log('[仍然继续] 解码后的URL:', decodedUrl);
    
    // 通知background script允许访问此URL
    console.log('[仍然继续] 步骤1: 发送allow_malicious_url消息');
    chrome.runtime.sendMessage({
      action: 'allow_malicious_url',
      url: decodedUrl
    }, (response) => {
      if (chrome.runtime.lastError) {
        console.error('[仍然继续] allow_malicious_url失败:', chrome.runtime.lastError.message);
      } else {
        console.log('[仍然继续] allow_malicious_url成功:', response);
      }
      
      // 跳转到目标URL
      if (tabId) {
        console.log('[仍然继续] 步骤2: 使用tabId跳转');
        // 如果有tabId，通过background更新
        chrome.runtime.sendMessage({
          action: 'navigate_tab',
          tabId: parseInt(tabId),
          url: decodedUrl
        }, (response) => {
          if (chrome.runtime.lastError) {
            console.error('[仍然继续] navigate_tab失败:', chrome.runtime.lastError.message);
            console.log('[仍然继续] 降级: 使用window.location.href');
            // 如果失败，直接跳转
            window.location.href = decodedUrl;
          } else {
            console.log('[仍然继续] navigate_tab成功:', response);
          }
        });
      } else {
        console.log('[仍然继续] 步骤2: 尝试获取当前标签页');
        // 尝试获取当前标签页
        chrome.tabs.getCurrent((tab) => {
          console.log('[仍然继续] getCurrent结果:', tab);
          if (tab && tab.id) {
            console.log('[仍然继续] 使用tabs.update跳转:', tab.id);
            chrome.tabs.update(tab.id, { url: decodedUrl }, () => {
              if (chrome.runtime.lastError) {
                console.error('[仍然继续] tabs.update失败:', chrome.runtime.lastError.message);
                console.log('[仍然继续] 降级: 使用window.location.href');
                window.location.href = decodedUrl;
              } else {
                console.log('[仍然继续] tabs.update成功');
              }
            });
          } else {
            console.log('[仍然继续] 降级: 直接使用window.location.href');
            // 直接跳转
            window.location.href = decodedUrl;
          }
        });
      }
    });
  } else {
    console.log('[仍然继续] 用户取消');
  }
});

console.log('[警告页面] 事件监听器已绑定');

