// 页面加载时初始化
document.addEventListener('DOMContentLoaded', () => {
  loadSettings();
  loadStats();
  bindEvents();
});

// 绑定事件
function bindEvents() {
  document.getElementById('saveBtn').addEventListener('click', saveSettings);
  document.getElementById('resetBtn').addEventListener('click', resetSettings);
  document.getElementById('exportBtn').addEventListener('click', exportSettings);
  document.getElementById('resetStatsBtn').addEventListener('click', resetStats);
  document.getElementById('openTestPageBtn').addEventListener('click', openTestPage);
}

// 加载设置
function loadSettings() {
  chrome.storage.sync.get({
    // 全局设置
    autoScan: false,
    notifications: true,
    
    // XSS设置
    xssEnabled: true,
    xssDepth: 1,
    autoSendRequest: false,
    
    // 高级设置
    sensitivity: 'medium',
    cacheTimeout: 5,
    ignoredSites: []
  }, (settings) => {
    // 全局设置
    document.getElementById('autoScan').checked = settings.autoScan;
    document.getElementById('notifications').checked = settings.notifications;
    
    // XSS设置
    document.getElementById('xssEnabled').checked = settings.xssEnabled;
    document.getElementById('xssDepth').value = settings.xssDepth;
    document.getElementById('autoSendRequest').checked = settings.autoSendRequest;
    
    // 高级设置
    document.getElementById('sensitivity').value = settings.sensitivity;
    document.getElementById('cacheTimeout').value = settings.cacheTimeout;
    document.getElementById('ignoredSites').value = settings.ignoredSites.join('\n');
  });
}

// 加载统计信息
function loadStats() {
  chrome.runtime.sendMessage({ action: 'getStats' }, (response) => {
    if (response) {
      document.getElementById('statsRequests').textContent = response.requestCount || 0;
      document.getElementById('statsVulns').textContent = response.vulnerabilityCount || 0;
    }
  });
}

// 保存设置
function saveSettings() {
  const settings = {
    // 全局设置
    autoScan: document.getElementById('autoScan').checked,
    notifications: document.getElementById('notifications').checked,
    
    // XSS设置
    xssEnabled: document.getElementById('xssEnabled').checked,
    xssDepth: parseInt(document.getElementById('xssDepth').value),
    autoSendRequest: document.getElementById('autoSendRequest').checked,
    
    // 高级设置
    sensitivity: document.getElementById('sensitivity').value,
    cacheTimeout: parseInt(document.getElementById('cacheTimeout').value),
    ignoredSites: document.getElementById('ignoredSites').value.split('\n')
      .map(site => site.trim())
      .filter(site => site && !site.startsWith('#')) // 忽略注释行
  };

  // 验证设置
  if (settings.cacheTimeout < 1 || settings.cacheTimeout > 60) {
    showMessage('请求缓存时长必须在1-60分钟之间', 'error');
    return;
  }

  chrome.storage.sync.set(settings, () => {
    showMessage('✓ 设置已保存！', 'success');
    
    // 如果XSS设置改变，通知background更新
    if (settings.xssEnabled) {
      chrome.runtime.sendMessage({
        action: 'updateConfig',
        config: {
          enabled: settings.xssEnabled,
          depth: settings.xssDepth
        }
      });
    }
  });
}

// 恢复默认设置
function resetSettings() {
  if (confirm('确定要恢复默认设置吗？所有自定义设置将会丢失。')) {
    const defaultSettings = {
      autoScan: false,
      notifications: true,
      xssEnabled: true,
      xssDepth: 1,
      autoSendRequest: false,
      sensitivity: 'medium',
      cacheTimeout: 5,
      ignoredSites: []
    };

    chrome.storage.sync.set(defaultSettings, () => {
      loadSettings();
      showMessage('设置已重置为默认值', 'success');
    });
  }
}

// 导出设置
function exportSettings() {
  chrome.storage.sync.get(null, (settings) => {
    const dataStr = JSON.stringify(settings, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `security-assistant-settings-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
    
    showMessage('配置已导出', 'success');
  });
}

// 重置统计
function resetStats() {
  if (confirm('确定要重置统计数据吗？')) {
    chrome.runtime.sendMessage({ action: 'resetStats' }, (response) => {
      if (response && response.success) {
        loadStats();
        showMessage('统计数据已重置', 'success');
      }
    });
  }
}

// 打开测试页面
function openTestPage() {
  chrome.tabs.create({
    url: chrome.runtime.getURL('test/index.html')
  });
}

// 显示消息
function showMessage(message, type = 'success') {
  const messageEl = document.createElement('div');
  messageEl.textContent = message;
  messageEl.className = `message message-${type}`;
  
  const style = type === 'success' ? {
    background: '#27ae60',
    color: 'white'
  } : {
    background: '#e74c3c',
    color: 'white'
  };
  
  messageEl.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    padding: 12px 20px;
    border-radius: 6px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    z-index: 1000;
    font-weight: 500;
  `;
  
  Object.assign(messageEl.style, style);
  
  document.body.appendChild(messageEl);
  setTimeout(() => {
    messageEl.style.transition = 'opacity 0.3s';
    messageEl.style.opacity = '0';
    setTimeout(() => messageEl.remove(), 300);
  }, 2000);
}