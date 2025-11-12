// Options页面脚本 - 管理设置页面的交互逻辑

// 页面加载时初始化
document.addEventListener('DOMContentLoaded', () => {
  loadConfig();
  loadWhitelist();
  loadHistory();
  loadStats();
  setupEventListeners();
});

// 加载配置
function loadConfig() {
  chrome.storage.local.get(['config'], (result) => {
    const config = result.config || getDefaultConfig();
    
    // URL检测设置
    document.getElementById('urlDetectionEnabled').checked = config.urlDetection.enabled;
    document.querySelector(`input[name="dataSource"][value="${config.urlDetection.dataSource}"]`).checked = true;
    document.getElementById('checkFrequency').value = config.urlDetection.checkFrequency || 'realtime';
    
    // XSS防护设置
    document.getElementById('xssProtectionEnabled').checked = config.xssProtection.enabled;
    document.getElementById('xssLevel').value = config.xssProtection.level || 'standard';
    document.getElementById('xssAutoBlock').checked = config.xssProtection.autoBlock;
    document.getElementById('xssShowConfirm').checked = config.xssProtection.showConfirm;
    
    // 追踪阻止设置
    document.getElementById('trackerBlockingEnabled').checked = config.trackerBlocking.enabled;
    document.getElementById('blockAds').checked = config.trackerBlocking.blockTypes.ads;
    document.getElementById('blockSocial').checked = config.trackerBlocking.blockTypes.social;
    document.getElementById('blockDataCollection').checked = config.trackerBlocking.blockTypes.dataCollection;
    document.getElementById('blockFingerprinting').checked = config.trackerBlocking.blockTypes.fingerprinting;
    document.getElementById('thirdPartyCookies').checked = config.trackerBlocking.thirdPartyCookies;
    document.getElementById('canvasProtection').checked = config.trackerBlocking.canvasProtection;
    document.getElementById('webrtcProtection').checked = config.trackerBlocking.webrtcProtection;
    
    // 隐私设置
    document.getElementById('anonymousReport').checked = config.privacy?.anonymousReport !== false;
    document.getElementById('autoUpdate').checked = config.privacy?.autoUpdate !== false;
  });
}

// 加载白名单
function loadWhitelist() {
  chrome.storage.local.get(['config'], (result) => {
    const config = result.config || getDefaultConfig();
    const whitelist = config.whitelist || [];
    const listEl = document.getElementById('whitelistList');
    
    listEl.innerHTML = '';
    
    if (whitelist.length === 0) {
      listEl.innerHTML = '<p style="color: #999; padding: 12px;">暂无白名单网站</p>';
      return;
    }
    
    whitelist.forEach((domain, index) => {
      const item = document.createElement('div');
      item.className = 'whitelist-item';
      item.innerHTML = `
        <span class="domain">${escapeHtml(domain)}</span>
        <button class="btn-remove" data-index="${index}">删除</button>
      `;
      listEl.appendChild(item);
    });
    
    // 绑定删除事件
    document.querySelectorAll('.btn-remove').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const index = parseInt(e.target.dataset.index);
        removeWhitelistItem(index);
      });
    });
  });
}

// 加载历史记录
function loadHistory() {
  chrome.storage.local.get(['history'], (result) => {
    const history = result.history || [];
    const listEl = document.getElementById('historyList');
    
    listEl.innerHTML = '';
    
    if (history.length === 0) {
      listEl.innerHTML = '<p style="color: #999; padding: 12px;">暂无历史记录</p>';
      return;
    }
    
    // 显示最近10条记录
    const recentHistory = history.slice(-10).reverse();
    recentHistory.forEach(item => {
      const historyItem = document.createElement('div');
      historyItem.className = 'history-item';
      
      const time = new Date(item.timestamp);
      const timeStr = formatTime(time);
      
      historyItem.innerHTML = `
        <div class="time">📅 ${timeStr}</div>
        <div class="event">${escapeHtml(item.event)}</div>
        ${item.location ? `<div class="location">位置: ${escapeHtml(item.location)}</div>` : ''}
      `;
      
      listEl.appendChild(historyItem);
    });
  });
}

// 加载统计数据
function loadStats() {
  chrome.storage.local.get(['config'], (result) => {
    const config = result.config || getDefaultConfig();
    const stats = config.stats || { threatsBlocked: 0, trackersBlocked: 0, xssIntercepted: 0 };
    
    document.getElementById('threatsBlocked').textContent = stats.threatsBlocked || 0;
    document.getElementById('trackersBlocked').textContent = stats.trackersBlocked || 0;
    document.getElementById('xssIntercepted').textContent = stats.xssIntercepted || 0;
  });
}

// 设置事件监听器
function setupEventListeners() {
  // 添加白名单
  document.getElementById('addWhitelistBtn').addEventListener('click', () => {
    const domain = prompt('请输入要添加的网站域名（例如: example.com）:');
    if (domain && domain.trim()) {
      addWhitelistItem(domain.trim());
    }
  });
  
  // 保存设置
  document.getElementById('saveBtn').addEventListener('click', () => {
    saveConfig();
  });
  
  // 清除数据
  document.getElementById('clearDataBtn').addEventListener('click', () => {
    if (confirm('确定要清除所有数据吗？此操作不可恢复。')) {
      clearAllData();
    }
  });
  
  // 重置设置
  document.getElementById('resetBtn').addEventListener('click', () => {
    if (confirm('确定要重置为默认设置吗？')) {
      resetToDefault();
    }
  });
  
  // 生成报告
  document.getElementById('generateReportBtn').addEventListener('click', () => {
    generateReport();
  });
  
  // 加载更多历史
  document.getElementById('loadMoreHistory').addEventListener('click', () => {
    // 这里可以加载更多历史记录
    alert('历史记录加载功能开发中...');
  });
}

// 保存配置
function saveConfig() {
  chrome.storage.local.get(['config'], (result) => {
    const config = result.config || getDefaultConfig();
    
    // 更新配置
    config.urlDetection = {
      enabled: document.getElementById('urlDetectionEnabled').checked,
      dataSource: document.querySelector('input[name="dataSource"]:checked').value,
      checkFrequency: document.getElementById('checkFrequency').value
    };
    
    config.xssProtection = {
      enabled: document.getElementById('xssProtectionEnabled').checked,
      level: document.getElementById('xssLevel').value,
      autoBlock: document.getElementById('xssAutoBlock').checked,
      showConfirm: document.getElementById('xssShowConfirm').checked
    };
    
    config.trackerBlocking = {
      enabled: document.getElementById('trackerBlockingEnabled').checked,
      blockTypes: {
        ads: document.getElementById('blockAds').checked,
        social: document.getElementById('blockSocial').checked,
        dataCollection: document.getElementById('blockDataCollection').checked,
        fingerprinting: document.getElementById('blockFingerprinting').checked
      },
      thirdPartyCookies: document.getElementById('thirdPartyCookies').checked,
      canvasProtection: document.getElementById('canvasProtection').checked,
      webrtcProtection: document.getElementById('webrtcProtection').checked
    };
    
    config.privacy = {
      anonymousReport: document.getElementById('anonymousReport').checked,
      autoUpdate: document.getElementById('autoUpdate').checked
    };
    
    chrome.storage.local.set({ config }, () => {
      alert('设置已保存！');
      
      // 通知background更新
      chrome.runtime.sendMessage({
        action: 'update_config',
        config: config
      });
    });
  });
}

// 添加白名单项
function addWhitelistItem(domain) {
  chrome.storage.local.get(['config'], (result) => {
    const config = result.config || getDefaultConfig();
    
    if (!config.whitelist) {
      config.whitelist = [];
    }
    
    if (!config.whitelist.includes(domain)) {
      config.whitelist.push(domain);
      chrome.storage.local.set({ config }, () => {
        loadWhitelist();
      });
    } else {
      alert('该网站已在白名单中');
    }
  });
}

// 删除白名单项
function removeWhitelistItem(index) {
  chrome.storage.local.get(['config'], (result) => {
    const config = result.config || getDefaultConfig();
    
    if (config.whitelist && config.whitelist[index]) {
      config.whitelist.splice(index, 1);
      chrome.storage.local.set({ config }, () => {
        loadWhitelist();
      });
    }
  });
}

// 清除所有数据
function clearAllData() {
  chrome.storage.local.clear(() => {
    chrome.storage.local.set({ config: getDefaultConfig() }, () => {
      loadConfig();
      loadWhitelist();
      loadHistory();
      loadStats();
      alert('所有数据已清除');
    });
  });
}

// 重置为默认设置
function resetToDefault() {
  chrome.storage.local.set({ config: getDefaultConfig() }, () => {
    loadConfig();
    alert('已重置为默认设置');
  });
}

// 生成报告
function generateReport() {
  chrome.storage.local.get(['config'], (result) => {
    const config = result.config || getDefaultConfig();
    const stats = config.stats || {};
    
    const report = `
安全浏览器插件 - 详细报告
========================

统计信息：
- 已阻止威胁: ${stats.threatsBlocked || 0} 次
- 已阻止追踪器: ${stats.trackersBlocked || 0} 个
- XSS拦截: ${stats.xssIntercepted || 0} 次

功能状态：
- URL检测: ${config.urlDetection?.enabled ? '已启用' : '已禁用'}
- XSS防护: ${config.xssProtection?.enabled ? '已启用' : '已禁用'}
- 追踪阻止: ${config.trackerBlocking?.enabled ? '已启用' : '已禁用'}

生成时间: ${new Date().toLocaleString('zh-CN')}
    `;
    
    // 创建下载链接
    const blob = new Blob([report], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `安全报告_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  });
}

// 获取默认配置
function getDefaultConfig() {
  return {
    urlDetection: {
      enabled: true,
      dataSource: 'local',
      checkFrequency: 'realtime'
    },
    xssProtection: {
      enabled: true,
      level: 'standard',
      autoBlock: true,
      showConfirm: false
    },
    trackerBlocking: {
      enabled: true,
      blockTypes: {
        ads: true,
        social: true,
        dataCollection: true,
        fingerprinting: true
      },
      thirdPartyCookies: true,
      canvasProtection: true,
      webrtcProtection: true
    },
    whitelist: [],
    stats: {
      threatsBlocked: 0,
      trackersBlocked: 0,
      xssIntercepted: 0
    },
    privacy: {
      anonymousReport: true,
      autoUpdate: true
    }
  };
}

// 工具函数
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function formatTime(date) {
  const now = new Date();
  const diff = now - date;
  const minutes = Math.floor(diff / 60000);
  
  if (minutes < 1) {
    return '刚刚';
  } else if (minutes < 60) {
    return `${minutes}分钟前`;
  } else if (minutes < 1440) {
    const hours = Math.floor(minutes / 60);
    return `${hours}小时前`;
  } else {
    return date.toLocaleString('zh-CN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    });
  }
}

