// Popup脚本 - 管理弹出窗口的交互逻辑

// 页面加载时初始化
document.addEventListener('DOMContentLoaded', () => {
  loadConfig();
  loadCurrentPageStatus();
  setupEventListeners();
});

// 加载配置
function loadConfig() {
  chrome.storage.local.get(['config'], (result) => {
    const config = result.config || getDefaultConfig();
    
    // 更新开关状态
    document.getElementById('urlSwitch').checked = config.urlDetection.enabled;
    document.getElementById('xssSwitch').checked = config.xssProtection.enabled;
    document.getElementById('trackerSwitch').checked = config.trackerBlocking.enabled;
    
    // 更新开关状态文本
    updateSwitchStatus('urlSwitch', 'urlSwitchStatus', config.urlDetection.enabled);
    updateSwitchStatus('xssSwitch', 'xssSwitchStatus', config.xssProtection.enabled);
    updateSwitchStatus('trackerSwitch', 'trackerSwitchStatus', config.trackerBlocking.enabled);
    
    // 更新统计信息
    updateStats(config);
  });
}

// 加载当前页面状态
function loadCurrentPageStatus() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) {
      const url = tabs[0].url;
      checkPageSecurity(url);
      
      // 从content script获取追踪器数量
      chrome.tabs.sendMessage(tabs[0].id, { action: 'get_tracker_count' }, (response) => {
        if (chrome.runtime.lastError) {
          // content script可能还未加载，使用存储的统计数据
          chrome.storage.local.get(['config'], (result) => {
            const config = result.config || getDefaultConfig();
            document.getElementById('trackersCount').textContent = 
              config.stats?.trackersBlocked || 0;
          });
        } else if (response && response.count !== undefined) {
          document.getElementById('trackersCount').textContent = response.count;
        }
      });
    }
  });
}

// 检查页面安全性
function checkPageSecurity(url) {
  if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://')) {
    updateStatusCard('safe', '页面安全', '当前页面无需检测');
    return;
  }

  // 检查是否是恶意URL（简化版）
  const maliciousPatterns = ['phishing', 'malware', 'scam'];
  const isMalicious = maliciousPatterns.some(pattern => url.toLowerCase().includes(pattern));
  
  if (isMalicious) {
    updateStatusCard('danger', '⚠️ 危险页面', '检测到潜在威胁');
  } else {
    updateStatusCard('safe', '✅ 页面安全', '当前页面未发现威胁');
  }
}

// 更新状态卡片
function updateStatusCard(status, title, desc) {
  const card = document.getElementById('statusCard');
  const icon = document.getElementById('statusIcon');
  const titleEl = document.getElementById('statusTitle');
  const descEl = document.getElementById('statusDesc');
  
  card.className = `status-card ${status}`;
  icon.textContent = status === 'safe' ? '✅' : status === 'warning' ? '⚠️' : '❌';
  titleEl.textContent = title;
  descEl.textContent = desc;
}

// 更新统计数据
function updateStats(config) {
  if (config.stats) {
    // 可以在这里显示更多统计数据
    document.getElementById('xssStatus').textContent = 
      config.xssProtection.enabled ? '已启用' : '已禁用';
    document.getElementById('urlStatus').textContent = 
      config.urlDetection.enabled ? '已启用' : '已禁用';
  }
}

// 更新开关状态文本
function updateSwitchStatus(switchId, statusId, enabled) {
  const statusEl = document.getElementById(statusId);
  statusEl.textContent = enabled ? 'ON' : 'OFF';
  statusEl.style.color = enabled ? '#4CAF50' : '#666';
}

// 设置事件监听器
function setupEventListeners() {
  // 设置按钮
  document.getElementById('settingsBtn').addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });

  // 扫描按钮
  document.getElementById('scanBtn').addEventListener('click', () => {
    scanCurrentPage();
  });

  // URL检测开关
  document.getElementById('urlSwitch').addEventListener('change', (e) => {
    toggleFeature('urlDetection', e.target.checked);
    updateSwitchStatus('urlSwitch', 'urlSwitchStatus', e.target.checked);
  });

  // XSS防护开关
  document.getElementById('xssSwitch').addEventListener('change', (e) => {
    toggleFeature('xssProtection', e.target.checked);
    updateSwitchStatus('xssSwitch', 'xssSwitchStatus', e.target.checked);
  });

  // 追踪阻止开关
  document.getElementById('trackerSwitch').addEventListener('change', (e) => {
    toggleFeature('trackerBlocking', e.target.checked);
    updateSwitchStatus('trackerSwitch', 'trackerSwitchStatus', e.target.checked);
  });

  // 详细报告链接
  document.getElementById('reportLink').addEventListener('click', (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });
}

// 切换功能开关
function toggleFeature(feature, enabled) {
  chrome.storage.local.get(['config'], (result) => {
    const config = result.config || getDefaultConfig();
    
    if (feature === 'urlDetection') {
      config.urlDetection.enabled = enabled;
    } else if (feature === 'xssProtection') {
      config.xssProtection.enabled = enabled;
    } else if (feature === 'trackerBlocking') {
      config.trackerBlocking.enabled = enabled;
    }
    
    chrome.storage.local.set({ config }, () => {
      // 通知background更新
      chrome.runtime.sendMessage({
        action: 'update_config',
        config: config
      });
    });
  });
}

// 扫描当前页面
function scanCurrentPage() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) {
      // 显示扫描中状态
      const scanBtn = document.getElementById('scanBtn');
      const originalText = scanBtn.innerHTML;
      scanBtn.innerHTML = '<span>⏳</span> 扫描中...';
      scanBtn.disabled = true;
      
      // 向content script发送扫描请求
      chrome.tabs.sendMessage(tabs[0].id, { action: 'scan_page' }, (response) => {
        setTimeout(() => {
          scanBtn.innerHTML = originalText;
          scanBtn.disabled = false;
          
          // 更新状态
          if (response && response.safe !== undefined) {
            if (response.safe) {
              updateStatusCard('safe', '✅ 扫描完成', '未发现威胁');
            } else {
              updateStatusCard('warning', '⚠️ 发现威胁', '检测到 ' + response.threats + ' 个潜在威胁');
            }
          }
          
          // 刷新追踪器计数
          loadCurrentPageStatus();
        }, 1000);
      });
    }
  });
}

// 获取默认配置
function getDefaultConfig() {
  return {
    urlDetection: { enabled: true },
    xssProtection: { enabled: true },
    trackerBlocking: { enabled: true },
    stats: {
      threatsBlocked: 0,
      trackersBlocked: 0,
      xssIntercepted: 0
    }
  };
}

