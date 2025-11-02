// 页面加载时初始化
document.addEventListener('DOMContentLoaded', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  initPopup(tab);
});

// 初始化弹窗
async function initPopup(tab) {
  // 加载设置
  await loadSettings();
  
  // 绑定事件
  bindEvents(tab);
  
  // 初始化显示
  await updateXssStatus();
  await loadVulnerabilities();
  checkCurrentPageStatus(tab);
}

// 加载设置
async function loadSettings() {
  return new Promise((resolve) => {
    chrome.storage.sync.get({
      autoScan: false,
      xssEnabled: true,
      xssDepth: 1
    }, (data) => {
      document.getElementById('autoScan').checked = data.autoScan;
      document.getElementById('xssEnabled').checked = data.xssEnabled;
      document.getElementById('depthValue').textContent = data.xssDepth;
      resolve(data);
    });
  });
}

// 更新XSS状态
async function updateXssStatus() {
  // 更新启用状态
  const settings = await new Promise((resolve) => {
    chrome.storage.sync.get({ xssEnabled: true }, resolve);
  });
  
  const statusBadge = document.getElementById('xssEnabledStatus');
  if (settings.xssEnabled) {
    statusBadge.textContent = '已启用';
    statusBadge.className = 'status-badge enabled';
  } else {
    statusBadge.textContent = '已禁用';
    statusBadge.className = 'status-badge disabled';
  }

  // 更新请求计数
  updateRequestCount();
}

// 更新请求计数
function updateRequestCount() {
  // 从background获取统计信息
  chrome.runtime.sendMessage(
    { action: 'getStats' },
    (response) => {
      if (response && response.requestCount) {
        document.getElementById('requestCount').textContent = response.requestCount;
      }
    }
  );
}

// 加载漏洞列表
async function loadVulnerabilities() {
  chrome.runtime.sendMessage(
    { action: 'getVulnerabilities' },
    (response) => {
      if (response && response.vulnerabilities) {
        displayVulnerabilities(response.vulnerabilities);
      }
    }
  );
}

// 显示漏洞列表
function displayVulnerabilities(vulnerabilities) {
  const section = document.getElementById('vulnerabilitiesSection');
  const list = document.getElementById('vulnerabilitiesList');
  
  if (!vulnerabilities || vulnerabilities.length === 0) {
    section.style.display = 'none';
    return;
  }

  section.style.display = 'block';
  list.innerHTML = '';

  vulnerabilities.slice(0, 5).forEach((vuln, index) => {
    const item = document.createElement('div');
    item.className = 'vulnerability-item';
    
    const title = document.createElement('div');
    title.className = 'vuln-title';
    title.innerHTML = `<strong>漏洞 #${index + 1}:</strong> ${vuln.vulnerability || 'XSS'}`;
    
    const url = document.createElement('div');
    url.className = 'vuln-url';
    url.textContent = truncateUrl(vuln.url);
    
    const param = document.createElement('div');
    param.className = 'vuln-param';
    param.textContent = `参数: ${vuln.parameter}`;
    
    item.appendChild(title);
    item.appendChild(url);
    item.appendChild(param);
    list.appendChild(item);
  });

  if (vulnerabilities.length > 5) {
    const more = document.createElement('div');
    more.className = 'vuln-more';
    more.textContent = `还有 ${vulnerabilities.length - 5} 个漏洞...`;
    list.appendChild(more);
  }
}

// 截断URL显示
function truncateUrl(url) {
  if (!url) return '';
  if (url.length <= 40) return url;
  return url.substring(0, 37) + '...';
}

// 绑定事件
function bindEvents(tab) {
  // 扫描按钮
  document.getElementById('scanBtn').addEventListener('click', () => {
    scanCurrentPage(tab);
  });

  // 快速扫描按钮
  document.getElementById('quickScanBtn').addEventListener('click', () => {
    quickScanCurrentPage(tab);
  });

  // 设置按钮
  document.getElementById('optionsBtn').addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });

  // 清除记录按钮
  document.getElementById('clearBtn').addEventListener('click', () => {
    clearVulnerabilities();
  });

  // 自动扫描切换
  document.getElementById('autoScan').addEventListener('change', (e) => {
    chrome.storage.sync.set({ autoScan: e.target.checked });
  });

  // XSS检测切换
  document.getElementById('xssEnabled').addEventListener('change', (e) => {
    chrome.storage.sync.set({ xssEnabled: e.target.checked });
    updateXssStatus();
  });
}

// 扫描当前页面
function scanCurrentPage(tab) {
  document.getElementById('scanBtn').textContent = '扫描中...';
  document.getElementById('scanBtn').disabled = true;
  
  chrome.tabs.sendMessage(tab.id, { action: 'scanPage' }, (response) => {
    updateStatus(response?.result || '扫描失败，请刷新页面重试');
    document.getElementById('scanBtn').textContent = '立即扫描页面';
    document.getElementById('scanBtn').disabled = false;
    loadVulnerabilities();
  });
}

// 快速扫描当前页面
function quickScanCurrentPage(tab) {
  document.getElementById('quickScanBtn').textContent = '扫描中...';
  document.getElementById('quickScanBtn').disabled = true;

  // 构造request对象，包含当前标签页的URL
  const request = {
    url: tab.url || window.location.href,
    method: 'GET',
    requestId: 'quick-scan-' + Date.now()
  };

  // 添加超时处理
  const timeout = setTimeout(() => {
    updateStatus('快速扫描超时');
    document.getElementById('quickScanBtn').textContent = '快速扫描';
    document.getElementById('quickScanBtn').disabled = false;
  }, 10000); // 10秒超时

  chrome.runtime.sendMessage({ 
    action: 'quickScan',
    data: request 
  }, (response) => {
    clearTimeout(timeout);
    
    if (chrome.runtime.lastError) {
      console.error('快速扫描错误:', chrome.runtime.lastError);
      updateStatus('快速扫描失败: ' + chrome.runtime.lastError.message);
      document.getElementById('quickScanBtn').textContent = '快速扫描';
      document.getElementById('quickScanBtn').disabled = false;
      return;
    }

    if (response && response.success) {
      const result = response.result;
      if (result.success) {
        if (result.suspicious) {
          updateStatus(`发现 ${result.parameters.length} 个可疑参数`);
        } else {
          updateStatus('未发现可疑参数');
        }
      } else {
        updateStatus(result.reason || '快速扫描完成，无结果');
      }
    } else {
      updateStatus(response?.error || '快速扫描失败');
    }
    
    document.getElementById('quickScanBtn').textContent = '快速扫描';
    document.getElementById('quickScanBtn').disabled = false;
  });
}

// 检查当前页面状态
async function checkCurrentPageStatus(tab) {
  try {
    const response = await chrome.tabs.sendMessage(tab.id, { action: 'scanPage' });
    updateStatus(response.result);
  } catch (error) {
    updateStatus('无法扫描此页面（可能不是HTTP/HTTPS页面）');
  }
}

// 更新状态显示
function updateStatus(result) {
  const statusEl = document.getElementById('status');
  statusEl.textContent = result;
  
  // 根据结果类型应用不同的样式类
  statusEl.className = 'status'; // 重置类
  
  if (result.includes('未发现') || result.includes('安全')) {
    statusEl.classList.add('safe');
  } else if (result.includes('可疑') || result.includes('警告')) {
    statusEl.classList.add('warning');
  } else if (result.includes('失败') || result.includes('错误')) {
    statusEl.classList.add('danger');
  } else {
    statusEl.classList.add('warning'); // 默认警告样式
  }
}

// 清除漏洞记录
function clearVulnerabilities() {
  chrome.runtime.sendMessage(
    { action: 'clearDetected' },
    (response) => {
      if (response && response.success) {
        displayVulnerabilities([]);
        updateStatus('漏洞记录已清除');
      }
    }
  );
}