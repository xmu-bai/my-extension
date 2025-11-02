// 弹窗打开时检查当前页面状态
document.addEventListener('DOMContentLoaded', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  // 获取自动扫描设置
  chrome.storage.sync.get('autoScan', (data) => {
    document.getElementById('autoScan').checked = data.autoScan || false;
  });

  // 立即扫描按钮
  document.getElementById('scanBtn').addEventListener('click', () => {
    scanCurrentPage(tab);
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

function scanCurrentPage(tab) {
  document.getElementById('scanBtn').textContent = '扫描中...';
  document.getElementById('scanBtn').disabled = true;
  
  chrome.tabs.sendMessage(tab.id, { action: 'scanPage' }, (response) => {
    updateStatus(response?.result || '扫描失败，请刷新页面重试');
    document.getElementById('scanBtn').textContent = '立即扫描页面';
    document.getElementById('scanBtn').disabled = false;
  });
}

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

async function checkCurrentPageStatus(tab) {
  try {
    const response = await chrome.tabs.sendMessage(tab.id, { action: 'scanPage' });
    updateStatus(response.result);
  } catch (error) {
    updateStatus('无法扫描此页面（可能不是HTTP/HTTPS页面）');
  }
}