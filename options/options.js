// Options页面脚本 - 管理设置页面的交互逻辑

// 页面加载时初始化
document.addEventListener('DOMContentLoaded', () => {
  loadConfig();
  loadWhitelist();
  loadHistory();
  loadStats();
  loadDbStats();
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
    // URL覆盖采集
    document.getElementById('scanElements').checked = config.urlDetection.scanElements !== false;
    document.getElementById('scanFetch').checked = config.urlDetection.scanFetch !== false;
    document.getElementById('scanXHR').checked = config.urlDetection.scanXHR !== false;
    document.getElementById('scanWebSocket').checked = config.urlDetection.scanWebSocket !== false;
    document.getElementById('scanWindowOpen').checked = config.urlDetection.scanWindowOpen !== false;
    document.getElementById('scanMetaRefresh').checked = config.urlDetection.scanMetaRefresh !== false;
    document.getElementById('scanCssUrls').checked = !!config.urlDetection.scanCssUrls;
    document.getElementById('dedupeTtlMs').value = Number(config.urlDetection.dedupeTtlMs || 120000);

    // 恶意库在线源与刷新间隔
    const sources = Array.isArray(config.urlDetection.sources) ? config.urlDetection.sources : [];
    document.getElementById('dbSources').value = sources.join('\n');
    document.getElementById('refreshIntervalHours').value = config.urlDetection.refreshIntervalHours || 24;
    
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
      addWhitelistItem(normalizeDomain(domain.trim()));
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

  // 恶意库：立即刷新
  const refreshBtn = document.getElementById('refreshDbBtn');
  refreshBtn.addEventListener('click', async () => {
    try {
      refreshBtn.disabled = true;
      const originalText = refreshBtn.textContent;
      refreshBtn.textContent = '刷新中...';
      const res = await chrome.runtime.sendMessage({ action: 'refresh_malicious_db' });
      await loadDbStats();
      alert(res && res.success ? `刷新完成，新增 ${res.added || 0} 项` : '刷新失败');
      refreshBtn.textContent = originalText;
      refreshBtn.disabled = false;
    } catch (e) {
      alert('刷新失败：' + e);
      refreshBtn.disabled = false;
    }
  });

  // 恶意库：导入（文件）
  const importBtn = document.getElementById('importDbBtn');
  const importFile = document.getElementById('importDbFile');
  importBtn.addEventListener('click', () => importFile.click());
  importFile.addEventListener('change', async (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    try {
      const text = await file.text();
      let domains = [];
      let patterns = [];
      const trimmed = text.trim();
      if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
        // JSON 格式
        const data = JSON.parse(trimmed);
        if (Array.isArray(data)) {
          // 纯数组 => 按行解析为域名
          domains = data.map(String);
        } else {
          if (Array.isArray(data.domains)) domains = data.domains;
          if (Array.isArray(data.patterns)) patterns = data.patterns;
          // 兼容部分格式：如 list 字段
          if (Array.isArray(data.list) && domains.length === 0 && patterns.length === 0) {
            domains = data.list.map(String);
          }
        }
      } else {
        // 纯文本：每行一个，/#...#/ 视为正则
        trimmed.split(/\r?\n/).forEach(line => {
          const s = line.trim();
          if (!s || s.startsWith('#')) return;
          if (s.startsWith('/') && s.endsWith('/')) {
            patterns.push(s.slice(1, -1));
          } else {
            domains.push(s);
          }
        });
      }
      const resp = await chrome.runtime.sendMessage({ action: 'import_malicious_list', domains, patterns });
      if (resp && resp.success) {
        await loadDbStats();
        alert(`导入成功。当前：域名 ${resp.counts?.domains ?? '-'}，正则 ${resp.counts?.patterns ?? '-'}`);
      } else {
        alert('导入失败：' + (resp && resp.error ? resp.error : '未知错误'));
      }
    } catch (err) {
      alert('解析/导入失败：' + err);
    } finally {
      // 重置文件选择
      e.target.value = '';
    }
  });

  // 恶意库：导出（读取本地存储的 maliciousDb）
  document.getElementById('exportDbBtn').addEventListener('click', async () => {
    const { maliciousDb } = await chrome.storage.local.get(['maliciousDb']);
    const data = maliciousDb || { domains: [], patterns: [], updatedAt: 0 };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `malicious-db-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
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
      checkFrequency: document.getElementById('checkFrequency').value,
      // 采集开关
      scanElements: document.getElementById('scanElements').checked,
      scanFetch: document.getElementById('scanFetch').checked,
      scanXHR: document.getElementById('scanXHR').checked,
      scanWebSocket: document.getElementById('scanWebSocket').checked,
      scanWindowOpen: document.getElementById('scanWindowOpen').checked,
      scanMetaRefresh: document.getElementById('scanMetaRefresh').checked,
      scanCssUrls: document.getElementById('scanCssUrls').checked,
      dedupeTtlMs: Math.max(1000, Number(document.getElementById('dedupeTtlMs').value || 120000)),
      // 同步恶意库在线源与刷新间隔
      sources: document.getElementById('dbSources').value
        .split(/\r?\n/)
        .map(s => s.trim())
        .filter(Boolean),
      refreshIntervalHours: Math.max(0.5, Number(document.getElementById('refreshIntervalHours').value || 24))
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

// 归一化域名/URL到 host[:port]
function normalizeDomain(input) {
  if (!input) return '';
  let s = String(input).trim();
  try {
    if (/^https?:\/\//i.test(s)) {
      const u = new URL(s);
      s = u.host || u.hostname || '';
    }
  } catch(e) {}
  return s.replace(/\/+$/, '').toLowerCase();
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
      checkFrequency: 'realtime',
      // 覆盖采集默认开启（CSS 解析默认关闭）
      scanElements: true,
      scanFetch: true,
      scanXHR: true,
      scanWebSocket: true,
      scanWindowOpen: true,
      scanMetaRefresh: true,
      scanCssUrls: false,
      dedupeTtlMs: 120000,
      sources: [],
      refreshIntervalHours: 24
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

// 加载恶意库统计信息
async function loadDbStats() {
  try {
    const resp = await chrome.runtime.sendMessage({ action: 'get_malicious_db' });
    const db = resp && resp.db ? resp.db : { count: { domains: 0, patterns: 0 }, updatedAt: 0 };
    document.getElementById('dbDomainsCount').textContent = db.count?.domains ?? 0;
    document.getElementById('dbPatternsCount').textContent = db.count?.patterns ?? 0;
    const t = db.updatedAt ? new Date(db.updatedAt) : null;
    document.getElementById('dbUpdatedAt').textContent = t ? t.toLocaleString('zh-CN') : '-';
  } catch (e) {
    // 忽略错误
  }
}

