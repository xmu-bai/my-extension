// NOTE: options page is loaded directly as a plain script (not bundled),
// so we must not use ESM import here. Inline the minimal STORAGE_KEYS used by this page.
const STORAGE_KEYS = {
  DETECTOR_CONFIG: 'xss_detector_config'
};

document.addEventListener('DOMContentLoaded', loadSettings);
document.getElementById('saveBtn').addEventListener('click', saveSettings);
document.getElementById('resetBtn').addEventListener('click', resetSettings);
document.getElementById('addIgnoredBtn').addEventListener('click', addIgnoredEntry);
document.getElementById('importBtn').addEventListener('click', importIgnoredList);
document.getElementById('exportBtn').addEventListener('click', exportIgnoredList);

// 显示提示信息（实现）
function showMessage(text, isError = false) {
  const container = document.getElementById('messageContainer');
  if (!container) return;
  container.innerText = text;
  container.className = 'message ' + (isError ? 'error' : 'success');
  // 自动清除提示
  setTimeout(() => {
    container.innerText = '';
    container.className = '';
  }, 4000);
}

// 加载设置（使用统一配置接口和存储键）
function loadSettings() {
  chrome.storage.sync.get(STORAGE_KEYS.DETECTOR_CONFIG, (data) => {
    const settings = data[STORAGE_KEYS.DETECTOR_CONFIG] || {
      enabled: false,
      detectionLevel: 'MEDIUM',
      showNotification: true,
      ignoredDomains: []
    };

    if (chrome.runtime.lastError) {
      showMessage(`加载设置失败: ${chrome.runtime.lastError.message}`, true);
      return;
    }

  document.getElementById('autoScan').checked = settings.enabled;
  document.getElementById('notifications').checked = settings.showNotification;
  document.getElementById('sensitivity').value = settings.detectionLevel || 'MEDIUM';
  renderIgnoredList(settings.ignoredDomains || []);
  });
}

// 保存设置（对齐配置接口）
function saveSettings() {
  // 始终从 ul 列表收集所有条目（与 saveIgnoredList 保持一致）
  const ignoredList = document.getElementById('ignoredList');
  const ignoredDomains = Array.from(ignoredList.children)
    .map(li => li.childNodes[0] ? li.childNodes[0].textContent.trim() : '')
    .filter(site => site && !site.startsWith('#'));

  const settings = {
    enabled: document.getElementById('autoScan').checked,
    detectionLevel: document.getElementById('sensitivity').value.toUpperCase(),
    showNotification: document.getElementById('notifications').checked,
    ignoredDomains: ignoredDomains,
    targetMethods: ['GET', 'POST'],
    ignoreHttps: false,
    recordHistory: true,
    historyRetentionDays: 30
  };

  chrome.storage.sync.set({ [STORAGE_KEYS.DETECTOR_CONFIG]: settings }, () => {
    if (chrome.runtime.lastError) {
      showMessage(`保存设置失败: ${chrome.runtime.lastError.message}`, true);
      return;
    }
    showMessage('✓ 设置已保存！');
    // 通知所有 tab 配置已更新
    chrome.tabs.query({}, (tabs) => {
      tabs.forEach(tab => {
        try {
          if (!tab.id) return;
          if (tab.url && !tab.url.startsWith('http')) return;
          chrome.tabs.sendMessage(tab.id, { type: 'CONFIG_UPDATED' }, (resp) => {
            // 忽略错误
          });
        } catch (e) {}
      });
    });
  });
}
// 渲染白名单列表
function renderIgnoredList(list) {
  const ul = document.getElementById('ignoredList');
  ul.innerHTML = '';
  list.forEach(site => {
    const li = document.createElement('li');
    li.textContent = site;
    const delBtn = document.createElement('button');
    delBtn.textContent = '删除';
    delBtn.className = 'delBtn';
    delBtn.onclick = function() {
      ul.removeChild(li);
      saveIgnoredList();
    };
    li.appendChild(delBtn);
    ul.appendChild(li);
  });
}

// 归一化输入条目
function normalizeIgnoredEntry(input) {
  let site = input.trim();
  if (!site || site.startsWith('#')) return '';
  try {
    if (site.startsWith('http://') || site.startsWith('https://')) {
      const u = new URL(site);
      site = u.host || u.hostname;
    }
  } catch (e) {}
  return site.replace(/\/+$/, '');
}

// 添加新条目
function addIgnoredEntry() {
  const input = document.getElementById('ignoredInput');
  const entry = normalizeIgnoredEntry(input.value);
  if (!entry) {
    showMessage('无效条目或注释行', true);
    return;
  }
  const ul = document.getElementById('ignoredList');
  const exists = Array.from(ul.children).some(li => li.textContent.replace('删除','').trim() === entry);
  if (exists) {
    showMessage('条目已存在', true);
    return;
  }
  const li = document.createElement('li');
  li.textContent = entry;
  const delBtn = document.createElement('button');
  delBtn.textContent = '删除';
  delBtn.className = 'delBtn';
  delBtn.onclick = function() {
    ul.removeChild(li);
    saveSettings();
  };
  li.appendChild(delBtn);
  ul.appendChild(li);
  input.value = '';
  saveIgnoredList();
}

// 导入白名单
function importIgnoredList() {
  const pasted = prompt('请粘贴要导入的白名单（每行一条），以 # 开头的行为注释：');
  if (!pasted) return;
  const ul = document.getElementById('ignoredList');
  const existsSet = new Set(Array.from(ul.children).map(li => li.textContent.replace('删除','').trim()));
  pasted.split(/\r?\n/).forEach(line => {
    const entry = normalizeIgnoredEntry(line);
    if (entry && !existsSet.has(entry)) {
      const li = document.createElement('li');
      li.textContent = entry;
      const delBtn = document.createElement('button');
      delBtn.textContent = '删除';
      delBtn.className = 'delBtn';
      delBtn.onclick = function() {
        ul.removeChild(li);
        saveIgnoredList();
      };
      li.appendChild(delBtn);
      ul.appendChild(li);
      existsSet.add(entry);
    }
  });
  saveIgnoredList();
// 只保存白名单列表到 storage（不影响其他设置）
function saveIgnoredList() {
  const ignoredList = document.getElementById('ignoredList');
  const ignoredDomains = Array.from(ignoredList.children)
    .map(li => {
      // 只取 li 的第一个文本节点（即域名），不包含“删除”按钮文本
      return li.childNodes[0] ? li.childNodes[0].textContent.trim() : '';
    })
    .filter(site => site && !site.startsWith('#'));
  chrome.storage.sync.get(STORAGE_KEYS.DETECTOR_CONFIG, (data) => {
    const settings = data[STORAGE_KEYS.DETECTOR_CONFIG] || {};
    settings.ignoredDomains = ignoredDomains;
    chrome.storage.sync.set({ [STORAGE_KEYS.DETECTOR_CONFIG]: settings }, () => {
      if (chrome.runtime.lastError) {
        showMessage(`保存白名单失败: ${chrome.runtime.lastError.message}`, true);
        return;
      }
      showMessage('白名单已保存！');
      // 通知所有 tab 配置已更新
      chrome.tabs.query({}, (tabs) => {
        tabs.forEach(tab => {
          try {
            if (!tab.id) return;
            if (tab.url && !tab.url.startsWith('http')) return;
            chrome.tabs.sendMessage(tab.id, { type: 'CONFIG_UPDATED' }, (resp) => {});
          } catch (e) {}
        });
      });
    });
  });
}
}

// 导出白名单
function exportIgnoredList() {
  const ul = document.getElementById('ignoredList');
  const list = Array.from(ul.children).map(li => li.textContent.replace('删除','').trim()).filter(Boolean);
  const text = list.join('\n');
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => showMessage('白名单已复制到剪贴板'));
  } else {
    prompt('复制以下白名单：', text);
  }
}

// 重置设置（使用DEFAULT_OPTIONS）
function resetSettings() {
  if (confirm('确定要恢复默认设置吗？所有自定义设置将会丢失。')) {
    const defaultSettings = {
      enabled: false,
      detectionLevel: 'MEDIUM',
      showNotification: true,
      ignoredDomains: ['localhost', '127.0.0.1', '*.local'],
      targetMethods: ['GET', 'POST'],
      ignoreHttps: false,
      recordHistory: true,
      historyRetentionDays: 30
    };
    chrome.storage.sync.set({
      [STORAGE_KEYS.DETECTOR_CONFIG]: defaultSettings
    }, () => {
      if (chrome.runtime.lastError) {
        showMessage(`重置设置失败: ${chrome.runtime.lastError.message}`, true);
        return;
      }
      loadSettings();
      showMessage('🔄 设置已重置为默认值');
    });
  }
}