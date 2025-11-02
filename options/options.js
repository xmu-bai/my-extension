import { STORAGE_KEYS } from '../config/constants.js';

document.addEventListener('DOMContentLoaded', loadSettings);
document.getElementById('saveBtn').addEventListener('click', saveSettings);
document.getElementById('resetBtn').addEventListener('click', resetSettings);

// 显示提示信息（保持不变）
function showMessage(text, isError = false) { /* ... */ }

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
    document.getElementById('sensitivity').value = settings.detectionLevel.toLowerCase();
    document.getElementById('ignoredSites').value = settings.ignoredDomains.join('\n');
  });
}

// 保存设置（对齐配置接口）
function saveSettings() {
  const ignoredDomains = document.getElementById('ignoredSites').value.split('\n')
    .map(site => site.trim())
    .filter(site => site && !site.startsWith('#'))
    .filter((site, index, self) => self.indexOf(site) === index);

  const settings = {
    enabled: document.getElementById('autoScan').checked,
    detectionLevel: document.getElementById('sensitivity').value.toUpperCase(),
    showNotification: document.getElementById('notifications').checked,
    ignoredDomains: ignoredDomains,
    // 补充默认配置中其他必填字段
    targetMethods: ['GET', 'POST'],
    ignoreHttps: false,
    recordHistory: true,
    historyRetentionDays: 30
  };

  chrome.storage.sync.set({
    [STORAGE_KEYS.DETECTOR_CONFIG]: settings
  }, () => {
    if (chrome.runtime.lastError) {
      showMessage(`保存设置失败: ${chrome.runtime.lastError.message}`, true);
      return;
    }
    showMessage('✓ 设置已保存！');
    // 通知content-script配置更新
    chrome.tabs.query({}, tabs => {
      tabs.forEach(tab => {
        chrome.tabs.sendMessage(tab.id, { type: 'CONFIG_UPDATED' });
      });
    });
  });
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