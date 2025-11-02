// 监听来自popup的扫描请求
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'scanPage') {
    // 这里是基础扫描逻辑（实际安全处理需扩展）
    const scanResult = basicSecurityCheck();
    sendResponse({ result: scanResult });
  }
});

// 表单安全性检查
function checkFormSecurity() {
  const issues = [];
  const forms = document.querySelectorAll('form');
  const isHttps = window.location.protocol === 'https:';
  
  if (forms.length === 0) {
    return issues; // 没有表单，无需检查
  }
  
  forms.forEach((form, index) => {
    const action = form.action || form.getAttribute('action') || '';
    
    // 检查表单提交地址是否安全
    if (action) {
      // 如果是相对路径（无协议），检查当前页面协议
      if (!action.includes('://')) {
        if (!isHttps) {
          issues.push(`表单${index + 1}将在HTTP连接上提交`);
        }
      } else if (action.startsWith('http://')) {
        // 明确使用HTTP协议
        issues.push(`表单${index + 1}使用不安全的HTTP协议提交`);
      } else if (action.startsWith('//')) {
        // 协议相对URL（//example.com），继承当前协议，需检查
        if (!isHttps) {
          issues.push(`表单${index + 1}使用协议相对URL且在HTTP页面上`);
        }
      }
    } else {
      // 没有action属性，表单将提交到当前页面
      if (!isHttps) {
        issues.push(`表单${index + 1}将在HTTP连接上提交（无action属性）`);
      }
    }
    
    // 检查密码输入框
    const passwordInputs = form.querySelectorAll('input[type="password"]');
    if (passwordInputs.length > 0 && !isHttps) {
      issues.push(`表单${index + 1}在HTTP页面上包含密码输入框`);
    }
  });
  
  return issues;
}

// 基础安全检查示例（仅框架）
function basicSecurityCheck() {
  // 1. 检查是否使用HTTPS
  const isHttps = window.location.protocol === 'https:';
  // 2. 检查是否有可疑脚本（示例）
  const suspiciousScripts = document.querySelectorAll('script[src*="unknown-domain"]');
  // 3. 检查表单安全性（新增功能）
  const formIssues = checkFormSecurity();
  
  let result = [];
  if (!isHttps) result.push('非HTTPS连接');
  if (suspiciousScripts.length > 0) result.push(`发现${suspiciousScripts.length}个可疑脚本`);
  if (formIssues.length > 0) result.push(...formIssues);
  
  return result.length > 0 ? result.join('; ') : '未发现明显问题';
}

// 自动扫描（根据设置）
chrome.storage.sync.get('autoScan', (data) => {
  if (data.autoScan) {
    const issues = basicSecurityCheck();
    if (issues !== '未发现明显问题') {
      // 向background发送问题通知
      chrome.runtime.sendMessage({
        action: 'securityIssue',
        details: issues
      });
    }
  }
});

// 监听DOM变化，实时扫描新增内容
function observeDOMChanges() {
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      // 检查新增的元素
      if (mutation.addedNodes.length > 0) {
        const newIssues = basicSecurityCheck(); // 复用现有检查逻辑
        if (newIssues !== '未发现明显问题') {
          chrome.runtime.sendMessage({
            action: 'securityIssue',
            details: `动态内容发现问题: ${newIssues}`
          });
        }
      }
    });
  });

  // 监听整个文档的DOM变化
  observer.observe(document.body, {
    childList: true,
    subtree: true,
    attributes: false,
    characterData: false
  });
}

// 在页面加载时启动监听
observeDOMChanges();