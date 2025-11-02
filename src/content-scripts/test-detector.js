/**
 * 测试页面XSS检测器
 * 专门用于检测extension://协议的测试页面
 */
class TestPageDetector {
  constructor() {
    this.detectedPayloads = [];
    // 检查是否是extension协议的测试页面
    const url = window.location.href;
    this.isTestPage = (url.startsWith('chrome-extension://') || url.startsWith('moz-extension://')) 
                     && url.includes('/test/');
    this.init();
  }

  init() {
    if (!this.isTestPage) {
      // 不是测试页面，直接返回，不执行任何操作
      return;
    }

    console.log('[TestPageDetector] 测试页面检测器已启动');
    
    // 监听DOM变化，实时检测XSS载荷
    this.observeDOM();
    
    // 检测当前页面中的XSS
    this.scanCurrentPage();
  }

  /**
   * 扫描当前页面
   */
  scanCurrentPage() {
    setTimeout(() => {
      this.scanDOM();
      this.scanURL();
    }, 1000); // 延迟1秒让页面完全加载
  }

  /**
   * 扫描DOM中的XSS载荷
   */
  scanDOM() {
    const suspiciousPatterns = [
      /<script/i,
      /on\w+\s*=/i,
      /javascript:/i,
      /<iframe/i,
      /<img[^>]*onerror/i,
      /<svg[^>]*onload/i
    ];

    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT,
      null
    );

    let node;
    while (node = walker.nextNode()) {
      // 检查文本节点
      if (node.nodeType === Node.TEXT_NODE && node.textContent) {
        for (const pattern of suspiciousPatterns) {
          if (pattern.test(node.textContent)) {
            this.reportVulnerability({
              type: 'DOM Injection',
              payload: node.textContent.substring(0, 100),
              element: 'TEXT_NODE'
            });
          }
        }
      }

      // 检查元素属性
      if (node.nodeType === Node.ELEMENT_NODE && node.attributes) {
        for (const attr of node.attributes) {
          for (const pattern of suspiciousPatterns) {
            if (pattern.test(attr.value)) {
              this.reportVulnerability({
                type: 'Attribute Injection',
                payload: attr.value.substring(0, 100),
                element: `${node.tagName}[${attr.name}]`
              });
            }
          }
        }

        // 检查innerHTML
        if (node.innerHTML) {
          for (const pattern of suspiciousPatterns) {
            if (pattern.test(node.innerHTML)) {
              this.reportVulnerability({
                type: 'innerHTML Injection',
                payload: node.innerHTML.substring(0, 200),
                element: node.tagName || 'UNKNOWN'
              });
            }
          }
        }
      }
    }
  }

  /**
   * 扫描URL参数
   */
  scanURL() {
    const url = new URL(window.location.href);
    const params = new URLSearchParams(url.search);

    for (const [key, value] of params) {
      const suspiciousPatterns = [
        /<script/i,
        /on\w+\s*=/i,
        /javascript:/i,
        /<iframe/i,
        /<img[^>]*onerror/i
      ];

      for (const pattern of suspiciousPatterns) {
        if (pattern.test(value)) {
          this.reportVulnerability({
            type: 'URL Parameter Reflection',
            payload: decodeURIComponent(value),
            element: `URL param: ${key}`,
            parameter: key
          });
        }
      }
    }

    // 检查hash
    if (url.hash) {
      const hashValue = decodeURIComponent(url.hash.substring(1));
      const suspiciousPatterns = [/<script/i, /on\w+\s*=/i, /javascript:/i];

      for (const pattern of suspiciousPatterns) {
        if (pattern.test(hashValue)) {
          this.reportVulnerability({
            type: 'Hash Reflection',
            payload: hashValue.substring(0, 100),
            element: 'location.hash'
          });
        }
      }
    }
  }

  /**
   * 观察DOM变化
   */
  observeDOM() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.addedNodes.length > 0) {
          // 检查新增的节点
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              this.checkNewNode(node);
            }
          });
        }
      });
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeOldValue: false,
      characterData: true
    });
  }

  /**
   * 检查新节点
   */
  checkNewNode(node) {
    const suspiciousPatterns = [
      /<script/i,
      /on\w+\s*=/i,
      /javascript:/i,
      /<iframe/i,
      /<img[^>]*onerror/i,
      /<svg[^>]*onload/i
    ];

    // 检查innerHTML
    if (node.innerHTML) {
      for (const pattern of suspiciousPatterns) {
        if (pattern.test(node.innerHTML)) {
          this.reportVulnerability({
            type: 'Dynamic DOM Injection',
            payload: node.innerHTML.substring(0, 200),
            element: node.tagName || 'UNKNOWN'
          });
        }
      }
    }

    // 检查属性
    if (node.attributes) {
      for (const attr of node.attributes) {
        for (const pattern of suspiciousPatterns) {
          if (pattern.test(attr.value)) {
            this.reportVulnerability({
              type: 'Dynamic Attribute Injection',
              payload: attr.value.substring(0, 100),
              element: `${node.tagName}[${attr.name}]`
            });
          }
        }
      }
    }
  }

  /**
   * 报告漏洞
   */
  reportVulnerability(info) {
    const vulnerability = {
      vulnerability: 'XSS',
      url: window.location.href,
      parameter: info.parameter,
      payload: info.payload,
      severity: 'high',
      description: `发现XSS漏洞: ${info.type}`,
      timestamp: Date.now(),
      element: info.element,
      type: info.type
    };

    // 发送到background
    chrome.runtime.sendMessage({
      action: 'reportTestXssVulnerability',
      vulnerability: vulnerability
    }).catch(err => console.log('无法发送消息:', err));

    // 防止重复报告
    const key = `${info.type}-${info.payload.substring(0, 50)}`;
    if (!this.detectedPayloads.includes(key)) {
      this.detectedPayloads.push(key);
      
      console.log('[TestPageDetector] 发现XSS漏洞:', vulnerability);
    }
  }
}

// 启动检测器
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    new TestPageDetector();
  });
} else {
  new TestPageDetector();
}
