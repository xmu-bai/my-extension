// XSS防护内容脚本 - 检测和阻止潜在的XSS攻击

(function() {
  'use strict';

  let config = null;
  let blockedCount = 0;

  // 获取配置
  chrome.runtime.sendMessage({ action: 'get_config' }, (response) => {
    if (response && response.config) {
      config = response.config;
      if (config.xssProtection.enabled) {
        initializeXSSProtection();
      }
    }
  });

  // 初始化XSS防护
  function initializeXSSProtection() {
    // 拦截危险的DOM操作
    interceptDangerousDOMOperations();
    
    // 拦截eval函数
    interceptEval();
    
    // 监控innerHTML操作
    monitorInnerHTML();
    
    // 监控动态脚本插入
    monitorScriptInsertion();
    
    console.log('XSS防护已启动');
  }

  // 拦截危险的DOM操作
  function interceptDangerousDOMOperations() {
    const originalCreateElement = document.createElement;
    document.createElement = function(tagName, options) {
      const element = originalCreateElement.call(this, tagName, options);
      
      // 拦截innerHTML设置
      if (element.innerHTML !== undefined) {
        const descriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
        if (descriptor && descriptor.set) {
          Object.defineProperty(element, 'innerHTML', {
            set: function(value) {
              if (isDangerousContent(value)) {
                handleXSSThreat('innerHTML', value, this);
                return; // 阻止设置
              }
              descriptor.set.call(this, value);
            },
            get: descriptor.get,
            configurable: true
          });
        }
      }
      
      return element;
    };
  }

  // 监控innerHTML操作
  function monitorInnerHTML() {
    const elements = document.querySelectorAll('*');
    elements.forEach(element => {
      if (element.innerHTML) {
        const originalValue = element.innerHTML;
        Object.defineProperty(element, 'innerHTML', {
          set: function(value) {
            if (isDangerousContent(value)) {
              handleXSSThreat('innerHTML', value, this);
              return;
            }
            // 使用原生方法设置
            Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML').set.call(this, value);
          },
          get: function() {
            return originalValue;
          },
          configurable: true
        });
      }
    });
  }

  // 拦截eval函数
  function interceptEval() {
    if (config.xssProtection.level === 'strict') {
      window.eval = function() {
        handleXSSThreat('eval', 'eval()调用被阻止', null);
        throw new Error('eval()已被安全插件阻止');
      };
    }
  }

  // 监控脚本插入
  function monitorScriptInsertion() {
    const originalAppendChild = Node.prototype.appendChild;
    Node.prototype.appendChild = function(child) {
      if (child.tagName === 'SCRIPT') {
        const scriptContent = child.textContent || child.innerHTML || '';
        if (isDangerousContent(scriptContent)) {
          handleXSSThreat('script_insertion', scriptContent, this);
          return child; // 返回但不真正插入
        }
      }
      return originalAppendChild.call(this, child);
    };
  }

  // 检测危险内容
  function isDangerousContent(content) {
    if (!content || typeof content !== 'string') {
      return false;
    }

    // XSS攻击模式检测
    const xssPatterns = [
      /<script[^>]*>/i,
      /javascript:/i,
      /onerror\s*=/i,
      /onclick\s*=/i,
      /onload\s*=/i,
      /onmouseover\s*=/i,
      /<iframe[^>]*>/i,
      /<object[^>]*>/i,
      /<embed[^>]*>/i,
      /expression\s*\(/i,  // CSS expression
      /vbscript:/i
    ];

    return xssPatterns.some(pattern => pattern.test(content));
  }

  // 处理XSS威胁
  function handleXSSThreat(type, content, element) {
    blockedCount++;
    
    console.warn('XSS威胁已检测并阻止:', {
      type: type,
      content: content.substring(0, 100), // 只记录前100个字符
      url: window.location.href,
      timestamp: new Date().toISOString()
    });

    // 向background报告
    chrome.runtime.sendMessage({
      action: 'xss_detected',
      type: type,
      url: window.location.href,
      timestamp: Date.now()
    });

    // 如果配置要求显示确认对话框
    if (config.xssProtection.showConfirm) {
      const userConfirm = confirm(
        '检测到潜在的XSS攻击尝试！\n\n' +
        '操作类型: ' + type + '\n' +
        '是否允许此操作？'
      );
      
      if (!userConfirm) {
        // 阻止操作
        return false;
      }
    } else if (config.xssProtection.autoBlock) {
      // 自动阻止
      showXSSBlockedNotification(type);
      return false;
    }

    return true;
  }

  // 显示XSS阻止通知
  function showXSSBlockedNotification(type) {
    // 创建通知元素
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: #4CAF50;
      color: white;
      padding: 15px 20px;
      border-radius: 5px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.2);
      z-index: 999999;
      font-family: Arial, sans-serif;
      font-size: 14px;
      max-width: 300px;
    `;
    notification.innerHTML = `
      <div style="display: flex; align-items: center; gap: 10px;">
        <span style="font-size: 20px;">🛡️</span>
        <div>
          <strong>XSS攻击已阻止</strong><br>
          <small>已阻止 ${blockedCount} 次潜在攻击</small>
        </div>
      </div>
    `;
    
    document.body.appendChild(notification);
    
    // 3秒后自动移除
    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification);
      }
    }, 3000);
  }

  // 监控用户输入插入DOM（MutationObserver）
  // 等待DOM加载完成后开始监控
  if (document.body) {
    startDOMObserver();
  } else {
    document.addEventListener('DOMContentLoaded', startDOMObserver);
  }

  function startDOMObserver() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === 1) { // Element node
            if (node.innerHTML && isDangerousContent(node.innerHTML)) {
              handleXSSThreat('dom_mutation', node.innerHTML, node);
              node.innerHTML = ''; // 清空危险内容
            }
          }
        });
      });
    });

    // 开始监控DOM变化
    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

})();

