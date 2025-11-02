/**
 * XSS检测器 - 测试页面专用
 * 在测试页面中直接运行，检测XSS漏洞
 */
(function() {
  'use strict';

  // 检查是否在扩展环境中
  if (!chrome || !chrome.runtime) {
    console.warn('[XSSDetector] 未在扩展环境中运行');
    return;
  }

  class TestPageXssDetector {
    constructor() {
      this.detectedPayloads = [];
      this.isTestPage = this.checkIfTestPage();
      
      if (this.isTestPage) {
        console.log('[XSSDetector] 测试页面检测器已启动');
        this.init();
      }
    }

    checkIfTestPage() {
      const url = window.location.href;
      return (url.includes('chrome-extension://') || url.includes('moz-extension://')) 
             && url.includes('/test/');
    }

    init() {
      // 等待DOM完全加载
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
          this.startDetection();
        });
      } else {
        this.startDetection();
      }
    }

    startDetection() {
      // 监听DOM变化
      this.observeDOM();
      
      // 延迟扫描，确保页面内容已加载
      setTimeout(() => {
        this.scanCurrentPage();
      }, 500);
    }

    /**
     * 扫描当前页面
     */
    scanCurrentPage() {
      this.scanDOM();
      this.scanURL();
    }

    /**
     * 扫描DOM中的XSS载荷
     */
    scanDOM() {
      if (!document.body) return;

      const suspiciousPatterns = [
        /<script[^>]*>/i,
        /on\w+\s*=/i,
        /javascript:/i,
        /<iframe[^>]*>/i,
        /<img[^>]*onerror/i,
        /<svg[^>]*onload/i,
        /<body[^>]*onload/i,
        /<input[^>]*onfocus/i
      ];

      try {
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
                  type: 'DOM Text Injection',
                  payload: node.textContent.substring(0, 100),
                  element: 'TEXT_NODE',
                  parentElement: node.parentElement ? node.parentElement.tagName : 'UNKNOWN'
                });
                break;
              }
            }
          }

          // 检查元素属性
          if (node.nodeType === Node.ELEMENT_NODE) {
            // 检查所有属性
            if (node.attributes && node.attributes.length > 0) {
              for (const attr of node.attributes) {
                if (!attr.value) continue;
                
                for (const pattern of suspiciousPatterns) {
                  if (pattern.test(attr.value)) {
                    this.reportVulnerability({
                      type: 'Attribute Injection',
                      payload: attr.value.substring(0, 100),
                      element: `${node.tagName}[${attr.name}]`,
                      parameter: attr.name
                    });
                    break;
                  }
                }
              }
            }

            // 检查innerHTML
            if (node.innerHTML && node.innerHTML.length > 0) {
              for (const pattern of suspiciousPatterns) {
                if (pattern.test(node.innerHTML)) {
                  this.reportVulnerability({
                    type: 'innerHTML Injection',
                    payload: node.innerHTML.substring(0, 200),
                    element: node.tagName || 'UNKNOWN'
                  });
                  break;
                }
              }
            }
          }
        }
      } catch (error) {
        console.error('[XSSDetector] DOM扫描错误:', error);
      }
    }

    /**
     * 扫描URL参数
     */
    scanURL() {
      try {
        const url = new URL(window.location.href);
        
        // 扫描查询参数
        const params = new URLSearchParams(url.search);
        for (const [key, value] of params) {
          if (this.isSuspicious(value)) {
            this.reportVulnerability({
              type: 'URL Parameter Reflection',
              payload: decodeURIComponent(value),
              element: `URL param: ${key}`,
              parameter: key
            });
          }
        }

        // 检查hash
        if (url.hash && url.hash.length > 1) {
          const hashValue = decodeURIComponent(url.hash.substring(1));
          if (this.isSuspicious(hashValue)) {
            this.reportVulnerability({
              type: 'Hash Reflection',
              payload: hashValue.substring(0, 100),
              element: 'location.hash'
            });
          }
        }
      } catch (error) {
        console.error('[XSSDetector] URL扫描错误:', error);
      }
    }

    /**
     * 检查值是否可疑
     */
    isSuspicious(value) {
      if (!value || typeof value !== 'string') return false;

      const suspiciousPatterns = [
        /<script[^>]*>/i,
        /<\/script>/i,
        /on\w+\s*=/i,
        /javascript:/i,
        /<iframe/i,
        /<img[^>]*onerror/i,
        /<svg[^>]*onload/i,
        /<body[^>]*onload/i,
        /alert\(/i,
        /eval\(/i,
        /document\./i,
        /window\./i
      ];

      return suspiciousPatterns.some(pattern => pattern.test(value));
    }

    /**
     * 观察DOM变化
     */
    observeDOM() {
      if (!document.body) {
        // 如果body还没加载，延迟观察
        setTimeout(() => this.observeDOM(), 100);
        return;
      }

      try {
        const observer = new MutationObserver((mutations) => {
          mutations.forEach((mutation) => {
            if (mutation.addedNodes.length > 0) {
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
      } catch (error) {
        console.error('[XSSDetector] DOM观察器错误:', error);
      }
    }

    /**
     * 检查新节点
     */
    checkNewNode(node) {
      if (!node || node.nodeType !== Node.ELEMENT_NODE) return;

      try {
        // 检查innerHTML
        if (node.innerHTML) {
          if (this.isSuspicious(node.innerHTML)) {
            this.reportVulnerability({
              type: 'Dynamic DOM Injection',
              payload: node.innerHTML.substring(0, 200),
              element: node.tagName || 'UNKNOWN'
            });
          }
        }

        // 检查属性
        if (node.attributes && node.attributes.length > 0) {
          for (const attr of node.attributes) {
            if (attr.value && this.isSuspicious(attr.value)) {
              this.reportVulnerability({
                type: 'Dynamic Attribute Injection',
                payload: attr.value.substring(0, 100),
                element: `${node.tagName || 'UNKNOWN'}[${attr.name}]`,
                parameter: attr.name
              });
            }
          }
        }
      } catch (error) {
        console.error('[XSSDetector] 新节点检查错误:', error);
      }
    }

    /**
     * 报告漏洞
     */
    reportVulnerability(info) {
      // 防止重复报告
      const key = `${info.type}-${info.payload ? info.payload.substring(0, 50) : 'unknown'}`;
      if (this.detectedPayloads.includes(key)) {
        return;
      }
      this.detectedPayloads.push(key);

      const vulnerability = {
        vulnerability: 'XSS',
        url: window.location.href,
        parameter: info.parameter || null,
        payload: info.payload || '',
        severity: 'high',
        description: `发现XSS漏洞: ${info.type}`,
        timestamp: Date.now(),
        element: info.element || 'UNKNOWN',
        type: info.type || 'Unknown'
      };

      console.log('[XSSDetector] 发现XSS漏洞:', vulnerability);

      // 发送到background
      try {
        chrome.runtime.sendMessage({
          action: 'reportTestXssVulnerability',
          vulnerability: vulnerability
        }).catch(err => {
          console.error('[XSSDetector] 发送消息失败:', err);
        });
      } catch (error) {
        console.error('[XSSDetector] 消息发送错误:', error);
      }
    }
  }

  // 立即启动检测器
  window.testXssDetector = new TestPageXssDetector();
})();

