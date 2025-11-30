// 隐私追踪阻止内容脚本 - 阻止追踪器和保护隐私

(function() {
  'use strict';

  let config = null;
  let blockedTrackers = 0;
  const blockedDomains = new Set();

  // 获取配置
  chrome.runtime.sendMessage({ action: 'get_config' }, (response) => {
    if (response && response.config) {
      config = response.config;
      if (config.trackerBlocking && config.trackerBlocking.enabled) {
        initializeTrackerBlocking();
      }
    }
  });

  // 初始化追踪阻止
  function initializeTrackerBlocking() {
    try {
      if (config.trackerBlocking && config.trackerBlocking.canvasProtection) {
        protectCanvasFingerprinting();
      }

      protectWebRTCLeak();
      protectThirdPartyCookies();
      removeTrackingScripts();

      // 注入网络拦截器（合并内置 blocklist 与 fallback_blocklist）
      injectNetworkInterceptor();
    } catch (e) {
      console.warn('initializeTrackerBlocking error', e);
    }
  }

  // 保护 Canvas（简单包装，避免抛出）
  function protectCanvasFingerprinting() {
    try {
      const proto = HTMLCanvasElement && HTMLCanvasElement.prototype;
      if (!proto) return;
      const _toDataURL = proto.toDataURL;
      if (typeof _toDataURL === 'function') {
        proto.toDataURL = function() {
          try {
            return _toDataURL.apply(this, arguments);
          } catch (e) {
            return '';
          }
        };
      }
      const _toBlob = proto.toBlob;
      if (typeof _toBlob === 'function') {
        proto.toBlob = function() {
          try {
            return _toBlob.apply(this, arguments);
          } catch (e) {
            if (arguments && typeof arguments[arguments.length - 1] === 'function') {
              try { arguments[arguments.length - 1](null); } catch (e) {}
            }
          }
        };
      }
    } catch (e) {
      // ignore
    }
  }

  // 保护 WebRTC（占位，不做破坏性改动）
  function protectWebRTCLeak() {
    try {
      // 目前作为最小侵入处理，仅记录
      if (window.RTCPeerConnection) {
        // 不主动修改，为兼容性保守处理
      }
    } catch (e) {}
  }

  // 尝试阻止第三方Cookie写入（简单策略）
  function protectThirdPartyCookies() {
    try {
      const docProto = Document.prototype;
      const original = Object.getOwnPropertyDescriptor(docProto, 'cookie');
      if (!original || !original.configurable) return;

      Object.defineProperty(docProto, 'cookie', {
        configurable: true,
        enumerable: true,
        get: function() {
          try {
            return original.get.call(this);
          } catch (e) {
            return '';
          }
        },
        set: function(val) {
          try {
            if (isThirdPartyCookie(val)) {
              // 阻止第三方 cookie 写入
              console.info('Blocked third-party cookie set attempt:', val);
              return;
            }
          } catch (e) {}
          return original.set.call(this, val);
        }
      });
    } catch (e) {
      // ignore
    }
  }

  // 简单的第三方Cookie检测（关键字匹配）
  function isThirdPartyCookie(cookieString) {
    try {
      const trackingKeywords = ['track', 'analytics', 'ad', 'pixel'];
      return trackingKeywords.some(keyword => cookieString.toLowerCase().includes(keyword));
    } catch (e) {
      return false;
    }
  }

  // 移除追踪脚本
  function removeTrackingScripts() {
    const trackingPatterns = [
      /google-analytics\.com/i,
      /googletagmanager\.com/i,
      /facebook\.net/i,
      /doubleclick\.net/i,
      /scorecardresearch\.com/i
    ];

    // 移除现有脚本
    document.querySelectorAll('script[src]').forEach(script => {
      try {
        const src = script.src;
        if (trackingPatterns.some(pattern => pattern.test(src))) {
          blockTracker(src);
          script.remove();
        }
      } catch (e) {}
    });

    // 监控新添加的脚本
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          try {
            if (node.tagName === 'SCRIPT' && node.src) {
              const src = node.src;
              if (trackingPatterns.some(pattern => pattern.test(src))) {
                blockTracker(src);
                node.remove();
              }
            }
          } catch (e) {}
        });
      });
    });

    observer.observe(document, {
      childList: true,
      subtree: true
    });
  }

  // 在页面上下文注入脚本以覆盖 fetch/XHR/sendBeacon
  function injectNetworkInterceptor() {
    try {
      const builtinBlocklist = [
        'google-analytics.com',
        'googletagmanager.com',
        'facebook.com',
        'doubleclick.net',
        'scorecardresearch.com',
        'adservice.google',
        'adservice.google.com',
        'ads.facebook.com',
        'analytics.twitter.com'
      ];

      chrome.storage.local.get(['fallback_blocklist'], (res) => {
        try {
          const fallback = Array.isArray(res && res.fallback_blocklist) ? res.fallback_blocklist : [];
          const merged = Array.from(new Set(builtinBlocklist.concat(fallback)));

          const injectedCode = `(() => {
            const BLOCKLIST = ${JSON.stringify(merged)};

            function isBlockedUrl(url) {
              try {
                if (!url) return false;
                let hostname = '';
                try {
                  const resolved = new URL(url, location.href);
                  hostname = resolved.hostname || '';
                } catch (e) {
                  hostname = String(url || '');
                }
                hostname = hostname.toLowerCase();
                return BLOCKLIST.some(domain => hostname.indexOf(domain.toLowerCase()) !== -1 || hostname === domain.toLowerCase());
              } catch (e) { return false; }
            }

            const _fetch = window.fetch;
            if (_fetch) {
              window.fetch = function(input, init) {
                try {
                  const url = (typeof input === 'string') ? input : (input && input.url) || '';
                  if (isBlockedUrl(url)) {
                    console.warn('fetch to tracker blocked by extension (injected):', url);
                    return Promise.reject(new Error('Blocked by extension'));
                  }
                } catch (e) {}
                return _fetch.apply(this, arguments);
              };
            }

            const _open = window.XMLHttpRequest && window.XMLHttpRequest.prototype.open;
            if (_open) {
              window.XMLHttpRequest.prototype.open = function(method, url) {
                try {
                  if (isBlockedUrl(url)) {
                    console.warn('XHR to tracker blocked by extension (injected):', url);
                    this._blocked_by_extension = true;
                  }
                } catch (e) {}
                return _open.apply(this, arguments);
              };
              const _send = window.XMLHttpRequest.prototype.send;
              if (_send) {
                window.XMLHttpRequest.prototype.send = function() {
                  if (this._blocked_by_extension) {
                    try {
                      this._blocked_by_extension = false;
                      const evt = new Event('error');
                      this.dispatchEvent(evt);
                    } catch (e) {}
                    return;
                  }
                  return _send.apply(this, arguments);
                };
              }
            }

            if (navigator && navigator.sendBeacon) {
              try {
                const _sendBeacon = navigator.sendBeacon.bind(navigator);
                navigator.sendBeacon = function(url, data) {
                  try {
                    if (isBlockedUrl(url)) {
                      console.warn('sendBeacon to tracker blocked by extension (injected):', url);
                      return false;
                    }
                  } catch (e) { console.error('sendBeacon override error', e); }
                  return _sendBeacon(url, data);
                };
              } catch (e) {}
            }

            try { window.__extensionNetworkInterceptor = { isBlockedUrl }; } catch (e) {}
          })();`;

          const script = document.createElement('script');
          script.textContent = injectedCode;
          (document.documentElement || document.head || document.body || document).appendChild(script);
          script.remove();
        } catch (e) {
          console.warn('注入网络拦截器失败（构建注入代码）:', e);
        }
      });
    } catch (e) {
      console.warn('注入网络拦截器失败:', e);
    }
  }

  // 阻止追踪器
  function blockTracker(url) {
    try {
      const domain = new URL(url).hostname;
      if (!blockedDomains.has(domain)) {
        blockedDomains.add(domain);
        blockedTrackers++;
        if (window.learningModeReporter && typeof window.learningModeReporter.record === 'function') {
          window.learningModeReporter.record(domain);
        }

        // 向background报告
        chrome.runtime.sendMessage({
          action: 'tracker_blocked',
          url: url,
          domain: domain
        });

        console.log('追踪器已阻止:', domain);
      }
    } catch (e) {
      console.error('追踪器阻止错误:', e);
    }
  }

  // 获取已阻止的追踪器数量
  function getBlockedCount() {
    return blockedTrackers;
  }

  // 监听来自popup的消息
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'get_tracker_count') {
      sendResponse({ count: blockedTrackers });
    }
    return true;
  });

  // 暴露给popup使用
  window.trackerBlocker = {
    getBlockedCount: getBlockedCount
  };

})();

