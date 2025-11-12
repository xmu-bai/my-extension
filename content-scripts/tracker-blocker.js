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
      if (config.trackerBlocking.enabled) {
        initializeTrackerBlocking();
      }
    }
  });

  // 初始化追踪阻止
  function initializeTrackerBlocking() {
    // 阻止Canvas指纹识别
    if (config.trackerBlocking.canvasProtection) {
      protectCanvasFingerprinting();
    }

    // 阻止WebRTC泄漏
    if (config.trackerBlocking.webrtcProtection) {
      protectWebRTCLeak();
    }

    // 阻止第三方Cookie
    if (config.trackerBlocking.thirdPartyCookies) {
      protectThirdPartyCookies();
    }

    // 移除追踪脚本
    removeTrackingScripts();

    console.log('隐私追踪阻止已启动');
  }

  // 保护Canvas指纹识别
  function protectCanvasFingerprinting() {
    const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
    const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;

    // 干扰Canvas指纹
    HTMLCanvasElement.prototype.toDataURL = function() {
      const context = this.getContext('2d');
      if (context) {
        // 添加随机噪声
        const imageData = context.getImageData(0, 0, this.width, this.height);
        for (let i = 0; i < imageData.data.length; i += 4) {
          imageData.data[i] += Math.floor(Math.random() * 3) - 1;
        }
        context.putImageData(imageData, 0, 0);
      }
      return originalToDataURL.apply(this, arguments);
    };

    CanvasRenderingContext2D.prototype.getImageData = function() {
      const imageData = originalGetImageData.apply(this, arguments);
      // 添加轻微噪声
      for (let i = 0; i < imageData.data.length; i += 4) {
        imageData.data[i] += Math.floor(Math.random() * 2) - 1;
      }
      return imageData;
    };
  }

  // 保护WebRTC IP泄漏
  function protectWebRTCLeak() {
    // 拦截RTCPeerConnection
    if (window.RTCPeerConnection) {
      const OriginalRTCPeerConnection = window.RTCPeerConnection;
      window.RTCPeerConnection = function(...args) {
        const pc = new OriginalRTCPeerConnection(...args);
        
        // 拦截createDataChannel
        const originalCreateDataChannel = pc.createDataChannel;
        pc.createDataChannel = function(...args) {
          console.warn('WebRTC createDataChannel调用被阻止');
          return null;
        };
        
        return pc;
      };
      
      window.RTCPeerConnection.prototype = OriginalRTCPeerConnection.prototype;
    }
  }

  // 保护第三方Cookie
  function protectThirdPartyCookies() {
    const originalCookieDescriptor = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    if (!originalCookieDescriptor || !originalCookieDescriptor.set) return;
    Object.defineProperty(document, 'cookie', {
      set: function(value) {
        const attr = parseCookieAttributes(value);
        const siteHost = window.location.hostname;
        const siteETLD = getETLDPlusOne(siteHost);

        const cookieDomain = (attr.Domain || siteHost).replace(/^\./, '');
        const cookieETLD = getETLDPlusOne(cookieDomain);
        const cookieName = attr.Name || '';

        const isThirdParty = !!attr.Domain && cookieETLD !== siteETLD;

        const domainAllow = (config.trackerBlocking.cookieDomainAllowlist || []).some(d =>
          cookieDomain.endsWith(d)
        );
        const nameAllow = (config.trackerBlocking.cookieNameAllowlist || []).includes(cookieName);

        const isTrackerDomain = isTrackerHostname(cookieDomain);
        const trackerAllowed = (config.trackerBlocking.trackerDomainAllowlist || []).some(d =>
          cookieDomain.endsWith(d)
        );

        if (isThirdParty && isTrackerDomain && !domainAllow && !nameAllow && !trackerAllowed) {
          console.log('第三方追踪Cookie被阻止:', value);
          return;
        }
        originalCookieDescriptor.set.call(this, value);
      },
      get: originalCookieDescriptor.get,
      configurable: true
    });
  }

  function getETLDPlusOne(hostname) {
    if (!hostname) return '';
    const parts = hostname.split('.').filter(Boolean);
    if (parts.length <= 2) return hostname;
    const doubleSuffix = ['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au'];
    const lastTwo = parts.slice(-2).join('.');
    if (doubleSuffix.includes(lastTwo) && parts.length >= 3) {
      return parts.slice(-3).join('.');
    }
    return lastTwo;
  }

  function parseCookieAttributes(cookieString) {
    const result = { Name: '', Value: '' };
    try {
      const segments = cookieString.split(';').map(s => s.trim());
      const [namePair, ...attrs] = segments;
      const eqIdx = namePair.indexOf('=');
      result.Name = eqIdx >= 0 ? namePair.slice(0, eqIdx) : namePair;
      result.Value = eqIdx >= 0 ? namePair.slice(eqIdx + 1) : '';
      attrs.forEach(seg => {
        const idx = seg.indexOf('=');
        if (idx > 0) {
          const k = seg.slice(0, idx);
          const v = seg.slice(idx + 1);
          result[k] = v;
        } else {
          result[seg] = true;
        }
      });
    } catch (e) {}
    return result;
  }

  function isTrackerHostname(hostname) {
    const patterns = [
      /google-analytics\.com/i,
      /googletagmanager\.com/i,
      /facebook\.net/i,
      /doubleclick\.net/i,
      /scorecardresearch\.com/i,
      /adservice\.google(\.com)?/i,
      /analytics\.twitter\.com/i
    ];
    return patterns.some(p => p.test(hostname));
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
      const src = script.src;
      if (trackingPatterns.some(pattern => pattern.test(src))) {
        blockTracker(src);
        script.remove();
      }
    });

    // 监控新添加的脚本
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.tagName === 'SCRIPT' && node.src) {
            const src = node.src;
            if (trackingPatterns.some(pattern => pattern.test(src))) {
              blockTracker(src);
              node.remove();
            }
          }
        });
      });
    });

    observer.observe(document, {
      childList: true,
      subtree: true
    });
  }

  // 阻止追踪器
  function blockTracker(url) {
    try {
      const domain = new URL(url).hostname;
      if (!blockedDomains.has(domain)) {
        blockedDomains.add(domain);
        blockedTrackers++;
        
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

