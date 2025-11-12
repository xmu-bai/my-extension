// 学习模式内容脚本 - 统计第三方域出现的站点
(function () {
  'use strict';

  const firstPartyHost = window.location.hostname || '';
  const pageThirdParties = new Set();
  const pendingQueue = new Set();
  let learningEnabled = false;
  let learningStateResolved = false;

  function normalizeHost(hostname) {
    if (!hostname) {
      return null;
    }
    return hostname.toLowerCase();
  }

  function isThirdParty(hostname) {
    const host = normalizeHost(hostname);
    if (!host || !firstPartyHost) {
      return false;
    }
    if (host === firstPartyHost) {
      return false;
    }
    return !host.endsWith(`.${firstPartyHost}`);
  }

  function queueRecord(thirdParty) {
    if (!thirdParty) {
      return;
    }

    const host = normalizeHost(thirdParty);
    if (!host) {
      return;
    }

    if (!learningStateResolved) {
      pendingQueue.add(host);
      return;
    }

    if (!learningEnabled) {
      return;
    }

    if (pageThirdParties.has(host)) {
      return;
    }

    pageThirdParties.add(host);
    chrome.runtime.sendMessage({
      action: 'learning_record',
      firstParty: firstPartyHost,
      thirdParty: host
    }, () => {
      void chrome.runtime.lastError;
    });
  }

  function flushPending() {
    if (!learningEnabled || pendingQueue.size === 0) {
      pendingQueue.clear();
      return;
    }
    pendingQueue.forEach((host) => {
      if (!pageThirdParties.has(host)) {
        pageThirdParties.add(host);
        chrome.runtime.sendMessage({
          action: 'learning_record',
          firstParty: firstPartyHost,
          thirdParty: host
        }, () => {
          void chrome.runtime.lastError;
        });
      }
    });
    pendingQueue.clear();
  }

  function handlePotentialThirdParty(urlOrHost) {
    if (!urlOrHost) {
      return;
    }

    let host = null;
    if (typeof urlOrHost === 'string') {
      try {
        const resolved = new URL(urlOrHost, window.location.href);
        host = resolved.hostname;
      } catch (e) {
        host = urlOrHost;
      }
    } else if (urlOrHost instanceof URL) {
      host = urlOrHost.hostname;
    } else if (urlOrHost && typeof urlOrHost === 'object') {
      if (urlOrHost.url) {
        try {
          host = new URL(urlOrHost.url, window.location.href).hostname;
        } catch (e) {
          host = normalizeHost(urlOrHost.url);
        }
      } else if (urlOrHost.href) {
        try {
          host = new URL(urlOrHost.href, window.location.href).hostname;
        } catch (e) {
          host = normalizeHost(urlOrHost.href);
        }
      }
    }

    if (!host || !isThirdParty(host)) {
      return;
    }

    queueRecord(host);
  }

  function initNetworkHooks() {
    if (typeof window.fetch === 'function') {
      const originalFetch = window.fetch;
      window.fetch = function (...args) {
        if (args && args[0]) {
          handlePotentialThirdParty(args[0]);
        }
        return originalFetch.apply(this, args);
      };
    }

    if (typeof window.XMLHttpRequest === 'function') {
      const OriginalXHR = window.XMLHttpRequest;
      function WrappedXHR() {
        const xhrInstance = new OriginalXHR();
        const originalOpen = xhrInstance.open;
        xhrInstance.open = function (method, url, ...rest) {
          handlePotentialThirdParty(url);
          return originalOpen.call(this, method, url, ...rest);
        };
        return xhrInstance;
      }
      WrappedXHR.prototype = OriginalXHR.prototype;
      window.XMLHttpRequest = WrappedXHR;
    }
  }

  function requestLearningState() {
    chrome.runtime.sendMessage({ action: 'get_learning_state' }, (response) => {
      learningStateResolved = true;
      learningEnabled = Boolean(response && response.enabled);
      if (learningEnabled) {
        flushPending();
      } else {
        pendingQueue.clear();
        pageThirdParties.clear();
      }
    });
  }

  chrome.runtime.onMessage.addListener((request) => {
    if (request && request.action === 'learning_mode_updated') {
      learningStateResolved = true;
      learningEnabled = Boolean(request.enabled);
      if (learningEnabled) {
        flushPending();
      } else {
        pendingQueue.clear();
        pageThirdParties.clear();
      }
    }
  });

  window.learningModeReporter = window.learningModeReporter || {};
  window.learningModeReporter.record = function (thirdPartyHost) {
    handlePotentialThirdParty(thirdPartyHost);
  };
  window.learningModeReporter.recordFromUrl = function (url) {
    handlePotentialThirdParty(url);
  };

  initNetworkHooks();
  requestLearningState();
})();


