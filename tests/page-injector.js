(function(){
  'use strict';

  const BLOCKLIST = [
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
    } catch (e) {
      return false;
    }
  }

  console.info('Page injector: network interceptor installing. Blocklist length=', BLOCKLIST.length);

  // Override fetch
  try {
    const _fetch = window.fetch;
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
  } catch (e) {
    console.warn('Page injector: failed to override fetch', e);
  }

  // Override XHR
  try {
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
  } catch (e) {
    console.warn('Page injector: failed to override XHR', e);
  }

  // Override sendBeacon
  try {
    if (navigator && navigator.sendBeacon) {
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
      console.info('Page injector: sendBeacon overridden');
    }
  } catch (e) {
    console.warn('Page injector: failed to override sendBeacon', e);
  }

  // Expose a small API for debugging
  window.__extensionNetworkInterceptor = {
    isBlockedUrl: isBlockedUrl,
    blocklist: BLOCKLIST.slice()
  };
})();
