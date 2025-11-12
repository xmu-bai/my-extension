// Whitelist utilities: expose to global as WhitelistUtils for content scripts and background reuse
(function(global){
  function normalizeHost(input) {
    if (!input) return '';
    let s = String(input).trim();
    if (!s) return '';
    try {
      if (/^https?:\/\//i.test(s)) {
        const u = new URL(s);
        s = u.host || u.hostname || '';
      }
    } catch (e) {
      // keep as-is for non-URL inputs
    }
    s = s.replace(/\/+$/, '').toLowerCase();
    return s;
  }

  function matchHostByRule(host, rule) {
    if (!host || !rule) return false;
    const h = host.toLowerCase();
    const r = rule.toLowerCase();
    if (r.includes('*')) {
      const regexStr = '^' + r.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$';
      try { return new RegExp(regexStr).test(h); } catch { return false; }
    }
    // 如果规则包含端口，要求精确匹配
    if (r.includes(':')) return h === r;
    // 否则允许后缀匹配，example.com 同样匹配 www.example.com
    return h === r || h.endsWith('.' + r);
  }

  function isWhitelisted(urlOrHost, rules) {
    if (!rules || !Array.isArray(rules) || rules.length === 0) return false;
    let host = urlOrHost;
    try {
      if (/^https?:\/\//i.test(urlOrHost)) {
        const u = new URL(urlOrHost);
        host = u.host || u.hostname || '';
      }
    } catch {
      // keep input as host
    }
    host = normalizeHost(host);
    return rules.some(r => matchHostByRule(host, normalizeHost(r)));
  }

  function mergeWhitelist(existing = [], incoming = []) {
    const set = new Set();
    [...existing, ...incoming].forEach(item => {
      const n = normalizeHost(item);
      if (n) set.add(n);
    });
    return Array.from(set);
  }

  global.WhitelistUtils = { normalizeHost, matchHostByRule, isWhitelisted, mergeWhitelist };
})(typeof globalThis !== 'undefined' ? globalThis : window);
