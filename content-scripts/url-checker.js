// URL检测内容脚本 - 强化版（递归解码/多维匹配/白名单统一/节流监听）
(async function() {
  'use strict';

  // ==================== 工具函数 ====================
  // 0. 防抖（节流触发）
  function debounce(fn, delay = 200) {
    let timer = null;
    return function(...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), delay);
    };
  }

  // 1. 递归URL解码（处理多次编码 + HTML实体/数值实体 + \xNN + \uXXXX + \u{...}）
  function decodeURLRecursively(input, maxDepth = 5) {
    let current = String(input ?? '');
    if (!current) return '';

    const hasPercentEncoded = (s) => /%(?:[0-9A-Fa-f]{2})/.test(s);

    const decodeHtml = (s) => s
      // 常见命名实体
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#39;|&apos;/g, "'")
      // 数值实体（十六进制）&#x3C;
      .replace(/&#x([0-9a-fA-F]+);/g, (m, hex) => {
        try { return String.fromCodePoint(parseInt(hex, 16)); } catch { return m; }
      })
      // 数值实体（十进制）&#60;
      .replace(/&#([0-9]+);/g, (m, dec) => {
        try { return String.fromCodePoint(parseInt(dec, 10)); } catch { return m; }
      });

    const decodeEscapes = (s) => s
      // ES6 \u{1F600}
      .replace(/\\u\{([0-9a-fA-F]+)\}/g, (m, hex) => {
        try { return String.fromCodePoint(parseInt(hex, 16)); } catch { return m; }
      })
      // 传统 \u003c
      .replace(/\\u([0-9a-fA-F]{4})/g, (m, hex) => {
        try { return String.fromCharCode(parseInt(hex, 16)); } catch { return m; }
      })
      // \x3C
      .replace(/\\x([0-9a-fA-F]{2})/g, (m, hex) => {
        try { return String.fromCharCode(parseInt(hex, 16)); } catch { return m; }
      });

    for (let i = 0; i < maxDepth; i++) {
      const prev = current;

      // 仅当存在合法 %XX 模式时尝试 URI 解码，避免无效递归
      if (hasPercentEncoded(current)) {
        try {
          const decoded = decodeURIComponent(current);
          current = decoded;
        } catch {
          // 忽略解码错误，继续后续 HTML/转义解码
        }
      }

      // HTML 实体与数值实体
      current = decodeHtml(current);
      // JS 转义（\u / \x / \u{...}）
      current = decodeEscapes(current);

      if (current === prev) break; // 无任何变化则提前退出
    }

    return current;
  }

  // 2. 降级白名单匹配（支持 /regex/ 与 *.domain 以及完整URL）
  function fallbackIsWhitelisted(url, whitelist = []) {
    if (!Array.isArray(whitelist) || whitelist.length === 0) return false;
    let domain = '';
    try { domain = new URL(url).hostname; } catch(e) { return false; }
    return whitelist.some(item => {
      if (typeof item !== 'string' || !item.trim()) return false;
      // 以 / 正则 /
      if (item.startsWith('/') && item.endsWith('/')) {
        try { return new RegExp(item.slice(1, -1), 'i').test(url); } catch { return false; }
      }
      // 通配域名
      if (item.startsWith('*.')) {
        const base = item.slice(2).toLowerCase();
        const d = domain.toLowerCase();
        return d === base || d.endsWith('.' + base);
      }
      // 完整URL精确
      return url === item;
    });
  }

  // 2.1 白名单缓存（TTL）
  const WHITELIST_TTL_MS = 5 * 60 * 1000; // 5分钟
  const whitelistCache = new Map(); // key: host, value: { allowed: boolean, expires: number }
  function checkWhitelistWithCache(url, mergedWhitelist) {
    let host = '';
    try { host = new URL(url).host; } catch { return false; }
    const now = Date.now();
    const cached = whitelistCache.get(host);
    if (cached && cached.expires > now) return cached.allowed;
    let allowed = false;
    try {
      if (globalThis.WhitelistUtils && typeof WhitelistUtils.isWhitelisted === 'function') {
        allowed = !!WhitelistUtils.isWhitelisted(url, mergedWhitelist);
      } else {
        allowed = !!fallbackIsWhitelisted(url, mergedWhitelist);
      }
    } catch {}
    whitelistCache.set(host, { allowed, expires: now + WHITELIST_TTL_MS });
    return allowed;
  }

  // 3. 覆盖 history 以捕获 pushState/replaceState
  function hookHistory() {
    const originalPushState = history.pushState;
    const originalReplaceState = history.replaceState;
    history.pushState = function(...args) {
      const result = originalPushState.apply(this, args);
      window.dispatchEvent(new CustomEvent('urlChange'));
      return result;
    };
    history.replaceState = function(...args) {
      const result = originalReplaceState.apply(this, args);
      window.dispatchEvent(new CustomEvent('urlChange'));
      return result;
    };
  }

  // 4. 风险检测核心
  function detectRisks(url, config) {
    const settings = config.urlDetection;
    const decodedUrl = decodeURLRecursively(url);
    let parsedUrl;
    try { parsedUrl = new URL(url); } catch { return { risks: [], decodedUrl }; }
    const risks = [];

    // 检测1：禁止协议
    if (settings.checkProtocol) {
      const protocol = parsedUrl.protocol; // 形如 'http:' 'javascript:'
      if (settings.blockedProtocols.some(p => protocol.toLowerCase() === p.toLowerCase())) {
        risks.push({ type: 'protocol', pattern: protocol, message: `禁止的协议: ${protocol}` });
      }
    }

    // 检测2：路径遍历
    if (settings.checkPathTraversal) {
      const pathTraversalPatterns = [/\.\.\//gi, /\.\.\\/gi, /%2e%2e%2f/gi, /%2e%2e%5c/gi];
      pathTraversalPatterns.forEach(pattern => {
        if (pattern.test(decodedUrl)) {
          risks.push({ type: 'pathTraversal', pattern: pattern.source, message: '检测到路径遍历特征' });
        }
      });
    }


    // 检测4：域名混淆（钓鱼）
    if (settings.checkPhishing) {
      // a) @ 符号（可能隐藏真实 host）
      if (parsedUrl.href.includes('@') && !parsedUrl.username && !parsedUrl.password) {
        risks.push({ type: 'phishing', pattern: '@', message: '检测到域名混淆特征（@符号）' });
      }
      // b) 多余的 // 出现在协议分隔之后
      const idx = parsedUrl.href.indexOf('://');
      if (idx > -1) {
        const after = parsedUrl.href.slice(idx + 3);
        if (after.includes('//')) {
          risks.push({ type: 'phishing', pattern: '//', message: '检测到域名混淆特征（多斜杠）' });
        }
      }
    }

    return { risks, decodedUrl };
  }

  // 5. 响应动作与上报
  function handleRisks(risks, url, decodedUrl, config) {
    if (!risks || risks.length === 0) return;
    const action = config.urlDetection.action || 'report';

    const reportData = {
      action: 'suspicious_url',
      url,
      decodedUrl,
      risks,
      pageTitle: document.title,
      referrer: document.referrer,
      timestamp: Date.now()
    };
    try { globalThis.Actions?.reportRisk?.(reportData); } catch {}

    switch (action) {
      case 'block':
        try { globalThis.Actions?.blockWithWarning?.({ url, risks }); } catch {}
        break;
      case 'warn':
        try { globalThis.Actions?.warnUser?.({ url, risks }); } catch {}
        break;
      case 'report':
      default:
        console.warn('[URL安全检测] 发现风险：', reportData);
        break;
    }
  }

  // ==================== 配置读取与白名单 ====================
  function getConfig() {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage({ action: 'get_config' }, (response) => {
          resolve((response && response.config) ? response.config : null);
        });
      } catch (e) { resolve(null); }
    });
  }

  const rawConfig = await getConfig();
  if (!rawConfig) return;

  // 默认开关与规则，兼容当前 options 配置
  const defaultUrlDetection = {
    enabled: true,
    action: 'report', // report | warn | block
    checkProtocol: true,
    checkPathTraversal: true,
  checkXSS: false, // 按需求禁用 XSS 检测
    checkPhishing: true,
    blockedProtocols: ['javascript:', 'data:', 'vbscript:'],
    suspiciousPatterns: [],
    whitelist: [],
    // 新增：采集与覆盖面开关
    scanElements: true,
    scanFetch: true,
    scanXHR: true,
    scanWebSocket: true,
    scanWindowOpen: true,
    scanMetaRefresh: true,
    scanCssUrls: false, // 解析 CSS url() 开销较大，默认关闭
    dedupeTtlMs: 120000 // 2 分钟内对相同来源-URL 去重
  };
  let config = {
    ...rawConfig,
    urlDetection: { ...defaultUrlDetection, ...(rawConfig.urlDetection || {}) }
  };
  if (!config.urlDetection.enabled) return;

  // 合并两处白名单来源：顶层 config.whitelist 与 urlDetection.whitelist
  let mergedWhitelist = []
    .concat(Array.isArray(config.whitelist) ? config.whitelist : [])
    .concat(Array.isArray(config.urlDetection.whitelist) ? config.urlDetection.whitelist : []);

  // 统一白名单检查（优先采用全局工具）
  function isWhitelisted(url) { return checkWhitelistWithCache(url, mergedWhitelist); }

  // 白名单优先
  try { if (isWhitelisted(location.href)) return; } catch(e) {}

  // ==================== 监听与检测 ====================
  hookHistory();
  let lastURL = window.location.href;

  const runCheck = () => {
    const currentURL = window.location.href;
    if (currentURL === lastURL) return;
    lastURL = currentURL;

    // 白名单再次确认（SPA 路由变化后可能进入白名单）
    if (isWhitelisted(currentURL)) return;

    const { risks, decodedUrl } = detectRisks(currentURL, config);
    if (risks && risks.length) handleRisks(risks, currentURL, decodedUrl, config);
  };

  const debouncedCheck = debounce(runCheck, 250);

  // 多维度监听 URL 变化
  window.addEventListener('urlChange', debouncedCheck);
  window.addEventListener('popstate', debouncedCheck);
  window.addEventListener('hashchange', debouncedCheck);

  const observer = new MutationObserver(debouncedCheck);
  try { observer.observe(document, { subtree: true, childList: true }); } catch(e) {}

  // 首次检测（不与 lastURL 比较，以确保初次页面也检测一次）
  (function initialCheck(){
    const currentURL = window.location.href;
    if (isWhitelisted(currentURL)) return;
    const { risks, decodedUrl } = detectRisks(currentURL, config);
    if (risks && risks.length) handleRisks(risks, currentURL, decodedUrl, config);
  })();

  // 动态配置热更新：后台广播时更新内存配置与白名单缓存
  try {
    chrome.runtime.onMessage.addListener((req) => {
      if (req && req.type === 'config_updated' && req.config) {
        const raw = req.config;
        config = {
          ...raw,
          urlDetection: { ...defaultUrlDetection, ...(raw.urlDetection || {}) }
        };
        mergedWhitelist = []
          .concat(Array.isArray(config.whitelist) ? config.whitelist : [])
          .concat(Array.isArray(config.urlDetection.whitelist) ? config.urlDetection.whitelist : []);
        whitelistCache.clear();
        // 立即再检测一次当前 URL
        try { debouncedCheck(); } catch {}
      }
    });
  } catch {}

  // ==================== 扩展：全页 URL 覆盖采集 ====================
  // 0) 工具：构造绝对 URL + 去重缓存
  function toAbsolute(url) {
    try { return new URL(url, document.baseURI).href; } catch { return null; }
  }
  const seen = new Map(); // key: source + '|' + url -> expires
  function shouldProcess(url, source) {
    const ttl = Number(config.urlDetection.dedupeTtlMs || defaultUrlDetection.dedupeTtlMs);
    const key = `${source}|${url}`;
    const now = Date.now();
    const exp = seen.get(key) || 0;
    if (exp > now) return false;
    seen.set(key, now + ttl);
    return true;
  }

  async function emitCandidate(absUrl, source) {
    if (!absUrl) return;
    if (!isValidHttp(absUrl)) return;
    if (isWhitelisted(absUrl)) return;
    if (!shouldProcess(absUrl, source)) return;

    // 本地启发式 → 后台恶意库 并行判定
    const local = detectRisks(absUrl, config) || { risks: [], decodedUrl: absUrl };
    const pDb = new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage({ action: 'check_url_risk', url: absUrl }, (resp) => {
          resolve(resp && resp.malicious ? { malicious: true } : { malicious: false });
        });
      } catch { resolve({ malicious: false }); }
    });

    const db = await pDb;
    const risks = [...(local.risks || [])];
    if (db.malicious) risks.push({ type: 'maliciousDb', pattern: 'blacklist', message: '命中恶意域名/URL库' });
    if (risks.length) handleRisks(risks, absUrl, local.decodedUrl || absUrl, config);
  }

  function isValidHttp(u) {
    try { const p = new URL(u).protocol; return p === 'http:' || p === 'https:'; } catch { return false; }
  }

  // 1) 拦截 fetch
  if (config.urlDetection.scanFetch && typeof window.fetch === 'function') {
    try {
      const _fetch = window.fetch.bind(window);
      window.fetch = function(...args) {
        try {
          const input = args[0];
          const url = (typeof input === 'string') ? input : (input && input.url);
          const abs = toAbsolute(url);
          emitCandidate(abs, 'fetch');
        } catch {}
        return _fetch(...args);
      };
    } catch {}
  }

  // 2) 拦截 XHR
  if (config.urlDetection.scanXHR && window.XMLHttpRequest && window.XMLHttpRequest.prototype) {
    try {
      const _open = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function(method, url, ...rest) {
        try { emitCandidate(toAbsolute(url), 'xhr'); } catch {}
        return _open.call(this, method, url, ...rest);
      };
    } catch {}
  }

  // 3) 拦截 WebSocket
  if (config.urlDetection.scanWebSocket && typeof window.WebSocket === 'function') {
    try {
      const WS = window.WebSocket;
      const Patched = function(url, protocols) {
        try { const abs = toAbsolute(url); if (abs && abs.startsWith('ws')) emitCandidate(abs.replace(/^ws/,'http'), 'websocket'); } catch {}
        return new WS(url, protocols);
      };
      Patched.prototype = WS.prototype;
      Object.setPrototypeOf(Patched, WS);
      window.WebSocket = Patched;
    } catch {}
  }

  // 4) 拦截 window.open
  if (config.urlDetection.scanWindowOpen && typeof window.open === 'function') {
    try {
      const _open = window.open;
      window.open = function(url, target, features) {
        try { emitCandidate(toAbsolute(url), 'window.open'); } catch {}
        return _open.call(window, url, target, features);
      };
    } catch {}
  }

  // 5) 监听 Meta Refresh
  function scanMetaRefresh(node) {
    try {
      const content = node.getAttribute('content') || '';
      const m = content.match(/url\s*=\s*([^;]+)$/i);
      if (m && m[1]) emitCandidate(toAbsolute(m[1].trim()), 'meta.refresh');
    } catch {}
  }
  if (config.urlDetection.scanMetaRefresh) {
    try {
      document.querySelectorAll('meta[http-equiv="refresh"]').forEach(scanMetaRefresh);
    } catch {}
  }

  // 6) 扫描与监听元素属性（a/img/script/link/iframe/source/video/audio/form）
  function collectFromElement(el) {
    if (!el || !el.tagName) return;
    const tag = el.tagName.toLowerCase();
    const attrs = [];
    if (tag === 'a' || tag === 'link' || tag === 'area') attrs.push('href');
    if (tag === 'img' || tag === 'script' || tag === 'iframe' || tag === 'source' || tag === 'audio' || tag === 'video') attrs.push('src');
    if (tag === 'form') attrs.push('action');
    for (const a of attrs) {
      const v = el.getAttribute(a);
      if (v) emitCandidate(toAbsolute(v), `el.${tag}.${a}`);
    }
    // 可选：style 与 CSS url()（关默认）
    if (config.urlDetection.scanCssUrls) {
      try {
        const styleAttr = el.getAttribute('style') || '';
        const css = styleAttr.match(/url\(([^)]+)\)/ig) || [];
        css.forEach(m => {
          const u = m.replace(/^url\((.+)\)$/i,'$1').replace(/^['"]|['"]$/g,'');
          emitCandidate(toAbsolute(u), 'css.inline');
        });
      } catch {}
    }
  }

  if (config.urlDetection.scanElements) {
    try {
      // 初次快速扫描（限制上限以控性能）
      let count = 0, limit = 800;
      const nodes = document.querySelectorAll('a[href],link[href],area[href],img[src],script[src],iframe[src],source[src],audio[src],video[src],form[action],meta[http-equiv="refresh"]');
      nodes.forEach((n) => { if (count++ < limit) { if (n.tagName.toLowerCase()==='meta') scanMetaRefresh(n); else collectFromElement(n); } });

      // 监听属性变化与新增节点
      const mo = new MutationObserver((list) => {
        for (const m of list) {
          if (m.type === 'attributes' && m.target) {
            const t = m.target;
            const name = m.attributeName || '';
            const watched = ['href','src','action','style'];
            if (watched.includes(name)) {
              if (t.tagName && t.tagName.toLowerCase() === 'meta' && name === 'content') scanMetaRefresh(t); else collectFromElement(t);
            }
          } else if (m.type === 'childList') {
            m.addedNodes && m.addedNodes.forEach((node) => {
              if (node.nodeType === 1) {
                const el = node;
                if (el.matches && el.matches('a[href],link[href],area[href],img[src],script[src],iframe[src],source[src],audio[src],video[src],form[action],meta[http-equiv="refresh"]')) {
                  if (el.tagName.toLowerCase()==='meta') scanMetaRefresh(el); else collectFromElement(el);
                }
                // 子树内也可能包含目标元素
                if (el.querySelectorAll) {
                  el.querySelectorAll('a[href],link[href],area[href],img[src],script[src],iframe[src],source[src],audio[src],video[src],form[action],meta[http-equiv="refresh"]').forEach((n) => {
                    if (n.tagName.toLowerCase()==='meta') scanMetaRefresh(n); else collectFromElement(n);
                  });
                }
              }
            });
          }
        }
      });
      mo.observe(document, { subtree: true, childList: true, attributes: true, attributeFilter: ['href','src','action','style','content'] });
    } catch {}
  }

})();

