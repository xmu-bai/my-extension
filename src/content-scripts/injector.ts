import { PayloadManager } from '../core/PayloadManager';
import { STORAGE_KEYS, DEFAULT_DETECTION_RULES } from '../config/constants';
import { XssDetectorOptions, DEFAULT_OPTIONS } from '../config/options';
import { getUrlParams, setUrlParams } from '../utils/url';
import { Storage } from '../utils/storage';
import { Log } from '../utils/log';

/**
 * 页面注入器：负责向表单/URL 参数注入检测 Payload，监听 DOM 变化以捕获 XSS 触发点
 * 运行在页面上下文（content-script 环境），与页面 DOM 直接交互
 */
class PayloadInjector {
  private payloadManager: PayloadManager;
  private config: XssDetectorOptions = DEFAULT_OPTIONS;
  private injectedElements = new WeakSet<HTMLInputElement | HTMLTextAreaElement>();
  private mutationObserver: MutationObserver | null = null;

  constructor() {
    this.payloadManager = new PayloadManager();
    this.init();
  }

  /** 初始化：加载配置、设置监听器 */
  private async init() {
    // 从存储加载配置（与 background 共享配置）
    this.config = await Storage.get<XssDetectorOptions>(STORAGE_KEYS.DETECTOR_CONFIG) || DEFAULT_OPTIONS;
    
    if (!this.config.enabled) {
      Log.info('XSS 检测已禁用，跳过页面注入初始化');
      return;
    }

    // 初始化时处理当前页面的 URL 和表单
    this.injectPayloadToUrl();
    this.injectPayloadToForms();

    // 监听 DOM 变化（新表单/元素添加时重新注入）
    this.startDomMutationListening();

    // 监听页面导航变化（如单页应用路由切换）
    this.listenToNavigationChanges();

    Log.info('Payload 注入器初始化完成');
  }

  /** 向当前页面 URL 参数注入 Payload（针对反射型 XSS 检测） */
  private injectPayloadToUrl() {
    if (!this.config.targetMethods.includes('GET')) return;

    const currentUrl = window.location.href;
    const payload = this.payloadManager.generatePayloadByLevel(this.config.detectionLevel);
    
    // 仅向敏感参数注入（如搜索框、用户输入参数）
    const params = getUrlParams(currentUrl);
    const sensitiveParams = DEFAULT_DETECTION_RULES.SENSITIVE_PARAMS;
    let hasInjected = false;

    Object.keys(params).forEach(key => {
      if (sensitiveParams.includes(key as any)) {
        params[key] = `${params[key]}${payload}`;
        hasInjected = true;
      }
    });

    // 若注入了 Payload，更新 URL（不刷新页面，仅修改地址栏）
    if (hasInjected) {
      const newUrl = setUrlParams(currentUrl, params);
      window.history.replaceState(null, '', newUrl);
      Log.debug('injector', `URL 参数注入完成: ${newUrl}`);
    }
  }

  /** 向页面中所有表单注入 Payload（针对 POST 表单提交） */
  private injectPayloadToForms() {
    if (!this.config.targetMethods.includes('POST')) return;

    const forms = document.querySelectorAll('form');
    const payload = this.payloadManager.generatePayloadByLevel(this.config.detectionLevel);

    forms.forEach(form => {
      // 忽略指定域名的表单（如配置中的忽略列表）
      if (this.shouldIgnoreDomain(form.action)) return;

      // 处理表单内的输入元素（input/textarea）
      const inputElements = form.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>(
        'input[type="text"], input[type="search"], textarea'
      );

      inputElements.forEach(el => {
        // 跳过已注入的元素
        if (this.injectedElements.has(el)) return;

        // 向输入值注入 Payload（保留原始值，拼接检测字符串）
        const originalValue = el.value || '';
        el.value = `${originalValue}${payload}`;
        this.injectedElements.add(el);

        // 触发输入事件（避免表单验证拦截）
        el.dispatchEvent(new Event('input', { bubbles: true }));
        Log.debug('injector', `向表单元素注入 Payload: ${el.name || el.id}`);
      });
    });
  }

  /** 监听 DOM 变化（新元素添加时重新注入 Payload） */
  private startDomMutationListening() {
    this.mutationObserver = new MutationObserver((mutations) => {
      mutations.forEach(mutation => {
        // 处理新增的节点
        mutation.addedNodes.forEach(node => {
          if (node.nodeType !== Node.ELEMENT_NODE) return;
          const element = node as HTMLElement;

          // 若新增了表单，重新注入 Payload
          if (element.tagName === 'FORM') {
            this.injectPayloadToForms();
          }

          // 若新增了输入元素，单独处理
          const newInputs = element.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>(
            'input[type="text"], input[type="search"], textarea'
          );
          newInputs.forEach(el => {
            if (!this.injectedElements.has(el)) {
              this.injectPayloadToForms();
            }
          });

          // 检测新增元素中是否包含未过滤的 Payload（XSS 触发点）
          this.detectXssInElement(element);
        });
      });
    });

    // 监听整个文档的 DOM 变化（包括子节点和属性）
    this.mutationObserver.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      characterData: true
    });
  }

  /** 检测元素中是否包含未过滤的 Payload（判断 XSS 触发） */
  private detectXssInElement(element: HTMLElement) {
    const payloads = this.payloadManager.getGeneratedPayloads();
    const elementHtml = element.outerHTML;
    const elementText = element.textContent || '';

    payloads.forEach(payload => {
      // 若 Payload 出现在 HTML 中（未被转义），可能存在存储型/反射型 XSS
      if (elementHtml.includes(payload.content) || elementText.includes(payload.content)) {
        Log.warn('injector', `检测到潜在 XSS 触发点: ${element.tagName}`);
        
        // 向 background 发送漏洞信息
        chrome.runtime.sendMessage({
          type: 'XSS_DETECTED',
          data: {
            url: window.location.href,
            element: element.tagName,
            payload: payload.content,
            context: elementHtml.slice(0, 100)
          }
        });
      }
    });
  }

  /** 监听页面导航变化（单页应用路由切换时重新注入） */
  private listenToNavigationChanges() {
    // 监听历史记录变化
    window.addEventListener('popstate', () => {
      this.injectPayloadToUrl();
      this.injectPayloadToForms();
    });

    // 拦截所有链接点击（处理 SPA 路由跳转）
    document.addEventListener('click', (e) => {
      const target = e.target as HTMLElement;
      const link = target.closest('a');
      if (link && link.href && !link.target) {
        // 延迟执行，等待路由更新
        setTimeout(() => {
          this.injectPayloadToUrl();
          this.injectPayloadToForms();
        }, 100);
      }
    });
  }

  /** 判断是否忽略当前域名（基于配置中的忽略列表） */
  private shouldIgnoreDomain(url: string): boolean {
    try {
      const domain = new URL(url).hostname;
      return this.config.ignoredDomains.some(ignored => {
        // 支持通配符（如 *.local 匹配 a.local、b.local）
        const regex = new RegExp(ignored.replace('*', '.*'));
        return regex.test(domain);
      });
    } catch (e) {
      return false;
    }
  }

  /** 清理资源（销毁监听器） */
  public destroy() {
    if (this.mutationObserver) {
      this.mutationObserver.disconnect();
    }
    this.injectedElements = new WeakSet();
  }
}

// 初始化注入器（页面加载时执行）
const injector = new PayloadInjector();

// 监听 background 发送的配置更新事件（如用户在选项页修改配置）
chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'CONFIG_UPDATED') {
    injector.destroy();
    new PayloadInjector();
  }
});