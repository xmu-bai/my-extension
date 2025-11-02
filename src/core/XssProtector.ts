import { Log } from '../utils/log';

/**
 * XSS 防护器：拦截并过滤潜在的恶意脚本（可选功能）
 */
export class XssProtector {
  /** 过滤 HTML 内容中的危险标签和属性 */
  filterDangerousHtml(html: string): string {
    // 1. 移除 <script> 标签
    let filtered = html.replace(/<script[\s\S]*?<\/script>/gi, '<!-- 过滤掉潜在恶意脚本 -->');
    
    // 2. 移除事件属性（如 onload、onerror 等）
    filtered = filtered.replace(/ on\w+="[\s\S]*?"/gi, '');
    
    // 3. 过滤 javascript: 伪协议
    filtered = filtered.replace(/href="javascript:[\s\S]*?"/gi, 'href="#filtered"');
    
    Log.debug('HTML 内容已过滤潜在危险元素');
    return filtered;
  }

  /** 监听 DOM 插入，过滤动态添加的危险内容 */
  startDomProtection() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach(mutation => {
        mutation.addedNodes.forEach(node => {
          if (node.nodeType !== Node.ELEMENT_NODE) return;
          const element = node as HTMLElement;

          // 移除危险标签
          if (element.tagName === 'SCRIPT' || element.tagName === 'IFRAME') {
            element.remove();
            Log.warn(`拦截并移除危险标签: ${element.tagName}`);
          }

          // 移除危险属性
          Array.from(element.attributes).forEach(attr => {
            if (attr.name.startsWith('on')) {
              element.removeAttribute(attr.name);
              Log.warn(`移除危险事件属性: ${attr.name}`);
            }
          });
        });
      });
    });

    // 监听整个文档的 DOM 变化
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true
    });

    Log.info('XSS 防护已启用');
    return observer;
  }
}