/**
 * URL工具类
 * 用于解析URL参数、注入payload等操作
 */
export class UrlUtils {
  /**
   * 解析URL并返回URL对象
   */
  getInfo(urlAddress) {
    try {
      return new URL(urlAddress);
    } catch (e) {
      console.error('[UrlUtils] Invalid URL:', urlAddress);
      return null;
    }
  }

  /**
   * 解析URL参数（Query String）
   * @param {string} urlAddress - 完整的URL地址
   * @returns {Object|false} 参数对象或false
   */
  parseSearch(urlAddress) {
    if (!urlAddress || typeof urlAddress !== 'string') {
      return false;
    }

    const url = this.getInfo(urlAddress);
    if (!url) {
      return false;
    }

    const search = url.search;
    if (!search || search[0] !== '?') {
      return false;
    }

    const params = {};
    const paramsStr = search.slice(1).split('&');
    
    for (let i = 0; i < paramsStr.length; i++) {
      const [key, value] = paramsStr[i].split('=');
      if (key) {
        params[decodeURIComponent(key)] = value ? decodeURIComponent(value) : '';
      }
    }

    return params;
  }

  /**
   * 将参数对象转换为URL查询字符串
   * @param {Object} paramsObj - 参数对象
   * @param {string} baseHref - 基础URL（可选）
   * @returns {string} 完整URL或查询字符串
   */
  stringifySearch(paramsObj, baseHref = '') {
    if (!paramsObj || typeof paramsObj !== 'object') {
      return false;
    }

    const params = [];
    for (const key in paramsObj) {
      if (Object.prototype.hasOwnProperty.call(paramsObj, key)) {
        const encodedKey = encodeURIComponent(key);
        const encodedValue = encodeURIComponent(paramsObj[key]);
        params.push(`${encodedKey}=${encodedValue}`);
      }
    }

    const queryString = params.join('&');
    
    if (baseHref) {
      // 移除baseHref中原有的查询参数
      const base = baseHref.split('?')[0];
      return `${base}?${queryString}`;
    }
    
    return queryString;
  }

  /**
   * 检查URL是否需要检测（过滤静态资源等）
   * @param {string} url - URL地址
   * @returns {boolean}
   */
  shouldSkipUrl(url) {
    if (!url) return true;
    
    // 跳过静态资源
    const skipExtensions = ['.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf'];
    return skipExtensions.some(ext => url.toLowerCase().includes(ext));
  }
}
