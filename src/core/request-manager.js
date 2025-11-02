import { supportAgreement, supportType, supportMethods } from './config.js';
import { UrlUtils } from './url-utils.js';

/**
 * 请求管理器
 * 负责拦截网络请求、去重、缓存等
 */
export class RequestManager {
  constructor() {
    this.requestList = {};
    this.urlUtils = new UrlUtils();
  }

  /**
   * 初始化请求拦截
   */
  init() {
    console.log('[RequestManager] 初始化请求拦截...');
    this.setupOnBeforeRequest();
    this.setupOnSendHeaders();
  }

  /**
   * 监听请求发送前事件
   */
  setupOnBeforeRequest() {
    chrome.webRequest.onBeforeRequest.addListener(
      (request) => {
        const requestId = request.requestId;
        
        // 检查是否需要处理该请求
        if (this.shouldSkipRequest(request)) {
          return {};
        }

        // 缓存请求
        this.requestList[requestId] = {
          ...request,
          timestamp: Date.now()
        };

        return {};
      },
      { urls: supportAgreement },
      ['requestBody']
    );
  }

  /**
   * 监听请求头发送事件
   */
  setupOnSendHeaders() {
    chrome.webRequest.onSendHeaders.addListener(
      (request) => {
        const requestId = request.requestId;
        const cachedRequest = this.requestList[requestId];

        if (!cachedRequest) {
          return {};
        }

        // 更新请求头
        cachedRequest.requestHeaders = request.requestHeaders;
        this.requestList[requestId] = cachedRequest;

        return {};
      },
      { urls: supportAgreement },
      ['requestHeaders']
    );
  }

  /**
   * 检查是否应该跳过该请求
   * @param {Object} request - 请求对象
   * @returns {boolean}
   */
  shouldSkipRequest(request) {
    // 检查请求类型
    if (!supportType.includes(request.type)) {
      return true;
    }

    // 检查是否为后台请求
    if (request.tabId === -1) {
      return true;
    }

    // 检查HTTP方法
    if (!supportMethods.includes(request.method.toUpperCase())) {
      return true;
    }

    // 检查URL是否为静态资源
    if (this.urlUtils.shouldSkipUrl(request.url)) {
      return true;
    }

    // 检查是否已存在相同请求
    if (this.isDuplicateRequest(request)) {
      return true;
    }

    return false;
  }

  /**
   * 检查是否为重复请求
   * @param {Object} request - 请求对象
   * @returns {boolean}
   */
  isDuplicateRequest(request) {
    const keys = Object.keys(this.requestList);
    
    for (const key of keys) {
      const cachedRequest = this.requestList[key];
      
      // 检查URL、类型、方法是否完全相同
      if (
        cachedRequest.url === request.url &&
        cachedRequest.type === request.type &&
        cachedRequest.method === request.method
      ) {
        // 如果在5秒内的重复请求，认为是一样的
        const timeDiff = Date.now() - cachedRequest.timestamp;
        if (timeDiff < 5000) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * 获取缓存的请求
   * @param {string} requestId - 请求ID
   * @returns {Object|undefined}
   */
  getRequest(requestId) {
    return this.requestList[requestId];
  }

  /**
   * 获取所有缓存的请求
   * @returns {Object}
   */
  getAllRequests() {
    return this.requestList;
  }

  /**
   * 清理过期的请求缓存
   * @param {number} maxAge - 最大保存时间（毫秒），默认5分钟
   */
  cleanExpiredRequests(maxAge = 5 * 60 * 1000) {
    const now = Date.now();
    const keys = Object.keys(this.requestList);

    for (const key of keys) {
      const request = this.requestList[key];
      if (now - request.timestamp > maxAge) {
        delete this.requestList[key];
      }
    }
  }
}
