import { RequestManager } from './core/request-manager.js';
import { XssDetector } from './detectors/xss-detector.js';

/**
 * 主入口文件
 * 初始化请求管理和XSS检测系统
 */
class SecurityExtension {
  constructor() {
    this.requestManager = null;
    this.xssDetector = null;
    this.initialized = false;
  }

  /**
   * 初始化
   */
  async init() {
    if (this.initialized) {
      console.log('[SecurityExtension] 已经初始化');
      return;
    }

    console.log('[SecurityExtension] 开始初始化...');

    // 初始化请求管理器
    this.requestManager = new RequestManager();
    this.requestManager.init();

    // 初始化XSS检测器
    this.xssDetector = new XssDetector();

    // 设置自动清理
    this.setupAutoCleanup();

    // 监听来自content script的消息
    this.setupMessageListener();

    this.initialized = true;
    console.log('[SecurityExtension] 初始化完成');
  }

  /**
   * 设置自动清理任务
   */
  setupAutoCleanup() {
    // 每5分钟清理一次过期的请求
    setInterval(() => {
      if (this.requestManager) {
        this.requestManager.cleanExpiredRequests();
      }
    }, 5 * 60 * 1000);
  }

  /**
   * 设置消息监听器
   */
  setupMessageListener() {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      console.log('[SecurityExtension] 收到消息:', message);

      // 处理扫描请求
      if (message.action === 'scanRequest') {
        this.handleScanRequest(message.data, sendResponse);
        return true; // 保持通道打开以异步响应
      }

      // 处理快速扫描
      if (message.action === 'quickScan') {
        this.handleQuickScan(message.data, sendResponse);
        return true;
      }

      // 处理获取漏洞列表
      if (message.action === 'getVulnerabilities') {
        const vulnerabilities = this.xssDetector.getDetectedVulnerabilities();
        sendResponse({ vulnerabilities });
        return true;
      }

      // 处理清除检测记录
      if (message.action === 'clearDetected') {
        this.xssDetector.clearDetectedVulnerabilities();
        sendResponse({ success: true });
        return true;
      }

      // 处理获取统计信息
      if (message.action === 'getStats') {
        const stats = this.getStats();
        sendResponse(stats);
        return true;
      }

      // 处理重置统计
      if (message.action === 'resetStats') {
        this.resetStats();
        sendResponse({ success: true });
        return true;
      }

      // 处理更新配置
      if (message.action === 'updateConfig') {
        this.updateConfig(message.config);
        sendResponse({ success: true });
        return true;
      }

      // 处理测试页面XSS漏洞报告
      if (message.action === 'reportTestXssVulnerability') {
        this.handleTestVulnerability(message.vulnerability);
        sendResponse({ success: true });
        return true;
      }

      sendResponse({ success: false, error: '未知操作' });
    });
  }

  /**
   * 处理扫描请求
   */
  async handleScanRequest(request, sendResponse) {
    try {
      const result = await this.xssDetector.detect(request);
      
      if (result.success && result.vulnerable) {
        // 记录漏洞
        result.results.forEach(vuln => {
          this.xssDetector.recordVulnerability(vuln);
        });

        // 发送通知
        this.sendNotification('发现XSS漏洞', `检测到 ${result.results.length} 个XSS漏洞`);
      }

      sendResponse({
        success: true,
        result: result
      });
    } catch (error) {
      console.error('[SecurityExtension] 扫描失败:', error);
      sendResponse({
        success: false,
        error: error.message
      });
    }
  }

  /**
   * 处理快速扫描
   */
  handleQuickScan(request, sendResponse) {
    try {
      // 检查request是否有效
      if (!request) {
        console.error('[SecurityExtension] 快速扫描：缺少request参数');
        sendResponse({
          success: false,
          error: '缺少请求参数'
        });
        return;
      }

      // 检查URL是否存在
      if (!request.url) {
        console.error('[SecurityExtension] 快速扫描：缺少URL');
        sendResponse({
          success: false,
          error: '缺少URL参数'
        });
        return;
      }

      // 执行快速扫描
      const result = this.xssDetector.quickScan(request);
      
      if (result.success && result.suspicious) {
        // 发送通知
        this.sendNotification('可疑XSS参数', `发现 ${result.parameters.length} 个可疑参数`);
      }

      sendResponse({
        success: true,
        result: result
      });
    } catch (error) {
      console.error('[SecurityExtension] 快速扫描失败:', error);
      sendResponse({
        success: false,
        error: error.message || '快速扫描执行出错'
      });
    }
  }

  /**
   * 发送通知
   */
  sendNotification(title, message) {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: title,
      message: message,
      priority: 2
    });
  }

  /**
   * 获取统计信息
   */
  getStats() {
    const requestCount = this.requestManager 
      ? Object.keys(this.requestManager.requestList).length 
      : 0;
    const vulnerabilityCount = this.xssDetector 
      ? this.xssDetector.getDetectedVulnerabilities().length 
      : 0;

    return {
      requestCount,
      vulnerabilityCount
    };
  }

  /**
   * 重置统计
   */
  resetStats() {
    if (this.xssDetector) {
      this.xssDetector.clearDetectedVulnerabilities();
    }
  }

  /**
   * 更新配置
   */
  updateConfig(config) {
    if (this.xssDetector && config) {
      if (typeof config.enabled === 'boolean') {
        this.xssDetector.config.enabled = config.enabled;
      }
      if (typeof config.depth === 'number') {
        this.xssDetector.config.depth = config.depth;
      }
      console.log('[SecurityExtension] 配置已更新:', config);
    }
  }

  /**
   * 处理测试页面漏洞报告
   */
  handleTestVulnerability(vulnerability) {
    // 记录漏洞
    this.xssDetector.recordVulnerability(vulnerability);
    
    // 发送通知
    this.sendNotification(
      '发现XSS测试漏洞',
      `${vulnerability.type || 'XSS漏洞'}`
    );
    
    console.log('[SecurityExtension] 测试页面XSS漏洞:', vulnerability);
  }
}

// 创建实例并初始化
const securityExtension = new SecurityExtension();

// 插件安装或启动时初始化
chrome.runtime.onInstalled.addListener(() => {
  console.log('[SecurityExtension] 插件已安装');
  securityExtension.init();
});

chrome.runtime.onStartup.addListener(() => {
  console.log('[SecurityExtension] 插件启动');
  securityExtension.init();
});

// 立即初始化
securityExtension.init();
