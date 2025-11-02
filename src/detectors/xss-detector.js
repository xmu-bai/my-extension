import { identifier, xssConfig } from '../core/config.js';
import { UrlUtils } from '../core/url-utils.js';
import { getPayloadsByDepth, getPayloadsByType } from '../payloads/xss-payloads.js';

/**
 * XSS检测器
 * 负责注入payload并检测XSS漏洞
 */
export class XssDetector {
  constructor() {
    this.urlUtils = new UrlUtils();
    this.config = xssConfig;
    this.detectedVulnerabilities = [];
  }

  /**
   * 检测单个请求的XSS漏洞
   * @param {Object} request - 请求对象
   * @returns {Promise<Object>} 检测结果
   */
  async detect(request) {
    if (!this.config.enabled) {
      return { success: false, reason: '检测已禁用' };
    }

    // 解析URL
    const urlInfo = this.urlUtils.getInfo(request.url);
    if (!urlInfo) {
      return { success: false, reason: '无效URL' };
    }

    // 检查是否有查询参数
    if (!urlInfo.search) {
      return { success: false, reason: '无查询参数' };
    }

    // 解析参数
    const params = this.urlUtils.parseSearch(request.url);
    if (!params || Object.keys(params).length === 0) {
      return { success: false, reason: '无有效参数' };
    }

    // 获取payload
    const payloads = getPayloadsByDepth(this.config.depth);

    // 逐一测试payload
    const results = [];
    for (const payload of payloads) {
      const testResult = await this.testPayload(request, params, payload);
      if (testResult.vulnerable) {
        results.push({
          vulnerability: 'XSS',
          url: request.url,
          parameter: testResult.parameter,
          payload: payload,
          severity: 'high',
          description: '发现反射型XSS漏洞',
          requestId: request.requestId
        });
      }
    }

    return {
      success: true,
      vulnerable: results.length > 0,
      results: results
    };
  }

  /**
   * 测试单个payload
   * @param {Object} request - 请求对象
   * @param {Object} params - 参数对象
   * @param {string} payload - XSS载荷
   * @returns {Promise<Object>} 测试结果
   */
  async testPayload(request, params, payload) {
    // 为所有参数注入payload
    const testParams = { ...params };
    let vulnerableParameter = null;

    for (const key in testParams) {
      if (Object.prototype.hasOwnProperty.call(testParams, key)) {
        // 注入payload
        testParams[key] = payload;
        
        // 构造测试URL
        const testUrl = this.urlUtils.stringifySearch(testParams, request.url);
        
        // 这里应该发送测试请求，但为了安全起见，我们只标记
        // 实际环境中可以配置是否真实发送请求
        if (this.shouldSendRequest()) {
          const isVulnerable = await this.sendTestRequest(request, testUrl);
          if (isVulnerable) {
            vulnerableParameter = key;
            break;
          }
        }
        
        // 恢复原值
        testParams[key] = params[key];
      }
    }

    return {
      vulnerable: vulnerableParameter !== null,
      parameter: vulnerableParameter
    };
  }

  /**
   * 发送测试请求
   * @param {Object} originalRequest - 原始请求
   * @param {string} testUrl - 测试URL
   * @returns {Promise<boolean>} 是否易受攻击
   */
  async sendTestRequest(originalRequest, testUrl) {
    try {
      // 使用fetch发送测试请求
      const response = await fetch(testUrl, {
        method: originalRequest.method,
        headers: originalRequest.requestHeaders || {}
      });

      const responseText = await response.text();

      // 检查响应中是否包含payload（简单检测）
      // 注意：这只是简单的字符串匹配，实际需要更复杂的检测
      return responseText.includes('<script>alert(1)</script>') ||
             responseText.includes('<img src=x onerror=alert(1)>') ||
             responseText.includes('<svg onload=alert(1)>');
    } catch (error) {
      console.error('[XssDetector] 测试请求失败:', error);
      return false;
    }
  }

  /**
   * 是否应该发送真实请求
   * @returns {boolean}
   */
  shouldSendRequest() {
    // 这里可以根据配置决定是否发送真实请求
    // 为了安全，默认返回false，只进行静态分析
    return false;
  }

  /**
   * 检测URL参数中可能的XSS
   * @param {Object} request - 请求对象
   * @returns {Object} 检测结果
   */
  quickScan(request) {
    try {
      // 检查request和url
      if (!request || !request.url) {
        return { 
          success: false,
          reason: '缺少URL参数'
        };
      }

      // 解析URL
      const urlInfo = this.urlUtils.getInfo(request.url);
      if (!urlInfo) {
        return { 
          success: false,
          reason: '无效的URL格式'
        };
      }

      // 如果没有查询参数，返回无结果
      if (!urlInfo.search) {
        return { 
          success: true,
          suspicious: false,
          parameters: [],
          reason: 'URL中没有查询参数'
        };
      }

      // 解析参数
      const params = this.urlUtils.parseSearch(request.url);
      if (!params || Object.keys(params).length === 0) {
        return { 
          success: true,
          suspicious: false,
          parameters: [],
          reason: '无法解析URL参数'
        };
      }

      // 扫描可疑参数
      const suspiciousParams = [];
      for (const key in params) {
        if (Object.prototype.hasOwnProperty.call(params, key)) {
          const value = params[key];
          
          if (!value || typeof value !== 'string') {
            continue;
          }

          // 检查是否包含可疑的关键字
          const suspiciousPatterns = [
            /<script/i,
            /javascript:/i,
            /onerror=/i,
            /onload=/i,
            /onfocus=/i,
            /<img/i,
            /<svg/i,
            /<iframe/i,
            /alert\(/i,
            /eval\(/i,
            /document\./i
          ];

          for (const pattern of suspiciousPatterns) {
            if (pattern.test(value)) {
              suspiciousParams.push({
                parameter: key,
                value: value.length > 100 ? value.substring(0, 100) + '...' : value,
                pattern: pattern.toString()
              });
              break;
            }
          }
        }
      }

      return {
        success: true,
        suspicious: suspiciousParams.length > 0,
        parameters: suspiciousParams
      };
    } catch (error) {
      console.error('[XssDetector] quickScan错误:', error);
      return {
        success: false,
        reason: '扫描过程出错: ' + error.message
      };
    }
  }

  /**
   * 记录检测到的漏洞
   * @param {Object} vulnerability - 漏洞信息
   */
  recordVulnerability(vulnerability) {
    this.detectedVulnerabilities.push({
      ...vulnerability,
      timestamp: Date.now()
    });
  }

  /**
   * 获取所有检测到的漏洞
   * @returns {Array<Object>}
   */
  getDetectedVulnerabilities() {
    return this.detectedVulnerabilities;
  }

  /**
   * 清除检测记录
   */
  clearDetectedVulnerabilities() {
    this.detectedVulnerabilities = [];
  }
}
