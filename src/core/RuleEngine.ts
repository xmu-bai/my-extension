import { XssPayload } from './PayloadManager';
import { RequestInfo } from '../background/service-worker';

/** 漏洞检测结果 */
export interface DetectionResult {
  isVulnerable: boolean; // 是否存在漏洞
  type?: 'reflected' | 'stored'; // 漏洞类型
  payload?: XssPayload; // 触发的 Payload
  evidence: string; // 漏洞证据（响应中匹配的内容）
  confidence: 'low' | 'medium' | 'high'; // 置信度
}

/**
 * 规则引擎：定义 XSS 检测的判定逻辑，判断 Payload 是否被成功执行/未过滤
 */
export class RuleEngine {
  /**
   * 检测响应内容中是否存在未过滤的 Payload（核心判定逻辑）
   * @param responseContent 响应体内容（HTML/文本）
   * @param requestInfo 请求信息（含注入的 Payload）
   * @param payloads 已生成的 Payload 列表
   */
  detectXssInResponse(
    responseContent: string,
    requestInfo: RequestInfo,
    payloads: XssPayload[]
  ): DetectionResult {
    // 1. 查找与请求关联的 Payload
    const matchedPayload = payloads.find(p => p.content.includes(requestInfo.payload));
    if (!matchedPayload) {
      return {
        isVulnerable: false,
        evidence: '未找到关联的 Payload',
        confidence: 'low'
      };
    }

    // 2. 根据 Payload 类型执行不同检测规则
    switch (matchedPayload.type) {
      case 'encoded':
        return this.checkEncodedPayload(responseContent, matchedPayload);
      case 'obfuscated':
        return this.checkObfuscatedPayload(responseContent, matchedPayload);
      default:
        return this.checkBasicPayload(responseContent, matchedPayload);
    }
  }

  /** 检测基础 Payload（未编码/混淆） */
  private checkBasicPayload(content: string, payload: XssPayload): DetectionResult {
    // 规则：原始 Payload 出现在响应中，且未被转义
    if (content.includes(payload.content)) {
      return {
        isVulnerable: true,
        type: payload.purpose,
        payload,
        evidence: `响应中包含未过滤的基础 Payload: ${payload.content.slice(0, 50)}`,
        confidence: 'high'
      };
    }
    return {
      isVulnerable: false,
      evidence: '基础 Payload 未在响应中出现',
      confidence: 'low'
    };
  }

  /** 检测编码 Payload（验证是否被解码执行） */
  private checkEncodedPayload(content: string, payload: XssPayload): DetectionResult {
    // 规则：编码后的 Payload 在响应中被解码（即原始内容出现）
    const decodedPayload = this.decodeHtml(payload.content);
    if (content.includes(decodedPayload)) {
      return {
        isVulnerable: true,
        type: payload.purpose,
        payload,
        evidence: `响应中包含解码后的 Payload: ${decodedPayload.slice(0, 50)}`,
        confidence: 'medium'
      };
    }
    return {
      isVulnerable: false,
      evidence: '编码 Payload 未被解码',
      confidence: 'low'
    };
  }

  /** 检测混淆 Payload（验证是否被还原执行） */
  private checkObfuscatedPayload(content: string, payload: XssPayload): DetectionResult {
    // 规则：混淆后的 Payload 在响应中被还原（即去混淆后内容出现）
    const deobfuscatedPayload = this.deobfuscatePayload(payload.content);
    if (content.includes(deobfuscatedPayload)) {
      return {
        isVulnerable: true,
        type: payload.purpose,
        payload,
        evidence: `响应中包含还原后的混淆 Payload: ${deobfuscatedPayload.slice(0, 50)}`,
        confidence: 'medium'
      };
    }
    return {
      isVulnerable: false,
      evidence: '混淆 Payload 未被还原',
      confidence: 'low'
    };
  }

  /** HTML 解码（与 PayloadManager 的编码逻辑对应） */
  private decodeHtml(content: string): string {
    return content
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#039;/g, "'");
  }

  /** 去混淆（与 PayloadManager 的混淆逻辑对应） */
  private deobfuscatePayload(content: string): string {
    // 移除零宽字符、还原关键字大小写
    return content
      .replace(/\u200B|\u200C/g, '') // 移除零宽字符
      .replace(/sCrIpT/g, 'script')
      .replace(/a\u200Blert/g, 'alert');
  }
}