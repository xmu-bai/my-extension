import { PayloadManager, XssPayload } from './PayloadManager';
import { RuleEngine, DetectionResult } from './RuleEngine';
import { RequestInfo } from '../background/service-worker';
import { Storage } from '../utils/storage';
import { STORAGE_KEYS } from '../config/constants';
import { Log } from '../utils/log';

/**
 * XSS 检测器：整合 Payload 生成与规则判定，执行完整检测流程
 */
export class XssDetector {
  private payloadManager: PayloadManager;
  private ruleEngine: RuleEngine;

  constructor(payloadManager: PayloadManager, ruleEngine: RuleEngine) {
    this.payloadManager = payloadManager;
    this.ruleEngine = ruleEngine;
  }

  /**
   * 执行检测流程
   * @param requestInfo 请求信息（含注入的 Payload）
   * @param responseContent 响应体内容
   * @returns 检测结果
   */
  async detect(requestInfo: RequestInfo, responseContent: string): Promise<DetectionResult> {
    Log.debug('XssDetector', `开始检测请求: ${requestInfo.id}，URL: ${requestInfo.url}`);

    // 1. 获取所有已生成的 Payload（用于规则匹配）
    const payloads = this.payloadManager.getGeneratedPayloads();

    // 2. 调用规则引擎判定是否存在漏洞
    const result = this.ruleEngine.detectXssInResponse(
      responseContent,
      requestInfo,
      payloads
    );

    // 3. 若检测到漏洞，存储结果
    if (result.isVulnerable) {
      await this.storeVulnerability({
        ...requestInfo,
        ...result,
        detectedAt: Date.now()
      });
      Log.warn('XssDetector', `检测到漏洞: ${result.evidence}`);
    }

    return result;
  }

  /** 生成存储型 XSS 检测专用 Payload（用于持续性检测） */
  generateStoredPayload(): XssPayload {
    return this.payloadManager.generatePayloadByLevel('HIGH', 'stored');
  }

  /** 存储漏洞信息到本地存储 */
  private async storeVulnerability(vuln: {
    id: string;
    url: string;
    method: string;
    detectedAt: number;
    result: DetectionResult;
  }) {
    const history = await Storage.get(STORAGE_KEYS.VULNERABILITY_HISTORY) || [];
    // 去重（避免同一漏洞重复存储）
    const uniqueHistory = history.filter((h: any) => h.id !== vuln.id);
    uniqueHistory.push(vuln);
    await Storage.set(STORAGE_KEYS.VULNERABILITY_HISTORY, uniqueHistory);
  }
}