import { DEFAULT_DETECTION_RULES, STORAGE_KEYS } from '../config/constants';
import { Log } from '../utils/log';
import { isDomainIgnored } from '../utils/url';
import { DEFAULT_OPTIONS } from '../config/options';

export interface RequestInfo {
  id: string;
  url: string;
  method: string;
  payload: string;
  timestamp: number;
}

export class BackgroundService {
  private requestList = new Map<string, RequestInfo>();
  private cleanupInterval: ReturnType<typeof setInterval>;

  constructor() {
    // 初始化时启动定时清理（每30秒执行一次）
    this.cleanupInterval = setInterval(() => this.cleanExpiredRequests(), 30 * 1000);
    Log.info('background', '服务初始化完成，启动定时清理');
  }

  /** 清理过期请求 */
  private cleanExpiredRequests() {
    const now = Date.now();
    const expiredCount = this.requestList.size;
    
    this.requestList.forEach((info, id) => {
      if (now - info.timestamp > DEFAULT_DETECTION_RULES.REQUEST_EXPIRE_TIME) {
        this.requestList.delete(id);
      }
    });

    if (expiredCount > this.requestList.size) {
      Log.debug('background', `清理了${expiredCount - this.requestList.size}个过期请求`);
    }
  }

  /** 存储请求信息 */
  storeRequest(info: RequestInfo) {
    this.requestList.set(info.id, { ...info, timestamp: Date.now() });
    // 存储后立即检查一次（避免内存峰值）
    this.cleanExpiredRequests();
  }

  /** 销毁资源（避免内存泄漏） */
  destroy() {
    clearInterval(this.cleanupInterval);
    this.requestList.clear();
    Log.info('background', '服务已销毁，清理资源完成');
  }
}

// 初始化服务
const backgroundService = new BackgroundService();

// 监听来自 content-script 的安全告警消息（例如 securityIssue）
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message && message.action === 'securityIssue') {
    // 异步读取配置以判断是否忽略该域名
    const url = message.url || (sender && (sender.url || ''));
    let hostname = '';
    try { hostname = new URL(url).hostname; } catch (e) { hostname = ''; }

    chrome.storage.sync.get([STORAGE_KEYS.DETECTOR_CONFIG], (data) => {
      const cfg = data[STORAGE_KEYS.DETECTOR_CONFIG] || DEFAULT_OPTIONS;
      const ignored = cfg.ignoredDomains || DEFAULT_OPTIONS.ignoredDomains || [];
      if (hostname && isDomainIgnored(hostname, ignored)) {
        Log.info('background', `忽略来自 ${hostname} 的 securityIssue 消息`);
        sendResponse({ ignored: true });
        return;
      }

      // 否则记录或处理该告警（当前仅记录日志，可扩展为存储/通知）
      Log.warn('background', `收到安全告警，来源: ${hostname || url}`);
      // 将消息存到本地存储或内存以便 popup 调用（示例：不持久化）
      // TODO: 可将 message 持久化到 chrome.storage
      sendResponse({ ok: true });
    });

    // 表示将异步调用 sendResponse
    return true;
  }
});

// 监听扩展卸载事件，清理资源
chrome.runtime.onSuspend.addListener(() => {
  backgroundService.destroy();
});