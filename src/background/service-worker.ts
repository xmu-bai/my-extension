import { DEFAULT_DETECTION_RULES } from '../config/constants';
import { Log } from '../utils/log';

export interface RequestInfo {
  id: string;
  url: string;
  method: string;
  payload: string;
  timestamp: number;
}

export class BackgroundService {
  private requestList = new Map<string, RequestInfo>();
  private cleanupInterval: NodeJS.Timeout;

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

// 监听扩展卸载事件，清理资源
chrome.runtime.onSuspend.addListener(() => {
  backgroundService.destroy();
});