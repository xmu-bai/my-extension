import { DEFAULT_DETECTION_RULES, DETECTION_LEVEL_RULES } from './constants';

/**
 * 可配置选项的类型定义（接口）
 * 约束检测功能的可配置项，确保前后端（选项页/后台）类型一致
 */
export interface XssDetectorOptions {
  // 是否启用自动检测（核心开关）
  enabled: boolean;
  // 检测级别（low/medium/high，对应不同的 payload 策略）
  detectionLevel: keyof typeof DETECTION_LEVEL_RULES;
  // 需要检测的请求方法（继承默认规则，可由用户修改）
  targetMethods: Array<typeof DEFAULT_DETECTION_RULES.TARGET_METHODS[number]>;
  // 是否在检测到漏洞时显示浏览器通知
  showNotification: boolean;
  // 是否忽略 HTTPS 网站（默认不忽略，因 HTTPS 也可能存在 XSS）
  ignoreHttps: boolean;
  // 忽略的域名列表（如本地开发域名，不进行检测）
  ignoredDomains: string[];
  // 是否记录检测历史（漏洞记录是否持久化）
  recordHistory: boolean;
  // 历史记录保留天数
  historyRetentionDays: number;
}

/**
 * 默认配置项
 * 当用户未修改配置时，使用此默认值初始化
 */
export const DEFAULT_OPTIONS: XssDetectorOptions = {
  enabled: true, // 默认启用检测
  detectionLevel: 'MEDIUM', // 默认中等检测级别
  targetMethods: [...DEFAULT_DETECTION_RULES.TARGET_METHODS], // 默认检测 GET/POST
  showNotification: true, // 默认显示通知
  ignoreHttps: false, // 不忽略 HTTPS
  ignoredDomains: ['localhost', '127.0.0.1', '*.local'], // 默认忽略本地域名
  recordHistory: true, // 默认记录历史
  historyRetentionDays: 30 // 历史记录保留 30 天
};

/**
 * 验证用户配置是否合法（避免无效配置导致功能异常）
 * @param options 用户提交的配置
 * @returns 验证后的合法配置（无效项替换为默认值）
 */
export function validateOptions(options: Partial<XssDetectorOptions>): XssDetectorOptions {
  // 基础验证：确保配置不为空
  if (!options) return DEFAULT_OPTIONS;

  return {
    // 验证 enabled（必须为 boolean）
    enabled: typeof options.enabled === 'boolean' ? options.enabled : DEFAULT_OPTIONS.enabled,
    // 验证检测级别（必须是预定义的 key）
    detectionLevel: Object.keys(DETECTION_LEVEL_RULES).includes(options.detectionLevel as string)
      ? (options.detectionLevel as keyof typeof DETECTION_LEVEL_RULES)
      : DEFAULT_OPTIONS.detectionLevel,
    // 验证请求方法（必须是默认方法的子集）
    targetMethods: options.targetMethods?.every(method => 
      DEFAULT_DETECTION_RULES.TARGET_METHODS.includes(method)
    ) 
      ? options.targetMethods 
      : DEFAULT_OPTIONS.targetMethods,
    // 验证通知开关
    showNotification: typeof options.showNotification === 'boolean' 
      ? options.showNotification 
      : DEFAULT_OPTIONS.showNotification,
    // 验证 HTTPS 忽略开关
    ignoreHttps: typeof options.ignoreHttps === 'boolean' 
      ? options.ignoreHttps 
      : DEFAULT_OPTIONS.ignoreHttps,
    // 验证忽略的域名（必须是字符串数组）
    ignoredDomains: Array.isArray(options.ignoredDomains) 
      ? options.ignoredDomains.filter(domain => typeof domain === 'string') 
      : DEFAULT_OPTIONS.ignoredDomains,
    // 验证历史记录开关
    recordHistory: typeof options.recordHistory === 'boolean' 
      ? options.recordHistory 
      : DEFAULT_OPTIONS.recordHistory,
    // 验证历史保留天数（必须是正数）
    historyRetentionDays: typeof options.historyRetentionDays === 'number' 
      && options.historyRetentionDays > 0 
      ? options.historyRetentionDays 
      : DEFAULT_OPTIONS.historyRetentionDays
  };
}