/**
 * XSS 检测核心常量
 * 替代原项目中分散的硬编码标识（如 identifier）、规则参数等
 */

// 1. 检测标识基础字符串（用于生成唯一 payload，避免与正常内容冲突）
export const XSS_DETECT_BASE_IDENTIFIER = 'xss_auto_detect_'; // 前缀
export const XSS_PAYLOAD_MARKER = '<!--xss_detected-->'; // 响应中检测到漏洞的标记

// 2. 存储相关键名（统一管理 chrome.storage 中的键，避免拼写错误）
export const STORAGE_KEYS = {
  DETECTOR_CONFIG: 'xss_detector_config', // 检测配置存储键
  VULNERABILITY_HISTORY: 'xss_vulnerability_history', // 漏洞历史存储键
  IGNORED_DOMAINS: 'xss_ignored_domains' // 忽略的域名列表存储键
};

// 3. 默认检测规则常量
export const DEFAULT_DETECTION_RULES = {
  // 需要注入 payload 的请求方法（GET/POST 等）
  TARGET_METHODS: ['GET', 'POST'] as const,
  // 敏感参数名（优先对这些参数注入 payload，如用户输入相关）
  SENSITIVE_PARAMS: ['q', 'search', 'input', 'username', 'comment', 'content'] as const,
  // payload 最大长度（避免注入过长内容导致请求异常）
  MAX_PAYLOAD_LENGTH: 200,
  // 请求过期时间（毫秒，与 background 中的清理逻辑对应）
  REQUEST_EXPIRE_TIME: 5 * 60 * 1000 // 5分钟
};

// 4. 检测级别对应规则（不同级别使用不同的 payload 策略）
export const DETECTION_LEVEL_RULES = {
  LOW: {
    payloadType: ['basic'] as const, // 仅基础 payload（如 <script>alert</script>）
    skipLargeRequests: true // 跳过大于 1MB 的请求
  },
  MEDIUM: {
    payloadType: ['basic', 'encoded'] as const, // 基础 + 编码 payload（如 &lt;script&gt;）
    skipLargeRequests: false
  },
  HIGH: {
    payloadType: ['basic', 'encoded', 'obfuscated'] as const, // 基础 + 编码 + 混淆 payload
    skipLargeRequests: false
  }
};

// 5. 扩展相关常量
export const EXTENSION_INFO = {
  NAME: 'auto-find-xss',
  VERSION: '1.0.0',
  AUTHOR: 'Black-Hole'
};