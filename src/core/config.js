// 生成唯一标识符（用于XSS检测）
export const identifier = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

// 支持的HTTP协议
export const supportAgreement = [
  'http://*/*',
  'https://*/*'
];

// 支持的请求类型
export const supportType = [
  'main_frame',
  'sub_frame',
  'script',
  'xmlhttprequest'
];

// 支持的HTTP方法
export const supportMethods = [
  'GET',
  'POST',
  'PUT',
  'DELETE',
  'PATCH'
];

// XSS检测配置
export const xssConfig = {
  // 是否启用自动检测
  enabled: true,
  // 检测深度（1-3）
  depth: 1,
  // 超时时间（毫秒）
  timeout: 5000
};
