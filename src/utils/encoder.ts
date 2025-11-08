/**
 * 编码/解码工具：提供 HTML、URL 等场景的编码和解码功能
 * 用于 Payload 生成（避免注入异常）和响应解析（检测未过滤内容）
 */

/**
 * HTML 编码：将特殊字符转换为实体，避免注入时破坏页面结构
 * @param str 原始字符串
 * @returns 编码后的字符串
 */
export function htmlEncode(str: string): string {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
    .replace(/`/g, '&#x60;')
    .replace(/=/g, '&#x3D;');
}

/**
 * HTML 解码：将实体转换为原始字符，用于解析响应中的潜在 Payload
 * @param str 编码后的字符串
 * @returns 解码后的原始字符串
 */
export function htmlDecode(str: string): string {
  if (!str) return '';
  const el = document.createElement('div');
  el.innerHTML = str;
  return el.textContent || '';
}

/**
 * URL 编码：对参数值进行编码，适用于 GET/POST 参数注入
 * @param str 原始字符串
 * @returns 编码后的字符串（RFC 3986 标准）
 */
export function urlEncode(str: string): string {
  return encodeURIComponent(str)
    .replace(/!/g, '%21')
    .replace(/'/g, '%27')
    .replace(/\(/g, '%28')
    .replace(/\)/g, '%29')
    .replace(/\*/g, '%2A');
}

/**
 * URL 解码：解析 URL 中的参数值
 * @param str 编码后的字符串
 * @returns 解码后的原始字符串
 */
export function urlDecode(str: string): string {
  return decodeURIComponent(str);
}

/**
 * 混淆编码：简单的字符替换混淆，用于绕过基础过滤规则
 * @param str 原始字符串
 * @returns 混淆后的字符串
 */
export function obfuscateEncode(str: string): string {
  // 示例：替换部分字符为 Unicode 相似字符（如 's' → '𝐬'）
  const map: Record<string, string> = {
    's': '𝐬',
    'c': '𝐜',
    'r': '𝐫',
    'i': '𝐢',
    'p': '𝐩',
    't': '𝐭',
    'a': '𝐚',
    'l': '𝐥',
    'e': '𝐞'
  };
  return str.split('').map(char => map[char] || char).join('');
}