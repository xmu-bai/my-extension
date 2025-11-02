import { Log } from './log';

/**
 * URL 处理工具：解析 URL、提取参数、修改参数、过滤域名等
 * 用于请求拦截、Payload 注入和域名过滤场景
 */

/**
 * 解析 URL 参数为键值对
 * @param url 目标 URL
 * @returns 参数对象（键值对）
 */
export function getUrlParams(url: string): Record<string, string> {
  try {
    const params = new URL(url).searchParams;
    const result: Record<string, string> = {};
    params.forEach((value, key) => {
      result[key] = value;
    });
    return result;
  } catch (error) {
    Log.error('urls', `解析 URL 参数失败（url: ${url}）`, error);
    return {};
  }
}

/**
 * 修改 URL 参数并返回新 URL
 * @param url 原始 URL
 * @param newParams 要修改的参数（键值对，undefined 表示删除）
 * @returns 修改后的 URL
 */
export function setUrlParams(url: string, newParams: Record<string, string | undefined>): string {
  try {
    const urlObj = new URL(url);
    // 遍历新参数，更新或删除
    Object.entries(newParams).forEach(([key, value]) => {
      if (value === undefined) {
        urlObj.searchParams.delete(key);
      } else {
        urlObj.searchParams.set(key, value);
      }
    });
    return urlObj.toString();
  } catch (error) {
    Log.error('urls', `修改 URL 参数失败（url: ${url}）`, error);
    return url; // 失败时返回原始 URL
  }
}

/**
 * 提取 URL 的域名（不含协议和路径）
 * @param url 目标 URL
 * @returns 域名（如 'example.com'）
 */
export function getDomain(url: string): string {
  try {
    return new URL(url).hostname;
  } catch (error) {
    Log.error('urls', `提取域名失败（url: ${url}）`, error);
    return '';
  }
}

/**
 * 判断域名是否在忽略列表中（支持通配符）
 * @param domain 待检测域名（如 'a.example.com'）
 * @param ignoredDomains 忽略列表（如 ['*.example.com', 'localhost']）
 * @returns 是否忽略
 */
export function isDomainIgnored(domain: string, ignoredDomains: string[]): boolean {
  if (!domain || !ignoredDomains.length) return false;

  return ignoredDomains.some(ignored => {
    // 通配符转换为正则（如 '*.example.com' → /.*\.example\.com/）
    const regexStr = ignored
      .replace(/\./g, '\\.') // 转义 .
      .replace(/\*/g, '.*'); // 替换 * 为 .*
    const regex = new RegExp(`^${regexStr}$`);
    return regex.test(domain);
  });
}

/**
 * 判断 URL 是否为 HTTPS 协议
 * @param url 目标 URL
 * @returns 是否为 HTTPS
 */
export function isHttps(url: string): boolean {
  try {
    return new URL(url).protocol === 'https:';
  } catch (error) {
    Log.error('urls', `判断协议失败（url: ${url}）`, error);
    return false;
  }
}