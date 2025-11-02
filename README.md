# my-extension

安全处理助手插件 - 自动化XSS漏洞检测工具

## 功能特性

### XSS自动检测
- **智能请求拦截**: 自动监听和拦截所有网络请求
- **多类型载荷**: 包含反射型、DOM型、存储型XSS载荷
- **智能去重**: 避免重复检测相同请求
- **实时通知**: 发现漏洞时自动发送桌面通知

### 检测深度
- **深度1**: 基础反射型XSS载荷
- **深度2**: 扩展载荷 + 绕过技术
- **深度3**: 全量载荷 + 编码载荷

## 项目结构

```
src/
├── core/                    # 核心框架
│   ├── config.js           # 全局配置（标识符、协议等）
│   ├── request-manager.js  # 请求管理（去重、缓存）
│   └── url-utils.js        # URL处理工具（解析、注入）
├── detectors/              # 检测器模块
│   ├── xss-detector.js    # XSS检测器（已完成）
│   ├── tracker-detector.js # 恶意追踪检测（待实现）
│   ├── csrf-detector.js   # CSRF检测（待实现）
│   └── clickjacking-detector.js # 点击劫持检测（待实现）
├── payloads/              # 载荷库
│   ├── xss-payloads.js    # XSS载荷库（已完成）
│   └── tracker-payloads.js # 追踪载荷（待实现）
├── background.js          # 主入口（后台服务）
├── utils/                 # 工具函数
├── popup/                 # 弹窗界面
└── options/              # 选项页面
```

## 核心模块说明

### 1. RequestManager（请求管理器）
- 使用 Chrome webRequest API 拦截所有HTTP/HTTPS请求
- 自动去重，避免重复检测
- 缓存请求信息，支持过期清理

### 2. XssDetector（XSS检测器）
- 解析URL参数
- 注入XSS载荷
- 检测响应中的漏洞
- 支持快速扫描和深度扫描

### 3. Payloads（载荷库）
包含多种XSS测试载荷：
- **基础载荷**: `<script>alert(1)</script>`、`<img src=x onerror=alert(1)>` 等
- **绕过载荷**: 各种编码、大小写混淆、注释绕过等
- **DOM载荷**: DOM型XSS特定载荷

## 使用方法

### 安装开发版
1. 克隆仓库
2. 在Chrome浏览器中打开 `chrome://extensions/`
3. 启用"开发者模式"
4. 点击"加载已解压的扩展程序"
5. 选择项目根目录

### 配置说明
在 `src/core/config.js` 中可以配置：
- `identifier`: 唯一标识符
- `supportAgreement`: 支持的协议
- `xssConfig`: XSS检测配置
  - `enabled`: 是否启用检测
  - `depth`: 检测深度（1-3）
  - `timeout`: 超时时间

## 检测原理

### 反射型XSS检测流程
1. **请求拦截**: 通过 webRequest API 拦截所有请求
2. **参数解析**: 解析URL查询参数
3. **载荷注入**: 将所有参数值替换为XSS载荷
4. **请求发送**: 发送包含载荷的测试请求
5. **响应分析**: 检查响应中是否包含载荷
6. **漏洞报告**: 如发现漏洞，记录并通知用户

### 去重机制
避免检测重复请求：
- 比较 URL、请求类型、方法
- 5秒内的重复请求会被忽略
- 自动清理5分钟以上的过期请求

## 注意事项

⚠️ **安全提醒**:
- 本工具仅供安全测试使用
- 请在授权范围内使用
- 不要在未授权的情况下测试他人网站
- 负载检测功能默认关闭真实请求发送

## 技术栈

- **Chrome Extension Manifest V3**
- **ES6+ JavaScript**
- **Chrome webRequest API**
- **Chrome Notifications API**

## 参考项目

本项目的XSS检测思路参考了 [autoFindXss](https://github.com/BlackHole1/autoFindXssAndCsrf) 项目

## 开发计划

- [x] XSS检测框架
- [x] 请求拦截和去重
- [x] 载荷注入系统
- [ ] UI界面优化
- [ ] CSRF检测
- [ ] 追踪检测
- [ ] 点击劫持检测
- [ ] 漏洞报告导出

## License

MIT