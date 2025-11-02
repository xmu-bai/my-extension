import { EXTENSION_INFO } from '../config/constants';

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

// 移除process.env依赖，使用固定级别
const currentLevel: LogLevel = 'info'; // 默认级别

const levelWeight: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3
};

function log(level: LogLevel, module: string, message: string, ...args: any[]) {
  if (levelWeight[level] < levelWeight[currentLevel]) return;
  const prefix = `[${EXTENSION_INFO.NAME}][${module}][${new Date().toISOString().slice(11, 19)}][${level}]`;
  switch (level) {
    case 'debug': console.debug(prefix, message, ...args); break;
    case 'info': console.info(prefix, message, ...args); break;
    case 'warn': console.warn(prefix, message, ...args); break;
    case 'error': console.error(prefix, message, ...args); break;
  }
}

export const Log = {
  debug: (module: string, message: string, ...args: any[]) => log('debug', module, message, ...args),
  info: (module: string, message: string, ...args: any[]) => log('info', module, message, ...args),
  warn: (module: string, message: string, ...args: any[]) => log('warn', module, message, ...args),
  error: (module: string, message: string, ...args: any[]) => log('error', module, message, ...args)
};