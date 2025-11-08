import { Log } from './log';

/// <reference types="chrome" />

type StorageArea = 'sync' | 'local';

export async function get<T>(key: string, area: StorageArea = 'sync'): Promise<T | undefined> {
  try {
    const storage = chrome.storage[area];
    const result = await new Promise<{ [key: string]: T }>((resolve) => {
      storage.get(key, resolve);
    });
    return result[key];
  } catch (error) {
    Log.error('storage', `获取存储失败（key: ${key}）`, error);
    return undefined;
  }
}

export async function set<T>(key: string, value: T, area: StorageArea = 'sync'): Promise<boolean> {
  try {
    const storage = chrome.storage[area];
    await new Promise<void>((resolve) => {
      storage.set({ [key]: value }, () => resolve());
    });
    Log.debug('storage', `存储成功（key: ${key}）`);
    return true;
  } catch (error) {
    Log.error('storage', `设置存储失败（key: ${key}）`, error);
    return false;
  }
}

// 添加缺失的add方法
export async function add<T>(key: string, value: T, area: StorageArea = 'sync'): Promise<boolean> {
  try {
    const existing = await get<T[]>(key, area) || [];
    existing.push(value);
    return await set(key, existing, area);
  } catch (error) {
    Log.error('storage', `添加存储失败（key: ${key}）`, error);
    return false;
  }
}

// 添加缺失的clear方法
export async function clear(area: StorageArea = 'sync'): Promise<boolean> {
  try {
    const storage = chrome.storage[area];
    await new Promise<void>((resolve) => {
      storage.clear(() => resolve());
    });
    Log.debug('storage', '存储已清空');
    return true;
  } catch (error) {
    Log.error('storage', '清空存储失败', error);
    return false;
  }
}

export const Storage = { get, set, add, clear };