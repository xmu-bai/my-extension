<<<<<<< HEAD
import { defineConfig } from 'rollup';
import typescript from '@rollup/plugin-typescript';
import commonjs from '@rollup/plugin-commonjs';
import resolve from '@rollup/plugin-node-resolve';
import replace from '@rollup/plugin-replace';
import css from 'rollup-plugin-css-only';
import terser from 'rollup-plugin-terser';
import path from 'path';

// 模块入口配置
const modules = {
  'background': 'src/background/service-worker.ts',
  'content-scripts': 'src/content-scripts/injector.ts',
  'options': 'src/options/index.tsx',
  'popup': 'src/popup/index.tsx'
};

// 获取当前要构建的模块（默认全量构建）
const targetModule = process.env.MODULE;
const entries = targetModule 
  ? { [targetModule]: modules[targetModule] } 
  : modules;

export default defineConfig({
  input: entries,
  output: {
    dir: 'dist',
    format: 'iife', // 适合浏览器环境的立即执行函数
    sourcemap: process.env.NODE_ENV !== 'production', // 开发环境生成 sourcemap
    entryFileNames: '[name]/[name].js' // 输出路径：dist/模块名/模块名.js
  },
  plugins: [
    // 解析第三方模块
    resolve({ browser: true }),
    // 转换 CommonJS 模块为 ES 模块
    commonjs(),
    // 处理 TypeScript/TSX
    typescript({
      tsconfig: './tsconfig.json',
      jsx: 'react' // 支持 JSX 语法
    }),
    // 提取 CSS 到单独文件
    css({ output: (name) => `dist/${name.split('/')[0]}/${name.split('/')[0]}.css` }),
    // 环境变量替换
    replace({
      'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV || 'development'),
      preventAssignment: true
    }),
    // 生产环境压缩
    process.env.NODE_ENV === 'production' && terser()
  ]
=======
import { defineConfig } from 'rollup';
import typescript from '@rollup/plugin-typescript';
import commonjs from '@rollup/plugin-commonjs';
import resolve from '@rollup/plugin-node-resolve';
import replace from '@rollup/plugin-replace';
import css from 'rollup-plugin-css-only';
import terser from 'rollup-plugin-terser';
import path from 'path';

// 模块入口配置
const modules = {
  'background': 'src/background/service-worker.ts',
  'content-scripts': 'src/content-scripts/injector.ts',
  'options': 'src/options/index.tsx',
  'popup': 'src/popup/index.tsx'
};

// 获取当前要构建的模块（默认全量构建）
const targetModule = process.env.MODULE;
const entries = targetModule 
  ? { [targetModule]: modules[targetModule] } 
  : modules;

export default defineConfig({
  input: entries,
  output: {
    dir: 'dist',
    format: 'iife', // 适合浏览器环境的立即执行函数
    sourcemap: process.env.NODE_ENV !== 'production', // 开发环境生成 sourcemap
    entryFileNames: '[name]/[name].js' // 输出路径：dist/模块名/模块名.js
  },
  plugins: [
    // 解析第三方模块
    resolve({ browser: true }),
    // 转换 CommonJS 模块为 ES 模块
    commonjs(),
    // 处理 TypeScript/TSX
    typescript({
      tsconfig: './tsconfig.json',
      jsx: 'react' // 支持 JSX 语法
    }),
    // 提取 CSS 到单独文件
    css({ output: (name) => `dist/${name.split('/')[0]}/${name.split('/')[0]}.css` }),
    // 环境变量替换
    replace({
      'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV || 'development'),
      preventAssignment: true
    }),
    // 生产环境压缩
    process.env.NODE_ENV === 'production' && terser()
  ]
>>>>>>> 2446077043e6c3be5469c271869b150589903a43
});