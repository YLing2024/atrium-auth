// ESLint flat config（工程化基线 v1 · 2026-09-30）
//
// 只开「正确性」规则：typescript-eslint 的 recommended（不含类型检查、不含格式）。
// 不引 Prettier / stylistic，避免巨型重排 diff；本仓库无 CSS，故无 Stylelint。
import tseslint from 'typescript-eslint';

// Node 全局：基线要求轻量，不为一个 globals 对象新增依赖，这里手工列内置全局。
// （TS 文件里 no-undef 已被 typescript-eslint 关闭，此表主要服务 .mjs / .js 配置文件。）
const nodeGlobals = {
  require: 'readonly',
  module: 'writable',
  exports: 'writable',
  __dirname: 'readonly',
  __filename: 'readonly',
  process: 'readonly',
  console: 'readonly',
  Buffer: 'readonly',
  global: 'readonly',
  globalThis: 'readonly',
  setTimeout: 'readonly',
  clearTimeout: 'readonly',
  setInterval: 'readonly',
  clearInterval: 'readonly',
  setImmediate: 'readonly',
  clearImmediate: 'readonly',
  queueMicrotask: 'readonly',
  URL: 'readonly',
  URLSearchParams: 'readonly',
  TextEncoder: 'readonly',
  TextDecoder: 'readonly',
  AbortController: 'readonly',
  AbortSignal: 'readonly',
  fetch: 'readonly',
  structuredClone: 'readonly',
  atob: 'readonly',
  btoa: 'readonly',
};

export default tseslint.config(
  {
    ignores: [
      'node_modules/**',
      // lib/totp-auth 是与 admin-server 以 file: 共用的零依赖 JS 模块，
      // 实现必须保持原字节不变，不参与本仓库 lint（改它需另行全局评估）。
      'lib/totp-auth/**',
      'public/**',
    ],
  },
  ...tseslint.configs.recommended,
  {
    files: ['scripts/**/*.js'],
    languageOptions: {
      // 独立测试驱动脚本：CommonJS，零依赖，不在 tsconfig include 内。
      sourceType: 'commonjs',
      globals: { ...nodeGlobals },
    },
    rules: {
      '@typescript-eslint/no-require-imports': 'off',
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    },
  },
  {
    files: ['src/**/*.ts', 'test/**/*.ts'],
    languageOptions: {
      // 本仓库是 CommonJS 单文件后端（零构建），require/module.exports 是既定形态
      sourceType: 'commonjs',
      globals: { ...nodeGlobals },
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // 基线：no-unused-vars 保持 warn，不报错
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      // 全仓库 CommonJS：require() 是既定写法，不是「应改 import」的问题
      '@typescript-eslint/no-require-imports': 'off',
    },
  }
);
