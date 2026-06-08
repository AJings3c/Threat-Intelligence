# Threat Intelligence Platform Design

## 1. 产品定位

Threat Intelligence Platform 是一个面向安全运营人员、威胁情报分析师、应急响应人员和红蓝队研究人员的证据型威胁情报工作台。

产品目标不是做装饰性大屏，也不是营销页，而是在一个可信、紧凑、可追溯的界面中完成这些工作：

- 查看当前情报源健康、数量、时间和异常状态。
- 检索 IP、域名、URL、Hash、CIDR、CVE 等 IOC。
- 基于当前项目已接入的情报来源生成证据链、STRIDE/DREAD 威胁模型和 Graph。
- 检查情报源、富化服务、通知能力的配置状态并执行测试。
- 过滤、查看、导出可解释的威胁情报数据。

产品的核心价值是：让分析人员在不离开工作台的情况下完成“发现、验证、关联、建模、导出”的闭环。

## 2. 用户与使用场景

主要用户：

- SOC 值班人员：快速判断当前情报源是否健康，筛选高危 IOC。
- 威胁情报分析师：检索 IOC，查看来源、置信度、参考链接和相关指标。
- 应急响应人员：围绕 CVE、恶意 URL、Hash 或网络段建立处置线索。
- 红蓝队研究人员：基于公开情报源和本地数据理解攻击路径、资产影响和缓解建议。

典型场景：

- 开始值班时查看 Overview，确认情报源和核心指标是否正常。
- 配置或排障时进入 Sources & Config，检查 API token、公开源、富化源和通知状态。
- 拿到一个 IOC 后进入 Investigation，查看精确匹配、关联指标、STRIDE 场景、Graph 和导出报告。
- 做系统级分析时进入 Threat Modeling，查看资产、数据流、信任边界、攻击路径和控制措施。
- 做批量筛选时进入 Intel Feed，根据来源、类型、严重性和关键词定位情报。

## 3. 产品原则

- 证据优先：任何结论都应尽量靠近来源、置信度、可靠性、TLP、时间戳和参考链接。
- 配置可见：每个情报源和集成都必须有配置态、测试态、缺失项和错误态。
- 工作流连续：搜索、富化、关联、建模、导出必须在同一个调查路径内完成。
- 密集但可读：优先使用表格、矩阵、分组面板和明确层级，而不是大面积装饰。
- 不虚构来源：Graph、威胁模型和建议只能基于当前项目已有情报源与后端接口。
- 失败要明确：区分未配置、上游错误、数据为空、加载中和测试失败。

## 4. 信息架构

项目采用 5 个工作区，通过 URL hash 深链管理：

- Overview：源健康、核心指标、地图、CVE、趋势、Hash/Malware 总览。
- Sources & Config：情报源矩阵、配置检查、单源测试、富化服务测试、通知测试。
- Investigation：IOC 命令区、证据、关联指标、STRIDE 场景、缓解建议、Graph/List、导出。
- Threat Modeling：架构威胁模型、资产、数据流、信任边界、STRIDE/DREAD、攻击路径、控制项。
- Intel Feed：筛选器、情报表格、行选中、详情侧栏、参考链接。

首屏应优先呈现当前工作区、配置状态和最近刷新时间。长内容放在工作区内部，不把所有模块堆成单一长滚动页面。

## 5. 视觉语言

整体风格：克制、可靠、运营型、安全控制台。

色彩策略：

- 背景：支持深色与浅色两种运营工作台主题。深色用于低光/值班环境，浅色用于白天办公和长时间阅读。两种主题都使用冷中性底，避免赛博朋克、高饱和渐变和装饰性光效。
- Surface：使用 `surface`、`surface-raised` 区分普通面板和强调面板。
- Accent：青绿色用于当前选中、主操作、健康状态和关键聚焦，不作为大面积装饰。
- Focus：浅蓝色只用于键盘焦点和交互边界。
- Severity：红色、琥珀色、绿色仅表达严重性和状态，不用于装饰。

图标策略：

- 使用 lucide-react 的线性图标，保持同一笔画风格。
- 不使用盾牌类图标作为品牌、指标或状态图标。
- 品牌 logo 统一使用 `frontend/public/brand-logo.png`，favicon、桌面侧边栏品牌位和移动端顶部品牌位必须保持一致。
- 深色模式使用 `frontend/public/brand-logo-dark.png`，浅色模式使用 `frontend/public/brand-logo-light.png`。
- 调查入口和功能导航使用 Radar、Network、Database、Activity 等证据/运营语义图标，不把功能图标当作品牌 logo。
- 图标只辅助识别，不能替代文字状态。

Logo 主题策略：

- 主题由用户显式切换，默认深色，并写入 `localStorage.theme`。
- UI 品牌位按主题切换 logo，不使用 CSS filter 临时反色。
- favicon 与 apple touch icon 跟随当前主题同步更新。
- 浅色模式下 logo 线条必须使用更深的 teal，保证在浅色表面上清晰可读。

排版：

- 使用系统无衬线字体栈，保持工具型产品的熟悉感。
- 工作区标题控制在 24-30px，不使用营销页式超大标题。
- 表格、标签、指标使用稳定字号和数字等宽特性，方便扫描。
- 中英文文案保持语义一致，避免英文短句和中文长句造成布局失衡。

空间与形状：

- 卡片圆角控制在 8px 左右。
- 避免卡片套卡片，页面分区使用面板、表格和 full-width band。
- 控件高度保持 40-44px 以上，移动端可触达。

## 6. 组件规范

核心组件：

- AppShell：左侧桌面导航、移动端顶部导航、sticky command/header。
- WorkspaceNav：5 个工作区切换，支持当前态和 hash 深链。
- StatusMetric：当前工作区、已配置来源、最近刷新等状态指标。
- SourceHealthBar：展示来源健康、数量、最近刷新和历史点。
- ConfigStatusPanel：配置检查、单源测试、Provider 测试、通知测试。
- IocInvestigationPanel：IOC 查询、证据、关联、enrichment、导出、Graph/List。
- ArchitectureThreatModelPanel：架构模型、Graph/List、场景、资产、控制项。
- ThreatTable：过滤表格、行选中、详情侧栏、参考链接。
- GraphDiagram：React Flow 图视图，必须提供列表备用视图。

交互状态：

- 所有按钮要有 default、hover、active、disabled、loading、focus-visible。
- 所有异步操作要显示加载或测试中状态。
- 错误以 inline alert 呈现，说明失败原因。
- 空状态要说明当前为空的原因和下一步可做什么。

## 7. 功能清单

数据总览：

- 展示总 IOC、CVE 数量、严重性分布、主要国家/地区、趋势。
- 展示全球威胁地图、近期 CVE、Hash/Malware 情报。

情报源与配置：

- 展示 CISA KEV、abuse.ch Feodo Tracker、URLhaus、ThreatFox、MalwareBazaar、OpenPhish、Spamhaus DROP、SANS ISC DShield、NVD CVE 等来源状态。
- 展示 X、Facebook、PhishTank、AbuseIPDB、AlienVault OTX、External TAXII 等可选配置状态。
- 支持配置检查、单源测试、富化服务测试、通知测试。

IOC 调查：

- 支持 domain、IP、URL、hash、CIDR、CVE 检索。
- 展示精确匹配、关联指标、来源汇总、置信度、严重性和可靠性。
- 支持本地威胁建模、STRIDE 场景、缓解建议、下一步行动。
- 支持 Markdown 和 JSON 导出。
- 支持 Graph/List 切换，Graph 只使用当前项目数据生成。

威胁建模：

- 展示架构资产、数据流、信任边界、攻击路径和控制措施。
- 使用 STRIDE 进行威胁分类，使用 DREAD 展示评分。
- 支持刷新模型和 Markdown 导出。
- 支持 Graph/List 双视图，图形不可替代列表信息。

情报列表：

- 支持按来源、类型、严重性、关键词过滤。
- 表格展示 severity、indicator、type、source、country、last seen。
- 选中行后展示详情，包括描述、标签、TLP、置信度、可靠性、参考链接。

## 8. 响应式与可访问性

响应式：

- 桌面端使用左侧导航和主工作区。
- 移动端使用顶部品牌区、命令区和横向工作区导航。
- 375px 以上不应出现页面级横向滚动。
- 表格和 Graph 可以在局部区域处理密集内容，但页面整体不能溢出。

可访问性：

- 文本对比度目标达到 WCAG 2.1 AA。
- 所有图标按钮必须有文字、aria-label 或可理解的上下文。
- 颜色不能作为唯一状态信号，必须有文字标签或数值。
- 支持键盘 Tab 顺序和清晰 focus ring。
- 动效控制在 150-250ms，并尊重 `prefers-reduced-motion`。

## 9. 文案语气

中文：直接、准确、偏运营语气，不使用夸张营销词。

英文：短句优先，强调 source、evidence、confidence、model、export 等行动词。

禁止：

- “下一代”“颠覆式”“全能 AI 安全大脑”等泛化文案。
- 把未配置或缺失数据写成成功。
- 用模糊话术掩盖来源、置信度或错误状态。

## 10. 设计验收

每次 UI 改动至少验证：

- `npm run typecheck`
- `npm run lint`
- `npm run build`
- 桌面 1440px 和移动 390px 页面无横向溢出。
- Overview、Sources、Investigation、Threat Modeling、Intel Feed 的核心内容可见。
- IOC Graph 和架构 Graph 非空，并能切换到 List。
- 中文和英文都能正常显示。
- 浏览器 console 无 error。
