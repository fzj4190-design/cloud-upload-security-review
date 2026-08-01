# Sources and provenance

本文件记录本 Skill 规则的公开依据。它们是设计输入，不是对目标项目安全状态的证明。链接和版本可能变化；使用 Skill 时应重新核对目标服务的当前文档和公告。

## AI 编码与应用安全研究

- [NIST Secure Software Development Framework (SSDF)](https://csrc.nist.gov/projects/ssdf) — 将安全实践纳入软件开发生命周期的官方框架。
- [OWASP LLM05: Improper Output Handling](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/) — 模型输出进入 shell、SQL、HTML、文件系统等解释器前需要校验和编码。
- [MITRE CWE Top 25, 2025](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html) — 常见软件弱点的官方排序资料。
- [Asleep at the Keyboard?](https://arxiv.org/abs/2108.09293) — 2021 年对生成程序安全性的学术研究；约 40% 样本被判定含漏洞，具体含义以论文方法为准。
- [A Large-Scale Study of AI-Generated Code on GitHub](https://arxiv.org/abs/2510.26103) — 2025 年 GitHub 样本研究，报告 CWE 分布和代码质量结果。
- [Do Large Language Models Know What They Don't Know? Package Hallucination](https://arxiv.org/abs/2406.10279) — 包名幻觉和依赖供应链风险研究。
- [Can AI Assistants Review AI-Generated Code?](https://arxiv.org/abs/2509.13650) — 关于 AI 代码审查遗漏 SQL 注入、XSS 和不安全反序列化的研究。

## 云平台、CI 和供应链官方资料

- [GitHub: About repositories](https://docs.github.com/en/repositories/creating-and-managing-repositories/about-repositories) — 仓库可见性和读者边界。
- [GitHub: Downloading source code archives](https://docs.github.com/en/repositories/working-with-files/using-files/downloading-source-code-archives) — 读者可取得源码归档的规则。
- [GitHub: Secret scanning](https://docs.github.com/en/code-security/concepts/secret-security/secret-scanning) — 密钥扫描能力与限制。
- [GitHub Actions: Secure use](https://docs.github.com/en/actions/reference/security/secure-use?learn=getting_started) — 最小权限、Action 固定和 secrets 边界。
- [GitHub Actions: Script injections](https://docs.github.com/en/actions/concepts/security/script-injections) — 不可信上下文直接插入 shell 的风险。
- [GitHub Actions: Artifact downloads](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/download-workflow-artifacts?tool=webui) — 制品下载权限和保留期。
- [OSV](https://osv.dev/) — 开源依赖漏洞数据库；使用时按实际锁定版本查询。

## 公开漏洞公告

- [Next.js middleware/proxy bypass](https://github.com/advisories/GHSA-6gpp-xcg3-4w24) — 说明升级和鉴权绕过核查的必要性。
- [Next.js SSRF](https://github.com/advisories/GHSA-89xv-2m56-2m9x) — 说明自定义服务器和 Server Actions 的 SSRF 核查。
- [sharp/libvips inherited vulnerabilities](https://github.com/advisories/GHSA-f88m-g3jw-g9cj) — 说明图片处理依赖需要精确版本审计。
- [brace-expansion denial of service](https://github.com/advisories/GHSA-mh99-v99m-4gvg) — 说明传递依赖和资源耗尽审计。
- [Requests CVE-2026-25645](https://github.com/advisories/GHSA-gc5v-m9x4-r6x2) — 说明 Python 依赖按实际调用路径和精确版本复核。
- [Pillow heap out-of-bounds write](https://github.com/advisories/GHSA-xj96-63gp-2gmr) — 说明图像解析/生成依赖的升级与输入边界审计。

## 厂商案例（明确标注为厂商自有研究）

以下是 Wiz 自行披露的研究和事件报告，不代表普遍统计结论；Skill 只把其中的风险模式转化为检查项：

- [Common security risks in vibe-coded apps](https://www.wiz.io/blog/common-security-risks-in-vibe-coded-apps) — 客户端鉴权、JavaScript Key、开放数据库规则、PII 和公开内部应用。
- [Base44 critical vulnerability](https://www.wiz.io/blog/critical-vulnerability-base44) — 低代码应用鉴权绕过案例；报告称及时修复且未发现被利用证据。
- [State of Code Security Report 2025](https://www.wiz.io/blog/state-of-code-security-report-2025) — Wiz 对其扫描数据的观察，不能外推为所有组织的比例。
- [Exposed MCP servers](https://www.wiz.io/blog/the-risk-hiding-behind-exposed-mcp-servers) — 暴露 MCP 端点和工具清单的风险模式。

## Research note

来源整理时间：2026-08-01（Asia/Shanghai）。本项目由 OpenAI Codex（AI）生成和整理，用户负责最终发布决策；贡献者应在更新规则时补充来源、日期和适用范围，不应把 AI 生成内容当作独立安全认证。
