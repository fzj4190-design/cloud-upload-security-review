# cloud-upload-security-review

一个在文件离开本机前执行失败关闭安全门禁的 Codex Skill，检查密钥、个人资料、真实业务数据、Git 历史、构建产物、归档、依赖、CI 权限和云端下载范围，并输出 `PASS` 或 `BLOCK`。

## Provenance

本项目由 OpenAI Codex（AI）根据公开网络安全案例、标准和公告整理生成，生成与研究整理日期为 2026-08-01。它不是安全认证、渗透测试或法律意见；规则需要结合目标服务和实际权限重新验证。完整来源与归属见 [SOURCES.md](SOURCES.md)。

## Quick start

```powershell
python scripts/preflight_scan.py <exact-upload-path> --json
python scripts/preflight_scan.py --self-test
```

脚本只做本地预扫描，退出码 `0` 表示没有脚本层阻断项，`1` 表示发现待处理项，`2` 表示覆盖不完整或运行失败。最终 `PASS` 还必须完成 Git 历史、依赖、构建产物和目标云端可下载性核查；权限无法实时核实时必须 `BLOCK`。

## Package contents

- `SKILL.md`：触发边界、审核流程、权限规则和完成契约。
- `scripts/preflight_scan.py`：无第三方依赖、脱敏、失败关闭的本地扫描器。
- `references/gate-policy.md`：严重度、证据要求和报告模板。
- `SOURCES.md`：公开来源和案例说明。
- `LICENSE`：MIT 许可证。

## Safety boundary

本 Skill 默认只读；它不会替用户上传、删除、清理 Git 历史、轮换密钥或修改云权限。安全审核通过也不等于获得上传授权。
