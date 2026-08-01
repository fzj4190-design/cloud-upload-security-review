# 云端上传安全门禁策略

## 1. 判定对象

一次审核必须绑定以下五元组：

1. 上传清单及每个文件的 SHA-256；
2. Git 提交/分支/标签和工作区状态（适用时）；
3. 生产构建产物及其 SHA-256；
4. 目标服务、目标路径和上传方式；
5. 预期可见性、读者名单/群组和保留期。

任一元素变化后重新审核。

## 2. 严重度

### 严重（P0）

- 已确认的私钥、仍有效的密码/令牌/API Key/Cookie/SMTP 授权码。
- 敏感内容已经匿名可下载，或已被未经授权的第三方读取。
- 上传过程会把敏感凭据发送给不可信依赖、脚本、Action 或外部端点。

处理：立即 `BLOCK`。建议撤销或轮换凭据并评估历史暴露；任何外部变更均需用户授权。

### 高危（P1）

- 有效身份证、手机号、私人邮箱、聊天记录、持仓成本或策略等真实隐私/业务数据进入客户端、公开文件或范围过宽的共享目标。
- 高危/严重依赖漏洞、鉴权绕过、静态资源绕过访问控制、公开 ACL 或意外协作者。
- CI 写权限过宽且同时执行未固定 SHA 的第三方代码，或不可信输入可注入高权限 shell。
- Git 历史、制品、日志、Release、备份或分享链接中存在上述内容。

处理：`BLOCK`，整改并重扫。

### 中危（P2）

- bearer token 出现在 URL、依赖未锁定/无哈希、制品保留期过长、权限大于必要范围。
- 中危漏洞、可利用面受限但真实存在的注入/路径/资源耗尽问题。
- 可能为隐私或密钥但尚未完成上下文核验的扫描发现。

处理：默认 `BLOCK`。只有用户明确接受剩余风险、目标范围足够窄且补偿控制可验证时，才可记为例外。

### 低危/信息（P3/P4）

- 不直接造成泄露的加固建议、经过证据确认的假阳性、受信任第三方依赖元数据。

处理：可在报告中保留，不单独阻止 `PASS`。

## 3. 无条件阻断条件

以下任一项成立即 `BLOCK`：

- 扫描器退出码为 `2`，或文件/历史/归档/二进制覆盖不完整。
- 无法实时确认目标云可见性、协作者、匿名访问或静态资源下载权限。
- 存在未解决的 P0/P1；存在未整改且未获明确风险接受的 P2。
- 未对最终构建产物复扫，或实际上传清单与审核清单不一致。
- 必要测试/构建失败，或依赖审计未完成。
- 发现密钥疑似泄露但尚未确认撤销/轮换状态。

## 4. 最低证据

- 本地扫描器的结构化结果与退出码。
- 手工复核记录：被判为假阳性的规则、相对路径、位置和理由；不得抄录原值。
- Git 历史/分支/标签覆盖说明。
- 依赖审计工具、时间、锁文件哈希和漏洞摘要。
- 测试及生产构建命令与结果。
- 云服务实时证据：查询时间、身份、目标 ID、可见性、协作者/共享范围、匿名或最低权限探测结果。
- 最终上传清单、文件哈希、目标和有效期。

## 5. 脱敏格式

每个敏感发现只允许包含：

```text
rule=<类别> severity=<P0-P4> path=<相对路径> location=<行号或成员名> fingerprint=sha256:<前12位>
```

不得包含匹配原文、前后文、密钥首尾字符或可逆编码。需要确认两个位置是否为同一密钥时，只比较本地计算的不可逆指纹。

## 6. 最终报告模板

```markdown
# 云端上传安全审核

- Verdict: PASS | BLOCK
- Audit ID: CUR-YYYYMMDD-HHMM-<hash-prefix>
- Audited at: <Asia/Shanghai timestamp>
- Valid until: <24 hours later; BLOCK 可不填>
- Scope: <manifest/hash or commit>
- Destination: <service/object/path>
- Intended visibility: <private/readers/public>
- Upload authorized by user: yes | no

## Coverage
- Current files: complete | incomplete
- Hidden/ignored files: complete | incomplete | n/a
- Git history/branches/tags: complete | incomplete | n/a
- Generated/client artifacts: complete | incomplete | n/a
- Binary/archive contents and metadata: complete | incomplete | n/a
- Dependencies/workflows: complete | incomplete | n/a
- Live cloud visibility/download test: complete | incomplete

## Findings
<脱敏发现、严重度、证据和状态；没有则写 none>

## Tests
<命令、结果、构建后复扫结果>

## Decision
<为何 PASS 或必须 BLOCK；列出剩余限制>
```

## 7. PASS 的边界

- 有效期最长 24 小时。
- 仅对报告中的内容、目的地、方式和权限有效。
- `PASS` 不是上传授权；没有明确授权时必须停在报告交付处。
- 上传完成后应校验远端哈希/提交和权限。远端不一致时撤销本次 `PASS` 并报告，不得静默继续。
