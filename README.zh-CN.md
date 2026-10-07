# Toolwrit

[English](README.md) · [Deutsch](README.de.md) · **简体中文** · [日本語](README.ja.md) · [Español](README.es.md)

**AI 智能体的书面授权。** 限定可用工具，封顶预算，证明发生了什么。

Apache-2.0 · Node >= 20 · Python >= 3.10

> 本页为简要版。以[英文 README](README.md) 为准，完整的策略参考、API 与威胁模型均在其中。

## 问题

拥有工具权限的智能体，就拥有这些工具的全部能力。`fs.write` 是写文件，`billing.refund` 是退款——而由模型决定何时调用。写在提示词里的规则（"不要碰工作区以外的文件"）只是建议：它们处在攻击者或犯迷糊的模型同样能控制的文本通道里。

Toolwrit 把决策放在**模型之外**：每次调用在执行前都按 YAML 策略检查，未明确允许的一律拒绝，每个决定都写入防篡改日志。决策路径中没有模型，因此没有可以被"越狱"的提示词。

Toolwrit 是**库和旁路进程（sidecar），不是网关**。你的流量不会离开你自己的基础设施。

## 60 秒上手

```
npm install toolwrit
pip install "git+https://github.com/emektor/toolwrit.git#subdirectory=python"
```

**`toolwrit.yaml`**

```yaml
version: "1"
default: deny

budget:
  calls: 50
  usd: 2.00

rules:
  - id: read-workspace
    tools: ["fs.read", "fs.list"]
    effect: allow
    when:
      path:
        startsWith: ["/srv/workspace/"]
        excludes: [".."]

  - id: no-secrets
    tools: ["fs.*"]
    effect: deny
    when:
      path:
        matches: "\\.env|id_rsa"
```

**在代码中**——包住现有的工具调用：

```ts
import { Toolwrit, loadPolicyFile } from 'toolwrit';

const toolwrit = new Toolwrit({ policy: loadPolicyFile('./toolwrit.yaml'), auditFile: './audit.jsonl' });
const result = await toolwrit.guard(name, args, () => tools[name](args));
```

**无需改代码**——放在已有的 MCP 服务器前面：

```
toolwrit run --policy toolwrit.yaml -- npx @modelcontextprotocol/server-filesystem /srv/workspace
```

## 功能

- **默认拒绝。** 只有明确允许的工具和参数才能通过；多条规则同时匹配时，deny 优先于 ask，ask 优先于 allow。
- **预算。** 每次运行的调用次数、token、美元和字节上限，并可设置预警阈值。
- **哈希链审计日志。** 修改任何一条记录，其后所有哈希都会失效。`toolwrit verify audit.jsonl`
- **防截断锚点。** 被截掉尾部的有效链仍然是有效链。`toolwrit anchor` 记录链头哈希，`toolwrit verify --against` 能发现缺失的尾部。
- **RFC 3161 时间戳。** `toolwrit anchor --tsa` 让外部时间戳机构（默认 DigiCert，免费）对链头签名。凭证无法伪造或倒签；`verify --max-lag` 可识别事后重写的日志。无需 Toolwrit 也可验证：`openssl ts -verify -digest <head> ...`
- **TypeScript 与 Python** 生成完全相同的哈希，一种语言写的日志可用另一种语言验证。仅一个运行时依赖。

## 它不做什么

Toolwrit 不读取提示词或模型输出，不过滤网络出口流量，也无法在自身主机被攻破后继续提供保护。时间戳证明的是链头*何时*存在，而不是实际发生了什么。详见[威胁模型](js/docs/threat-model.md)。

## 商业支持

集成、定制策略或移植到其他语言：[erginsakoglu@gmail.com](mailto:erginsakoglu@gmail.com)

许可证：Apache 2.0。
