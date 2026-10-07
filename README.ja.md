# Toolwrit

[English](README.md) · [Deutsch](README.de.md) · [简体中文](README.zh-CN.md) · **日本語** · [Español](README.es.md)

**AI エージェントのための書面による権限。** 使えるツールを限定し、予算に上限を設け、何が起きたかを証明する。

Apache-2.0 · Node >= 20 · Python >= 3.10

> このページは要約版です。正式な内容は[英語の README](README.md) にあり、ポリシーの完全なリファレンス、API、脅威モデルもそちらに記載しています。

## 問題

ツールを使えるエージェントは、そのツールが持つ権限をすべて持っています。`fs.write` はファイル書き込み、`billing.refund` は返金であり、いつ呼ぶかはモデルが決めます。プロンプトに書いたルール（「ワークスペース外のファイルに触れるな」）は助言にすぎません。攻撃者や混乱したモデルが操作できるのと同じテキストの経路にあるからです。

Toolwrit は判断を**モデルの外**に置きます。すべての呼び出しは実行前に YAML ポリシーで検査され、明示的に許可されていないものは拒否され、すべての判断は改ざん検知可能なログに記録されます。判断の経路にモデルがいないため、ジェイルブレイクで説得される余地もありません。

Toolwrit は**ライブラリとサイドカーであり、ゲートウェイではありません**。トラフィックが自社のインフラの外に出ることはありません。

## 60 秒で始める

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

**コードで**――既存のツール呼び出しを包むだけ：

```ts
import { Toolwrit, loadPolicyFile } from 'toolwrit';

const toolwrit = new Toolwrit({ policy: loadPolicyFile('./toolwrit.yaml'), auditFile: './audit.jsonl' });
const result = await toolwrit.guard(name, args, () => tools[name](args));
```

**コード変更なしで**――既存の MCP サーバーの前に置く：

```
toolwrit run --policy toolwrit.yaml -- npx @modelcontextprotocol/server-filesystem /srv/workspace
```

## 主な機能

- **デフォルト拒否。** 明示的に許可されたツールと引数だけが通ります。複数のルールが該当する場合は deny が ask に、ask が allow に優先します。
- **予算。** 1 回の実行あたりの呼び出し回数・トークン・米ドル・バイト数に上限を設定でき、警告しきい値も指定できます。
- **ハッシュチェーンの監査ログ。** どれか 1 件を書き換えると、それ以降のハッシュがすべて壊れます。`toolwrit verify audit.jsonl`
- **切り詰め対策のアンカー。** 末尾を切り落としたチェーンも、それ自体は有効なチェーンです。`toolwrit anchor` で先頭ハッシュを記録し、`toolwrit verify --against` で欠けた末尾を検出します。
- **RFC 3161 タイムスタンプ。** `toolwrit anchor --tsa` で外部のタイムスタンプ局（既定は DigiCert、無料）に先頭ハッシュへ署名してもらいます。証拠の偽造やバックデートはできず、`verify --max-lag` で後から書き換えられたログを見抜けます。Toolwrit なしでも検証可能：`openssl ts -verify -digest <head> ...`
- **TypeScript と Python** が同一のハッシュを生成するため、一方で書いたログをもう一方で検証できます。実行時の依存はひとつだけ。

## できないこと

Toolwrit はプロンプトやモデルの出力を読まず、ネットワークの送信を制限せず、自身のホストが侵害された場合には守れません。タイムスタンプが証明するのは先頭ハッシュが*いつ*存在したかであり、実際に何が起きたかではありません。詳しくは[脅威モデル](js/docs/threat-model.md)を参照してください。

## 商用サポート

導入支援、独自ポリシーの作成、他言語への移植：[erginsakoglu@gmail.com](mailto:erginsakoglu@gmail.com)

ライセンス：Apache 2.0。
