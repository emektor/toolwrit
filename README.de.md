# Toolwrit

[English](README.md) · **Deutsch** · [简体中文](README.zh-CN.md) · [日本語](README.ja.md) · [Español](README.es.md)

**Eine schriftliche Vollmacht für KI-Agenten.** Erlaubte Tools festlegen, das Budget deckeln, nachweisen, was passiert ist.

Apache-2.0 · Node >= 20 · Python >= 3.10

> Diese Seite ist eine Kurzfassung. Maßgeblich ist die [englische README](README.md); dort stehen die vollständige Policy-Referenz, das API und das Bedrohungsmodell.

## Das Problem

Ein Agent mit Tool-Zugriff hat genau die Befugnisse seiner Tools. Ein `fs.write`-Tool ist ein Schreibzugriff, ein `billing.refund`-Tool ist eine Rückerstattung – und das Modell entscheidet, wann es sie benutzt. Regeln im Prompt („fasse keine Dateien außerhalb des Workspace an“) sind nur Empfehlungen: Sie stehen im selben Textkanal, den ein Angreifer oder ein verwirrtes Modell kontrolliert.

Toolwrit setzt die Entscheidung **außerhalb des Modells**: Jeder Aufruf wird vor der Ausführung gegen eine YAML-Policy geprüft, alles nicht ausdrücklich Erlaubte wird abgelehnt, und jede Entscheidung landet in einem manipulationssicheren Protokoll. Kein Modell im Entscheidungspfad – also nichts, was man per Jailbreak überreden könnte.

Toolwrit ist eine **Bibliothek und ein Sidecar, kein Gateway**. Ihr Datenverkehr verlässt Ihre Infrastruktur nicht.

## In 60 Sekunden

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

**Im Code** – den bestehenden Tool-Aufruf einwickeln:

```ts
import { Toolwrit, loadPolicyFile } from 'toolwrit';

const toolwrit = new Toolwrit({ policy: loadPolicyFile('./toolwrit.yaml'), auditFile: './audit.jsonl' });
const result = await toolwrit.guard(name, args, () => tools[name](args));
```

**Ohne Code** – vor einen vorhandenen MCP-Server schalten:

```
toolwrit run --policy toolwrit.yaml -- npx @modelcontextprotocol/server-filesystem /srv/workspace
```

## Was drin ist

- **Deny by default.** Nur ausdrücklich erlaubte Tools und Argumente gehen durch; bei mehreren passenden Regeln gilt: deny vor ask vor allow.
- **Budgets.** Obergrenzen für Aufrufe, Tokens, US-Dollar und Bytes pro Lauf, mit Warnschwellen.
- **Hash-verkettetes Audit-Log.** Wird ein Eintrag geändert, brechen alle folgenden Hashes. `toolwrit verify audit.jsonl`
- **Anker gegen Kürzung.** Eine gültige Kette, deren Ende abgeschnitten wurde, ist immer noch gültig. `toolwrit anchor` hält den Kopf-Hash fest; `toolwrit verify --against` erkennt das fehlende Ende.
- **RFC-3161-Zeitstempel.** `toolwrit anchor --tsa` lässt den Kopf-Hash von einer externen Zeitstempelstelle (standardmäßig DigiCert, kostenlos) signieren. Der Beleg lässt sich weder fälschen noch zurückdatieren; `verify --max-lag` erkennt ein nachträglich umgeschriebenes Log. Prüfbar auch ohne Toolwrit: `openssl ts -verify -digest <head> ...`
- **TypeScript und Python** erzeugen identische Hashes – ein Log aus der einen Sprache verifiziert in der anderen. Eine einzige Laufzeitabhängigkeit.

## Was es nicht ist

Toolwrit liest keine Prompts oder Modellausgaben, filtert keinen Netzwerkverkehr und übersteht keine Kompromittierung des eigenen Hosts. Ein Zeitstempel beweist, *wann* ein Kopf existierte, nicht was wirklich geschah. Details im [Bedrohungsmodell](js/docs/threat-model.md).

## Kommerzieller Support

Integration, eigene Policies oder eine Portierung in eine andere Sprache: [erginsakoglu@gmail.com](mailto:erginsakoglu@gmail.com)

Lizenz: Apache 2.0.
