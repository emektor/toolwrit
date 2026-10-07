# Toolwrit

[English](README.md) · [Deutsch](README.de.md) · [简体中文](README.zh-CN.md) · [日本語](README.ja.md) · **Español**

**Una autorización por escrito para agentes de IA.** Limita las herramientas, pon tope al presupuesto, demuestra lo que ocurrió.

Apache-2.0 · Node >= 20 · Python >= 3.10

> Esta página es un resumen. La referencia es el [README en inglés](README.md), con la referencia completa de políticas, la API y el modelo de amenazas.

## El problema

Un agente con acceso a herramientas tiene toda la autoridad de esas herramientas. `fs.write` es escribir archivos, `billing.refund` es devolver dinero, y es el modelo quien decide cuándo usarlas. Las reglas en el prompt («no toques archivos fuera del workspace») son solo consejos: viven en el mismo canal de texto que controla un atacante o un modelo confundido.

Toolwrit pone la decisión **fuera del modelo**: cada llamada se comprueba contra una política YAML antes de ejecutarse, todo lo que no está permitido explícitamente se rechaza y cada decisión queda en un registro a prueba de manipulaciones. No hay ningún modelo en el camino de la decisión, así que no hay prompt que se pueda convencer con un jailbreak.

Toolwrit es una **biblioteca y un sidecar, no un gateway**. Tu tráfico no sale de tu infraestructura.

## Empieza en 60 segundos

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

**En el código**: envuelve la llamada que ya tienes:

```ts
import { Toolwrit, loadPolicyFile } from 'toolwrit';

const toolwrit = new Toolwrit({ policy: loadPolicyFile('./toolwrit.yaml'), auditFile: './audit.jsonl' });
const result = await toolwrit.guard(name, args, () => tools[name](args));
```

**Sin código**: ponlo delante de un servidor MCP que ya uses:

```
toolwrit run --policy toolwrit.yaml -- npx @modelcontextprotocol/server-filesystem /srv/workspace
```

## Qué incluye

- **Denegar por defecto.** Solo pasan las herramientas y argumentos permitidos explícitamente; si coinciden varias reglas, deny gana a ask y ask gana a allow.
- **Presupuestos.** Topes por ejecución de llamadas, tokens, dólares y bytes, con umbrales de aviso.
- **Registro de auditoría encadenado por hash.** Si se modifica una entrada, se rompen todos los hashes posteriores. `toolwrit verify audit.jsonl`
- **Anclas contra el recorte.** Una cadena válida a la que se le corta el final sigue siendo válida. `toolwrit anchor` fija el hash de cabeza y `toolwrit verify --against` detecta el final que falta.
- **Sellos de tiempo RFC 3161.** `toolwrit anchor --tsa` hace que una autoridad de sellado externa (DigiCert por defecto, gratuita) firme el hash de cabeza. El recibo no se puede falsificar ni antedatar, y `verify --max-lag` detecta un registro reescrito después. Verificable sin Toolwrit: `openssl ts -verify -digest <head> ...`
- **TypeScript y Python** producen hashes idénticos: un registro escrito en un lenguaje se verifica con el otro. Una sola dependencia en tiempo de ejecución.

## Lo que no hace

Toolwrit no lee prompts ni la salida del modelo, no filtra el tráfico de red saliente y no resiste que su propio host esté comprometido. Un sello de tiempo demuestra *cuándo* existía una cabeza, no lo que realmente ocurrió. Más detalles en el [modelo de amenazas](js/docs/threat-model.md).

## Soporte comercial

Integración, políticas a medida o una adaptación a otro lenguaje: [erginsakoglu@gmail.com](mailto:erginsakoglu@gmail.com)

Licencia: Apache 2.0.
