/**
 * Build a Leash audit chain with the reference TypeScript implementation.
 *
 * Reads a JSON spec on argv[2] ({ run, redact, file, entries: [...] }) and
 * writes the chain to `file`, printing the head hash and each entry hash as
 * JSON on stdout. The Python cross-language test drives this: same spec in,
 * same hashes out, or the port is not chain-compatible.
 *
 * Lives in the Python package because the TypeScript tree is read-only
 * reference; it imports the built dist by absolute path from argv[3].
 */

import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const spec = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const { AuditLog } = await import(pathToFileURL(process.argv[3]).href);

const log = new AuditLog({
  run: spec.run,
  ...(spec.file ? { file: spec.file } : {}),
  ...(spec.redact ? { redact: spec.redact } : {}),
});

for (const entry of spec.entries) {
  log.record(
    { id: entry.id ?? 'x', tool: entry.tool, args: entry.args, at: entry.at },
    entry.decision,
    entry.usage
  );
}

process.stdout.write(
  JSON.stringify({ head: log.head(), hashes: log.all().map((e) => e.hash) })
);
