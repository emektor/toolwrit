/**
 * Print the reference `canonicalize()` output for each value in a JSON array.
 *
 * Used by the differential test that pins the Python canonical form against
 * the TypeScript one value by value, including the number formatting that is
 * the whole difficulty of the port.
 */

import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const values = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const { canonicalize } = await import(pathToFileURL(process.argv[3]).href);

process.stdout.write(JSON.stringify(values.map((v) => canonicalize(v))));
