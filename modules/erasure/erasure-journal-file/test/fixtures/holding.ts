// A process that holds the journal at the path given and waits, until it is killed.
import { randomBytes } from "node:crypto";
import { nodeFiles } from "../../src/files/files.ts";
import { journalFileWith } from "../../src/journal.ts";

const [path = ""] = process.argv.slice(2);
const journal = journalFileWith({
	path,
	files: nodeFiles,
	clock: { now: () => Date.now() },
	random: { bytes: (length) => new Uint8Array(randomBytes(length)) },
});
const held = await journal.hold();
process.stdout.write(`${held.kind}\n`);
setInterval(() => {}, 60_000);
