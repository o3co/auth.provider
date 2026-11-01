import { defineModule, type LogLine, logSinks } from "@mod/kernel";
import { drained } from "./drain.ts";

const envelope = new Set(["level", "at", "event"]);

/** One JSON object: the envelope first, then the fields; a field named like the envelope is dropped. */
function text(line: LogLine): string {
	const fields = Object.entries(line.fields).filter(([name]) => !envelope.has(name));
	const object = {
		level: line.level,
		at: line.at,
		event: line.event,
		...Object.fromEntries(fields),
	};
	return `${JSON.stringify(object)}\n`;
}

export default defineModule({ name: "log-stdout", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(logSinks).by((c) => {
		const out = process.stdout;
		// Once its reader has gone, a write fails and the stream's 'error' is heard by kernel: the line is
		// dropped, and every later write fails as quietly.
		// A sink's hook runs after every other module's: the lines they logged as they stopped are out.
		c.onStop((signal) => drained(out, signal));
		return {
			write: (line) => {
				out.write(text(line));
			},
		};
	}),
]);
