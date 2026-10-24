import { defineModule, type LogLine, logSinks } from "@mod/kernel";

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
	m.contribute(logSinks).by(() => ({
		write: (line) => {
			process.stdout.write(text(line));
		},
	})),
]);
