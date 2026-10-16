import { extensionPoint } from "./handles.ts";
import type { Clock, Log, LogFields, LogSink } from "./runtime.ts";

/** In order: a threshold lets through its own level and those after it. */
export const thresholds = ["trace", "debug", "info", "warn", "error", "fatal", "silent"] as const;
export type Threshold = (typeof thresholds)[number];

export const logSinks = extensionPoint<LogSink>("logSinks", { multiplicity: "many" });

type Write = (level: keyof Log, event: string, fields?: LogFields) => void;

/** A Log whose calls never throw, whatever `write` does. */
function logOf(write: Write): Log {
	const method = (level: keyof Log) => (event: string, fields?: LogFields) => {
		try {
			write(level, event, fields);
		} catch {
			// Log's contract: a call never throws, so no caller guards one.
		}
	};
	return Object.freeze({
		trace: method("trace"),
		debug: method("debug"),
		info: method("info"),
		warn: method("warn"),
		error: method("error"),
		fatal: method("fatal"),
	});
}

/** The same log, its calls never throwing. */
export function guardedLog(log: Log): Log {
	return logOf((level, event, fields) => log[level](event, fields));
}

/**
 * A log handing each line at or above `threshold` to every sink, in order. `sinks` answers
 * undefined while the sinks are being built, and those lines are dropped.
 */
export function routedLog(
	threshold: Threshold,
	clock: Clock,
	sinks: () => readonly LogSink[] | undefined,
): Log {
	const floor = thresholds.indexOf(threshold);
	return logOf((level, event, fields) => {
		if (thresholds.indexOf(level) < floor) return;
		const list = sinks();
		if (list === undefined) return;
		const line = Object.freeze({
			level,
			event,
			at: clock.now(),
			fields: Object.freeze({ ...fields }),
		});
		for (const sink of list) {
			try {
				sink.write(line);
			} catch {
				// A failing sink must not keep the line from the next sink.
			}
		}
	});
}
