import { randomBytes } from "node:crypto";

export interface Clock {
	now(): number;
}

export interface Random {
	bytes(length: number): Uint8Array;
}

export type LogFields = Readonly<Record<string, string | number | boolean>>;

/**
 * A call never throws: kernel guards every log it hands out, so no caller wraps one in try. No field
 * takes a line's own name (level, event, at), which a sink writes beside the fields as one object.
 */
export interface Log {
	trace<
		F extends LogFields & { readonly level?: never; readonly event?: never; readonly at?: never },
	>(event: string, fields?: F): void;
	debug<
		F extends LogFields & { readonly level?: never; readonly event?: never; readonly at?: never },
	>(event: string, fields?: F): void;
	info<
		F extends LogFields & { readonly level?: never; readonly event?: never; readonly at?: never },
	>(event: string, fields?: F): void;
	warn<
		F extends LogFields & { readonly level?: never; readonly event?: never; readonly at?: never },
	>(event: string, fields?: F): void;
	error<
		F extends LogFields & { readonly level?: never; readonly event?: never; readonly at?: never },
	>(event: string, fields?: F): void;
	fatal<
		F extends LogFields & { readonly level?: never; readonly event?: never; readonly at?: never },
	>(event: string, fields?: F): void;
}

export type LogLevel = "trace" | "debug" | "info" | "warn" | "error" | "fatal";

export interface LogLine {
	readonly level: LogLevel;
	readonly event: string;
	/** Epoch ms, on the kernel's clock. */
	readonly at: number;
	readonly fields: LogFields;
}

/** Where log lines go; contributed to `logSinks`. */
export interface LogSink {
	write(line: LogLine): void;
}

export interface Runtime {
	readonly clock: Clock;
	readonly random: Random;
	readonly log: Log;
}

export const systemClock: Clock = Object.freeze({ now: () => Date.now() });

export const systemRandom: Random = Object.freeze({
	bytes: (length: number) => new Uint8Array(randomBytes(length)),
});
