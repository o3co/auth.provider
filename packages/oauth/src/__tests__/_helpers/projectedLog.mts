/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License").
 */

import { expect } from "vitest";
import type { MockLogger } from "./mockLogger.mjs";

/** What no log line may carry: it rides on the command a store refused. */
export const REFUSED_COMMAND_MARKER = "args-must-never-reach-a-log";

/**
 * What ioredis rejects with: a ReplyError carrying the command it refused,
 * arguments and all, as `command.args`. Under `encryption.mode =
 * "allow-plaintext"` those are a token record.
 */
export const storeReplyError = (): Error =>
	Object.assign(new Error("READONLY You can't write against a read only replica."), {
		name: "ReplyError",
		command: { name: "set", args: ["federation-token:sid-1:google", REFUSED_COMMAND_MARKER] },
	});

/** Every argument of every warn and error call, own properties and all, as JSON. */
export const serialisedCalls = (logger: MockLogger): string => {
	const walk = (value: unknown, seen = new WeakSet<object>()): unknown => {
		if (typeof value !== "object" || value === null) return value;
		if (seen.has(value)) return "[circular]";
		seen.add(value);
		const out: Record<string, unknown> = {};
		for (const key of Object.getOwnPropertyNames(value)) {
			out[key] = walk((value as Record<string, unknown>)[key], seen);
		}
		return out;
	};
	return JSON.stringify(walk([logger.warn.mock.calls, logger.error.mock.calls]));
};

/**
 * The string-first warn line whose message matches `message` carried the
 * error's projection — a `ReplyError` by name, not the error — and no warn or
 * error call carried the refused command.
 */
export const expectProjectedWarn = (logger: MockLogger, message: RegExp): void => {
	const line = logger.warn.mock.calls.find(
		([first]) => typeof first === "string" && message.test(first),
	);
	expect(line, `a warn line matching ${message}`).toBeDefined();
	expect(line?.[1]).toMatchObject({ name: "ReplyError" });
	expect(line?.[1]).not.toBeInstanceOf(Error);
	expect(serialisedCalls(logger)).not.toContain(REFUSED_COMMAND_MARKER);
};
