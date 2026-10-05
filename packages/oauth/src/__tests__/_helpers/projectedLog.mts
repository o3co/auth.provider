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
 * The policy for a branch that answers 503 because a store, a repository or a
 * keystore could not answer: exactly one line, at error level, object-first,
 * named `event`, carrying `fields` and the error's projection (a `ReplyError`
 * by name, not the error); no warn line about it (one carrying an error, or
 * string-first); and nowhere the refused command. A verifier's once-per-logger
 * audit-gap notice (`jwt_verify_aud_skipped`, object-first, no error) is not
 * about it and may precede it.
 */
export const expectOutageLine = (
	logger: MockLogger,
	event: string,
	fields: Record<string, unknown>,
	errName = "ReplyError",
): Record<string, unknown> => {
	const warnedAboutIt = logger.warn.mock.calls.filter(
		([first]) =>
			typeof first === "string" ||
			(typeof first === "object" && first !== null && "err" in (first as object)),
	);
	expect(warnedAboutIt, "no warn-level line on an outage").toEqual([]);
	expect(logger.error, "one error-level line").toHaveBeenCalledTimes(1);
	const [line, name] = logger.error.mock.calls[0] as [Record<string, unknown>, string];
	expect(name).toBe(event);
	expect(line).toMatchObject(fields);
	expect(line.err).toMatchObject({ name: errName });
	expect(line.err).not.toBeInstanceOf(Error);
	expect(serialisedCalls(logger)).not.toContain(REFUSED_COMMAND_MARKER);
	return line;
};

/**
 * The policy for a best-effort step whose failure the route rides over (no
 * 503): exactly one warn-level line named `event`, object-first, whose fields
 * include `fields` (so two lines under one event, told apart by `store` or
 * `clientId`, are each checked on their own), carrying the error's projection,
 * not the error (`errName: null` for a line about no error); no line at all
 * whose first argument is a string; and nowhere the refused command.
 */
export const expectBestEffortWarn = (
	logger: MockLogger,
	event: string,
	fields: Record<string, unknown>,
	errName: string | null = "ReplyError",
): Record<string, unknown> => {
	const stringFirst = [...logger.warn.mock.calls, ...logger.error.mock.calls].filter(
		([first]) => typeof first === "string",
	);
	expect(stringFirst, "no template-string line").toEqual([]);
	const lines = logger.warn.mock.calls.filter(
		([first, name]) =>
			name === event &&
			typeof first === "object" &&
			first !== null &&
			Object.entries(fields).every(
				([key, value]) => (first as Record<string, unknown>)[key] === value,
			),
	);
	expect(lines, `one ${event} warn with ${JSON.stringify(fields)}`).toHaveLength(1);
	const line = lines[0]?.[0] as Record<string, unknown>;
	expect(line).toMatchObject(fields);
	if (errName === null) {
		expect(line).not.toHaveProperty("err");
	} else {
		expect(line.err).toMatchObject({ name: errName });
		expect(line.err).not.toBeInstanceOf(Error);
	}
	expect(serialisedCalls(logger)).not.toContain(REFUSED_COMMAND_MARKER);
	return line;
};

/**
 * No warn or error line carries `uri` in any form: as written, as `URL`
 * serialises it (a tab inside the scheme is stripped, the scheme is
 * lowercased), or its scheme alone: with the colon, and without it unless
 * the scheme is http(s), whose bare name a reason such as
 * `http-non-loopback` carries.
 */
export const expectUriNotLogged = (logger: MockLogger, uri: string): void => {
	// A projected error's stack names source files and line numbers, never
	// the record: left out, so a value such as `42` is not found in a line
	// number.
	const logged = serialisedCalls(logger).replace(/"stack":"(?:[^"\\]|\\.)*"/g, '"stack":""');
	const forms = [JSON.stringify(uri).slice(1, -1)];
	try {
		const url = new URL(uri);
		forms.push(url.href, url.protocol);
		if (url.protocol !== "http:" && url.protocol !== "https:")
			forms.push(url.protocol.slice(0, -1));
	} catch {
		// Not a URL: the written form is the only one.
	}
	for (const form of forms) expect(logged, `the log carries ${form}`).not.toContain(form);
};
