/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Every number setting of `session {}` and `session-store {}` is read as a
 * whole number in decimal digits, held to its range: a typo such as `"1e3"`
 * or `"0x10"`, or an exported-but-empty variable, fails boot naming the key
 * instead of being read as some other number.
 */

import { MAX_DURATION_MS } from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { MAX_CSRF_TTL_SECONDS } from "#/csrf.mjs";
import { sessionSectionSchema } from "#/module.mjs";
import { sessionStoreConfigSchema } from "#/modules/sessionStoreModule.mjs";

type Parsed = {
	success: boolean;
	data?: unknown;
	error?: { issues: ReadonlyArray<{ path: PropertyKey[]; message: string }> };
};

/** `session {}` with `change` laid over the keys the schema requires, parsed. */
const parseSession = (change: Record<string, unknown>): Parsed =>
	sessionSectionSchema.safeParse({
		loginPage: { url: "/login" },
		rateLimit: { login: { windowMs: 900_000, limit: 20 } },
		...change,
	});

/** The fixture's `session-store {}` with `change` laid over it, parsed. */
const parseSessionStore = (change: Record<string, unknown>): Parsed =>
	sessionStoreConfigSchema.safeParse({
		...(makeValidAppConfig() as unknown as { "session-store": object })["session-store"],
		...change,
	});

const upTo = (max: number) => `must be a whole number from 1 to ${max}, in decimal digits`;

/** Each number key: its path, how to parse a section carrying `value` there, and its range's message. */
const KEYS: ReadonlyArray<
	readonly [path: string, parse: (value: unknown) => Parsed, message: string]
> = [
	[
		"csrf.ttlSeconds",
		(value) => parseSession({ csrf: { trustedOrigins: [], ttlSeconds: value } }),
		upTo(MAX_CSRF_TTL_SECONDS),
	],
	[
		"rateLimit.login.windowMs",
		(value) => parseSession({ rateLimit: { login: { windowMs: value, limit: 20 } } }),
		upTo(MAX_DURATION_MS),
	],
	[
		"rateLimit.login.limit",
		(value) => parseSession({ rateLimit: { login: { windowMs: 900_000, limit: value } } }),
		"must be a whole number of at least 1, in decimal digits",
	],
	["maxAge", (value) => parseSessionStore({ maxAge: value }), upTo(MAX_DURATION_MS)],
];

/** What an operator might write that is not a whole number in decimal digits. */
const REFUSED: ReadonlyArray<unknown> = [
	"0x10",
	"1e3",
	"5.0",
	"+5",
	true,
	"",
	"  ",
	"Infinity",
	"NaN",
	Number.POSITIVE_INFINITY,
	Number.NaN,
];

const issuesAt = (result: Parsed, path: string) =>
	(result.error?.issues ?? [])
		.filter((issue) => issue.path.map(String).join(".") === path)
		.map((issue) => issue.message);

/** The value the parsed section carries at `path`. */
const readAt = (result: Parsed, path: string): unknown =>
	path
		.split(".")
		.reduce<unknown>(
			(node, key) => (node as Record<string, unknown> | undefined)?.[key],
			result.data,
		);

describe("session {} and session-store {} read each number setting in decimal digits", () => {
	describe.each(KEYS)("%s", (path, parse, message) => {
		it.each(REFUSED.map((value) => [value]))("refuses %j, naming the key", (value) => {
			const result = parse(value);
			expect(result.success).toBe(false);
			expect(issuesAt(result, path)).toEqual([message]);
		});

		// A well-formed number out of range may also meet the section's own
		// check (session-store's cookie refusal); the range's message is among them.
		it.each([[0], ["0"]])("refuses %j, below the minimum", (value) => {
			expect(issuesAt(parse(value), path)).toContain(message);
		});

		it.each([[60], ["60"], [" 60 "]])("reads %j as 60", (value) => {
			const result = parse(value);
			expect(result.error?.issues ?? []).toEqual([]);
			expect(readAt(result, path)).toBe(60);
		});
	});

	it.each([
		["csrf.ttlSeconds", MAX_CSRF_TTL_SECONDS],
		["rateLimit.login.windowMs", MAX_DURATION_MS],
		["maxAge", MAX_DURATION_MS],
	] as const)("refuses %s above %d", (path, max) => {
		const [, parse, message] = KEYS.find(([key]) => key === path) ?? [];
		expect(parse === undefined ? [] : issuesAt(parse(max + 1), path)).toContain(message);
	});
});
