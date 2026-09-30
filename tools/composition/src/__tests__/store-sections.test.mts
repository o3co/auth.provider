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
 * The stores' sections, the federation-grants section and the WebAuthn
 * variables, through the template's own reading of the full set: the
 * operator's layer and environment read once, phase one's switches, then the
 * layers over every loaded package's `reference.conf` handed to boot. Each
 * section is read at its module's name and refuses a key it does not declare;
 * a path it moved from refuses boot naming the new one; a variable renamed
 * with the move refuses boot unless its new name carries the same value.
 */

import { BootError } from "@o3co/auth-provider-core";
import { SINGLE_ENV } from "@o3co/auth-provider-standalone/src/__tests__/all-modules-composition.fixture.mts";
import { afterEach, describe, expect, it } from "vitest";
import { composeFullSet, type FullSet, type FullSetOptions } from "./full-set.fixture.mts";

let current: FullSet | undefined;

afterEach(async () => {
	await current?.handle.dispose();
	current = undefined;
});

/** Boots the full set, the operator's layer and environment as given, and remembers it. */
async function boot(options: FullSetOptions = {}): Promise<FullSet> {
	current = await composeFullSet(options);
	return current;
}

/** What boot refused the full set with. */
async function refused(options: FullSetOptions): Promise<BootError> {
	try {
		current = await composeFullSet(options);
	} catch (err) {
		if (err instanceof BootError) return err;
		throw err;
	}
	throw new Error("the full set booted");
}

/** A section the parsed configuration holds, by its top-level name. */
const sectionOf = (composition: FullSet, name: string): unknown =>
	(composition.config as unknown as Record<string, unknown>)[name];

describe("a WebAuthn rate-limit variable renamed to the name its path derives, through the template's reading", () => {
	/** Each renamed variable: its old name, its new name, the path the new one binds, a value. */
	const ROWS = [
		{
			from: "WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT",
			to: "WEBAUTHN_RATE_LIMIT_AUTHENTICATION_OPTIONS_LIMIT",
			path: "webauthn.rateLimit.authenticationOptions.limit",
			value: "12",
		},
		{
			from: "WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_WINDOW_SECONDS",
			to: "WEBAUTHN_RATE_LIMIT_AUTHENTICATION_OPTIONS_WINDOW_SECONDS",
			path: "webauthn.rateLimit.authenticationOptions.windowSeconds",
			value: "120",
		},
	] as const;

	it.each(ROWS)(
		"$from set alone: refused, naming $to and $path",
		async ({ from, to, path, value }) => {
			const err = await refused({ env: { ...SINGLE_ENV, [from]: value } });

			expect(err.details).toEqual({
				reason: "environment-variable-renamed",
				renamed: [{ module: "webauthn", from, to, path, state: "unset" }],
			});
		},
	);

	it.each(ROWS)(
		"$from set beside $to at a different value: refused, naming neither value",
		async ({ from, to }) => {
			const err = await refused({ env: { ...SINGLE_ENV, [from]: "31", [to]: "47" } });

			expect(err.details).toMatchObject({ renamed: [{ from, to, state: "different" }] });
			for (const value of ["31", "47"]) {
				expect(JSON.stringify(err.details)).not.toContain(`"${value}"`);
			}
		},
	);

	it.each(ROWS)(
		"$from set beside $to at the same value: boots, the value at $path",
		async ({ from, to, path, value }) => {
			const composition = await boot({ env: { ...SINGLE_ENV, [from]: value, [to]: value } });

			const key = path.split(".").at(-1) as string;
			const options = (
				sectionOf(composition, "webauthn") as {
					rateLimit: { authenticationOptions: Record<string, unknown> };
				}
			).rateLimit.authenticationOptions;
			expect(String(options[key])).toBe(value);
		},
	);
});
