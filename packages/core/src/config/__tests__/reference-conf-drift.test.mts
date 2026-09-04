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

import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { describe, expect, it } from "vitest";
import { AppConfigSchema } from "#/config/application.schema.mjs";

/**
 * #472 — `AppConfigSchema` must not strip a single path the shipped defaults
 * carry.
 *
 * The schema is a strip-mode `z.object`: a key it does not declare is dropped
 * at parse time, silently, before any module's own `configSchema` runs. That
 * has now bitten five times over — `redisSessionStores` (MIN-3),
 * `redisRefreshTokenFamilyStore` (D-2 v2), `redisCodeRepository` (OR-9),
 * `redisFederationTokenStore` (#456), `redisDeviceCodeStore` and
 * `oauth.deviceAuthorization` (#472) — each found by an operator whose
 * documented override did nothing. Every fix declared the one missing
 * section and left the mechanism in place.
 *
 * This resolves `reference.conf` the way the standalone does, runs it through
 * the schema, and diffs the key trees: any path the resolved HOCON has that
 * the parsed config lacks is a section the next module forgot to declare, and
 * it fails here by name rather than in production by omission.
 */

const REFERENCE_CONF_PATH = new URL("../../../config/reference.conf", import.meta.url).pathname;

/** The three substitutions `reference.conf` cannot validate without. */
const REQUIRED_ENV = {
	OAUTH_JWT_SECRET: "reference-conf-drift.at-least-32-bytes.ok",
	OAUTH_JWT_ISSUER: "https://auth.test",
	SESSION_SECRET: "reference-conf-drift-session.at-least-32-bytes.ok",
};

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * Every dotted path in `tree`, branches and leaves alike. Arrays are leaves:
 * their elements are values, not configuration keys.
 */
function collectPaths(tree: unknown, prefix = ""): string[] {
	if (!isPlainObject(tree)) return [];
	return Object.entries(tree).flatMap(([key, value]) => {
		const path = prefix === "" ? key : `${prefix}.${key}`;
		return [path, ...collectPaths(value, path)];
	});
}

function hasPath(tree: unknown, path: string): boolean {
	let cursor: unknown = tree;
	for (const segment of path.split(".")) {
		if (!isPlainObject(cursor) || !Object.hasOwn(cursor, segment)) return false;
		cursor = cursor[segment];
	}
	return true;
}

describe("reference.conf survives AppConfigSchema without losing a path (#472)", () => {
	const raw = parseFile(REFERENCE_CONF_PATH, { env: REQUIRED_ENV });
	const resolved = raw.toObject();
	const parsed = validate(raw, AppConfigSchema);

	it("resolves to a non-trivial tree, so the diff below is over something", () => {
		const paths = collectPaths(resolved);
		expect(paths.length).toBeGreaterThan(50);
		expect(paths).toContain("oauth.jwt.signingKey.local.algorithm");
		expect(paths).toContain("redisFederationTokenStore.keyPrefix");
	});

	it("strips no path the shipped defaults carry", () => {
		const stripped = collectPaths(resolved).filter((path) => !hasPath(parsed, path));
		// A path listed here is a section `reference.conf` ships that
		// `AppConfigSchema` does not declare. Declare it — presence-only, like
		// the `redis*` sections in `fullSectionsSchema` — rather than adding it
		// to an allowlist here.
		expect(stripped).toEqual([]);
	});
});
