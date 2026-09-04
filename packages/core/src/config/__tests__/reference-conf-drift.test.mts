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

import { readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
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
 * has now bitten seven times over — `redisSessionStores` (MIN-3),
 * `redisRefreshTokenFamilyStore` (D-2 v2), `redisCodeRepository` (OR-9),
 * `redisFederationTokenStore` (#456), `redisDeviceCodeStore` and
 * `oauth.deviceAuthorization` (#472), `redisRateLimiter` (#495) and
 * `oauth.mtls` / `oauth.dpop` / `webauthn` (#496) — each found by an operator
 * whose documented override did nothing. Every fix declared the one missing
 * section and left the mechanism in place.
 *
 * This resolves `reference.conf` the way the standalone does, runs it through
 * the schema, and diffs the key trees: any path the resolved HOCON has that
 * the parsed config lacks is a section the next module forgot to declare, and
 * it fails here by name rather than in production by omission.
 *
 * #496: every package that ships defaults gets the same treatment, in the
 * chained shape a composition root actually assembles (`withFallback` down to
 * core's). Core's own file could only ever cover core's own sections, and
 * `oauth.mtls`, `oauth.dpop` and `webauthn` ship their defaults from the
 * packages that own them — so the sections most likely to be forgotten here
 * were exactly the ones the original diff could not see.
 */

const REFERENCE_CONF_PATH = fileURLToPath(
	new URL("../../../config/reference.conf", import.meta.url),
);

const REPO_ROOT = fileURLToPath(new URL("../../../../../", import.meta.url));

/**
 * Every `reference.conf` shipped by a workspace under `packages/`, found by
 * looking rather than by a list: a new package's defaults join this diff
 * without anyone remembering to add them.
 */
function shippedReferenceConfs(dir: string, found: string[] = []): string[] {
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		if (entry.name === "node_modules" || entry.name === "dist") continue;
		const full = join(dir, entry.name);
		if (entry.isDirectory()) shippedReferenceConfs(full, found);
		else if (entry.name === "reference.conf") found.push(full);
	}
	return found.sort();
}

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

describe("core's reference.conf survives AppConfigSchema without losing a path (#472)", () => {
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

describe("every shipped reference.conf survives AppConfigSchema (#496)", () => {
	const confPaths = shippedReferenceConfs(join(REPO_ROOT, "packages"));

	// The chain a composition root assembles: each package's defaults layered
	// over core's, which is the bottom tier the standalone template resolves.
	const chained = confPaths
		.filter((path) => path !== REFERENCE_CONF_PATH)
		.reduce(
			(config, path) => config.withFallback(parseFile(path, { env: REQUIRED_ENV })),
			parseFile(REFERENCE_CONF_PATH, { env: REQUIRED_ENV }),
		);
	const resolved = chained.toObject();
	const parsed = validate(chained, AppConfigSchema);

	it("finds the packages that ship defaults", () => {
		// Named rather than counted: the diff below is the assertion, and a new
		// package's `reference.conf` joins it without touching this test. These
		// five are here so a lookup that silently found nothing — a moved file,
		// a renamed directory — fails as itself rather than as a passing diff
		// over an empty tree.
		expect(confPaths.map((path) => relative(REPO_ROOT, path))).toEqual(
			expect.arrayContaining([
				"packages/core/config/reference.conf",
				"packages/device-grant/src/reference.conf",
				"packages/dpop/src/reference.conf",
				"packages/mtls/src/reference.conf",
				"packages/webauthn/config/reference.conf",
			]),
		);
	});

	it("resolves the sections those packages own", () => {
		const paths = collectPaths(resolved);
		expect(paths).toContain("oauth.mtls.full-pki.max-chain-depth");
		expect(paths).toContain("oauth.dpop.replay-store");
		expect(paths).toContain("oauth.deviceAuthorization.enabled");
		expect(paths).toContain("webauthn.rateLimit.authenticationOptions.limit");
		expect(paths).toContain("redisRateLimiter.defaultLimit.limit");
	});

	it("strips no path any shipped default carries", () => {
		const stripped = collectPaths(resolved).filter((path) => !hasPath(parsed, path));
		// A path listed here is a section some package ships that
		// `AppConfigSchema` does not declare, so an operator who overrides it
		// hands `createApp` a configuration without it. Declare it —
		// presence-only, like the `redis*` sections in `fullSectionsSchema`.
		expect(stripped).toEqual([]);
	});
});
