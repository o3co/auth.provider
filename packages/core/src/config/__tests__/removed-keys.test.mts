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
 * The one way a removed config key dies loudly (#366).
 *
 * Zod's default object behavior strips unknown keys before refinement sees
 * them, so an operator's stale config line would be silently ignored on
 * upgrade — the exact opposite of what a removal needs. The repo had grown
 * two copy-pasted preprocess wrappers doing the detection (refreshToken,
 * authorize) plus a differently-shaped one for the legacy JWT fields;
 * `withRemovedKeys` is the shared spelling, and this suite is its contract.
 */
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { environmentVariableFor } from "#/config/environment-variable.mjs";
import {
	findRelocatedKeys,
	type RemovedKey,
	relocatedKeyMessage,
	withRemovedKeys,
} from "#/config/removed-keys.mjs";

const REMOVED: readonly RemovedKey[] = [
	{
		name: "oldFlag",
		removedIn: "v9.9.9 (test)",
		note: "It stopped meaning anything.",
	},
	{
		name: "otherFlag",
		removedIn: "v9.9.8 (test)",
		note: "Superseded by newFlag.",
	},
];

const schema = withRemovedKeys("test.section", REMOVED, z.object({ kept: z.string() }));

describe("withRemovedKeys", () => {
	it("passes a config that no longer sets any removed key", () => {
		expect(schema.parse({ kept: "value" })).toEqual({ kept: "value" });
	});

	it("refuses a config still setting a removed key, naming key, release, and note", () => {
		const result = schema.safeParse({ kept: "value", oldFlag: true });
		expect(result.success).toBe(false);
		const issue = result.success ? undefined : result.error.issues[0];
		// The message skeleton is shared with the pre-#366 wrappers, so the
		// operator-facing shape (and the tests pinning it) survive the
		// consolidation: "<section>.<key> was removed in <release>; see
		// CHANGELOG. <note> Remove this field from your config."
		expect(issue?.message).toContain("test.section.oldFlag was removed in v9.9.9 (test)");
		expect(issue?.message).toContain("see CHANGELOG");
		expect(issue?.message).toContain("It stopped meaning anything.");
		expect(issue?.message).toContain("Remove this field from your config.");
		expect(issue?.path).toEqual(["oldFlag"]);
	});

	it("reports every removed key present, not just the first", () => {
		const result = schema.safeParse({ kept: "value", oldFlag: 1, otherFlag: "x" });
		expect(result.success).toBe(false);
		const messages = result.success ? [] : result.error.issues.map((i) => i.message).join("\n");
		expect(messages).toContain("oldFlag");
		expect(messages).toContain("otherFlag");
	});

	it("leaves non-object input to the wrapped schema's own error", () => {
		// The detection must not crash on scalars/arrays; the wrapped schema
		// reports the type mismatch as it always did.
		expect(schema.safeParse("nonsense").success).toBe(false);
		expect(schema.safeParse([1, 2]).success).toBe(false);
	});
});

describe("findRelocatedKeys — a key that moved (#728)", () => {
	const dpopMoved = { from: ["oauth", "dpop"], to: ["dpop"] } as const;
	const iatRenamed = {
		from: ["oauth", "dpop", "iat-window-seconds"],
		to: ["dpop", "iatWindowSeconds"],
	} as const;

	it("finds a leaf set at the old path, with its new path and the variable that binds it", () => {
		const found = findRelocatedKeys({ endpoints: { login: { url: "https://login" } } }, [
			{ from: ["endpoints", "login", "url"], to: ["session", "loginPage", "url"] },
		]);
		expect(found.map(({ relocation: _, ...key }) => key)).toEqual([
			{
				from: "endpoints.login.url",
				to: "session.loginPage.url",
				environmentVariable: "SESSION_LOGIN_PAGE_URL",
			},
		]);
	});

	it("finds every leaf of a subtree set at the old path, each at the same place under the new one", () => {
		const found = findRelocatedKeys(
			{ oauth: { dpop: { "iat-window-seconds": 30, nonce: { lifetime: 5 } }, jwt: {} } },
			[dpopMoved],
		);
		expect(
			found.map(({ from, to, environmentVariable }) => [from, to, environmentVariable]),
		).toEqual([
			["oauth.dpop.iat-window-seconds", "dpop.iat-window-seconds", "DPOP_IAT_WINDOW_SECONDS"],
			["oauth.dpop.nonce.lifetime", "dpop.nonce.lifetime", "DPOP_NONCE_LIFETIME"],
		]);
	});

	it("maps a key by the most specific relocation that covers it: a renamed key inside a moved subtree", () => {
		const found = findRelocatedKeys(
			{ oauth: { dpop: { "iat-window-seconds": 30, nonce: { lifetime: 5 } } } },
			[dpopMoved, iatRenamed],
		);
		expect(found.map(({ from, to }) => [from, to])).toEqual([
			["oauth.dpop.iat-window-seconds", "dpop.iatWindowSeconds"],
			["oauth.dpop.nonce.lifetime", "dpop.nonce.lifetime"],
		]);
		// Each key once, whatever order the relocations come in.
		expect(
			findRelocatedKeys({ oauth: { dpop: { "iat-window-seconds": 30 } } }, [
				iatRenamed,
				dpopMoved,
			]).map(({ to }) => to),
		).toEqual(["dpop.iatWindowSeconds"]);
	});

	it("reads a list as one value, and an empty subtree as the path itself", () => {
		expect(
			findRelocatedKeys({ old: { list: [1, 2] } }, [{ from: ["old"], to: ["new"] }]).map(
				({ from, to, environmentVariable }) => [from, to, environmentVariable],
			),
		).toEqual([["old.list", "new.list", "NEW_LIST"]]);
		expect(
			findRelocatedKeys({ old: {} }, [{ from: ["old"], to: ["new"] }]).map(
				({ from, to, environmentVariable }) => [from, to, environmentVariable],
			),
		).toEqual([["old", "new", undefined]]);
	});

	it("finds nothing where the configuration sets nothing, and reads own keys only", () => {
		expect(findRelocatedKeys({ oauth: {} }, [dpopMoved])).toEqual([]);
		expect(findRelocatedKeys({}, [{ from: ["constructor"], to: ["x"] }])).toEqual([]);
		expect(findRelocatedKeys(undefined, [dpopMoved])).toEqual([]);
	});

	it("says what moved where in the words a removed key is refused in", () => {
		expect(
			relocatedKeyMessage({
				from: "oauth.dpop.iat-window-seconds",
				to: "dpop.iatWindowSeconds",
				environmentVariable: "DPOP_IAT_WINDOW_SECONDS",
			}),
		).toBe(
			"oauth.dpop.iat-window-seconds has moved to dpop.iatWindowSeconds; see CHANGELOG. " +
				"Write it there (environment variable DPOP_IAT_WINDOW_SECONDS) and remove this field from your config.",
		);
		expect(relocatedKeyMessage({ from: "old", to: "new" })).toBe(
			"old has moved to new; see CHANGELOG. Write it there and remove this field from your config.",
		);
	});
});

describe("environmentVariableFor — the variable a path is bound to (#728 B9)", () => {
	it.each([
		[["device-grant", "codeLifetimeSeconds"], "DEVICE_GRANT_CODE_LIFETIME_SECONDS"],
		[["redis-consent-store", "keyPrefix"], "REDIS_CONSENT_STORE_KEY_PREFIX"],
		[["mfa", "encryptionKeys", "0", "key"], "MFA_ENCRYPTION_KEYS_0_KEY"],
		[["key-store", "local", "privateKeyPath"], "KEY_STORE_LOCAL_PRIVATE_KEY_PATH"],
		[["jwks", "cacheMaxAge"], "JWKS_CACHE_MAX_AGE"],
		[["http", "cors", "allowedOrigins"], "HTTP_CORS_ALLOWED_ORIGINS"],
		[["oauth", "jwksURLPath"], "OAUTH_JWKS_URL_PATH"],
	])("%j → %s", (path, name) => {
		expect(environmentVariableFor(path)).toBe(name);
	});
});
