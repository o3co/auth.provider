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
 * The relocated-path refusals: what a configuration value sets
 * (`pathsSetBy`), the keys a configuration still sets at a path a module
 * moved or removed (`findRelocatedKeys`), the words a moved or removed key is
 * refused in, and the variable a path is bound to.
 */
import { describe, expect, it } from "vitest";
import { environmentVariableFor } from "#/config/environment-variable.mjs";
import {
	findRelocatedKeys,
	pathsSetBy,
	relocatedKeyMessage,
	renamedVariableMessage,
	unreadSectionMessage,
} from "#/config/removed-keys.mjs";

describe("pathsSetBy — what a configuration value sets", () => {
	const set = (value: unknown) => pathsSetBy(value, ["at"]).map((path) => path.join("."));

	it("is one path for a value, a list of values (an empty one too) and data that is not plain", () => {
		for (const value of [1, "x", null, false, [1, 2], [], new Date(0)]) {
			expect(set(value), JSON.stringify(value)).toEqual(["at"]);
		}
	});

	it("walks a section and a list of sections, each index a key", () => {
		expect(set({ a: 1, b: { c: "x" }, d: [{ e: 1 }, { f: 2 }] })).toEqual([
			"at.a",
			"at.b.c",
			"at.d.0.e",
			"at.d.1.f",
		]);
	});

	it("is nothing for an empty section, one holding only empty sections, or a list of empty sections", () => {
		for (const value of [{}, { a: {} }, { a: { b: {} } }, { list: [{}] }]) {
			expect(set(value), JSON.stringify(value)).toEqual([]);
		}
	});
});

describe("findRelocatedKeys — a key that moved", () => {
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

	it("reads a list of values as one value, and a list of objects element by element, each index a key", () => {
		expect(
			findRelocatedKeys({ old: { list: [1, 2], empty: [] } }, [{ from: ["old"], to: ["new"] }]).map(
				({ from, to, environmentVariable }) => [from, to, environmentVariable],
			),
		).toEqual([
			["old.list", "new.list", "NEW_LIST"],
			["old.empty", "new.empty", "NEW_EMPTY"],
		]);
		expect(
			findRelocatedKeys({ old: { keys: [{ id: "a", key: "k" }] } }, [
				{ from: ["old"], to: ["new"] },
			]).map(({ from, to, environmentVariable }) => [from, to, environmentVariable]),
		).toEqual([
			["old.keys.0.id", "new.keys.0.id", "NEW_KEYS_0_ID"],
			["old.keys.0.key", "new.keys.0.key", "NEW_KEYS_0_KEY"],
		]);
	});

	it("names no variable for a value written at a path whose relocation moves it whole as a section", () => {
		expect(
			findRelocatedKeys({ old: null, other: { value: 1 } }, [
				{ from: ["old"], to: ["new"], toSection: true },
				{ from: ["other"], to: ["moved"], toSection: true },
			]).map(({ relocation: _, ...key }) => key),
		).toEqual([
			{ from: "old", to: "new" },
			{ from: "other.value", to: "moved.value", environmentVariable: "MOVED_VALUE" },
		]);
	});

	it("reads an empty subtree as nothing set: HOCON leaves {} where an unset variable was the only binding", () => {
		expect(findRelocatedKeys({ old: {} }, [{ from: ["old"], to: ["new"] }])).toEqual([]);
		expect(
			findRelocatedKeys({ old: { nested: {}, value: 1 } }, [{ from: ["old"], to: ["new"] }]).map(
				({ from }) => from,
			),
		).toEqual(["old.value"]);
	});

	it("reads a value that is not plain data — a Date, a URL — as one value, not walked into", () => {
		expect(
			findRelocatedKeys({ old: { at: new Date(0), url: new URL("https://x.example/") } }, [
				{ from: ["old"], to: ["new"] },
			]).map(({ from }) => from),
		).toEqual(["old.at", "old.url"]);
	});

	it("finds a key under each old path, a second one disjoint from the first included", () => {
		expect(
			findRelocatedKeys({ second: { value: 1 } }, [
				{ from: ["first"], to: ["new"] },
				{ from: ["second"], to: ["new", "moved"] },
			]).map(({ from, to }) => [from, to]),
		).toEqual([["second.value", "new.moved.value"]]);
	});

	it("reports a key removed rather than moved — a relocation to null — with no new path and no variable", () => {
		const pkce = ["oauth", "grants", "authorization_code", "pkce", "requireS256"];
		expect(
			findRelocatedKeys(
				{ oauth: { grants: { authorization_code: { pkce: { requireS256: true } } } } },
				[{ from: pkce, to: null }],
			).map(({ from, to, environmentVariable }) => [from, to, environmentVariable]),
		).toEqual([["oauth.grants.authorization_code.pkce.requireS256", null, undefined]]);
	});

	it("names no variable for a new path no variable binds yet: under a transitional section path", () => {
		expect(
			findRelocatedKeys({ old: { value: 1 } }, [
				{ from: ["old"], to: ["legacy", "current"], unbound: true },
			]).map(({ to, environmentVariable }) => [to, environmentVariable]),
		).toEqual([["legacy.current.value", undefined]]);
	});

	it("finds nothing where the configuration sets nothing, and reads own keys only", () => {
		expect(findRelocatedKeys({ oauth: {} }, [dpopMoved])).toEqual([]);
		expect(findRelocatedKeys({}, [{ from: ["constructor"], to: ["x"] }])).toEqual([]);
		expect(findRelocatedKeys(undefined, [dpopMoved])).toEqual([]);
	});

	it("says what moved where, or that it was removed, in the words a removed key is refused in", () => {
		expect(
			relocatedKeyMessage({
				from: "oauth.dpop.iat-window-seconds",
				to: "dpop.iatWindowSeconds",
				environmentVariable: "DPOP_IAT_WINDOW_SECONDS",
			}),
		).toBe(
			"oauth.dpop.iat-window-seconds has moved to dpop.iatWindowSeconds; see the upgrade guide (docs/upgrading-from-v0.16.0.md). " +
				"Write it there (environment variable DPOP_IAT_WINDOW_SECONDS) and remove this field from your config " +
				"(or unset the environment variable that sets it).",
		);
		expect(relocatedKeyMessage({ from: "old", to: "new" })).toBe(
			"old has moved to new; see the upgrade guide (docs/upgrading-from-v0.16.0.md). Write it there and remove this field from your config " +
				"(or unset the environment variable that sets it).",
		);
		expect(relocatedKeyMessage({ from: "old", to: null })).toBe(
			"old was removed; see the upgrade guide (docs/upgrading-from-v0.16.0.md). Remove this field from your config " +
				"(or unset the environment variable that sets it).",
		);
	});
});

describe("the refusals of a retired name — where they send the operator", () => {
	const GUIDE = "see the upgrade guide (docs/upgrading-from-v0.16.0.md).";
	const rename = { module: "core", from: "OLD", oldPath: "old", to: "NEW", path: "new" } as const;

	it("points every moved, removed or renamed name at the upgrade guide, never at the CHANGELOG", () => {
		const messages = [
			relocatedKeyMessage({ from: "old", to: "new", environmentVariable: "NEW" }),
			relocatedKeyMessage({ from: "old", to: null }),
			unreadSectionMessage("cors", "Provide httpSettings."),
			renamedVariableMessage({ ...rename, state: "unset" }),
			renamedVariableMessage({ ...rename, state: "different" }),
			renamedVariableMessage({ ...rename, to: null, path: null, state: "removed" }),
		];
		for (const message of messages) {
			expect(message).toContain(GUIDE);
			expect(message).not.toContain("CHANGELOG");
		}
	});
});

describe("environmentVariableFor — the variable a path is bound to", () => {
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
