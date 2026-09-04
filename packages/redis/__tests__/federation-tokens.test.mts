/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import {
	type FederationTokenStore,
	type FederationTokens,
	type SupportsLock,
	supportsLock,
} from "@o3co/auth-provider-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { encryptTokenField } from "#/internal/crypto.mjs";
import type { FederationTokenStoreClient } from "../src/clients.mjs";
import {
	createRedisFederationTokenStore,
	redisFederationTokenStoreBuilder,
} from "../src/federation-tokens.mjs";

function createFakeRedis() {
	const data = new Map<string, string>();
	// #291: the per-session key index lives in a SET, kept separate from the
	// string-valued envelopes so assertions on `data` still see only envelopes.
	const sets = new Map<string, Set<string>>();
	const ttls = new Map<string, number>();
	const removeKey = (k: string): number => {
		let removed = 0;
		if (data.delete(k)) removed += 1;
		if (sets.delete(k)) removed += 1;
		ttls.delete(k);
		return removed;
	};
	return {
		data,
		sets,
		ttls,
		get: vi.fn(async (k: string) => data.get(k) ?? null),
		// Positional form: (key, value, mode: "PX", ttlMs, condition?: "NX")
		set: vi.fn(
			async (
				k: string,
				v: string,
				_mode: "PX",
				ttl: number,
				condition?: "NX",
			): Promise<"OK" | null> => {
				if (condition === "NX" && data.has(k)) return null;
				data.set(k, v);
				ttls.set(k, ttl);
				return "OK";
			},
		),
		del: vi.fn(async (...keys: string[]) => keys.reduce((n, k) => n + removeKey(k), 0)),
		unlink: vi.fn(async (...keys: string[]) => keys.reduce((n, k) => n + removeKey(k), 0)),
		sAddWithTtl: vi.fn(async (key: string, member: string, ttlMs: number) => {
			const members = sets.get(key) ?? new Set<string>();
			members.add(member);
			sets.set(key, members);
			ttls.set(key, Math.max(ttls.get(key) ?? 0, ttlMs));
		}),
		sRem: vi.fn(async (key: string, member: string) => {
			const members = sets.get(key);
			if (!members) return 0;
			const removed = members.delete(member) ? 1 : 0;
			if (members.size === 0) sets.delete(key);
			return removed;
		}),
		sScanIterator: vi.fn((key: string, _opts?: { COUNT?: number }) => {
			const snapshot = [...(sets.get(key) ?? [])];
			return (async function* () {
				for (const member of snapshot) yield member;
			})();
		}),
		scanIterator: vi.fn((opts: { MATCH: string; COUNT?: number }) => {
			const prefix = opts.MATCH.endsWith("*") ? opts.MATCH.slice(0, -1) : opts.MATCH;
			const matched = [...data.keys()].filter((k) => k.startsWith(prefix));
			return (async function* () {
				for (const k of matched) yield k;
			})();
		}),
		compareAndDelete: vi.fn(async (k: string, expected: string): Promise<boolean> => {
			const stored = data.get(k);
			if (stored !== undefined && stored === expected) {
				data.delete(k);
				return true;
			}
			return false;
		}),
	} satisfies FederationTokenStoreClient & {
		data: Map<string, string>;
		sets: Map<string, Set<string>>;
		ttls: Map<string, number>;
	};
}

const encryptionKey = Buffer.alloc(32, 7);
const tokens: FederationTokens = {
	accessToken: "at",
	refreshToken: "rt-secret",
	idToken: "it",
	expiresAt: new Date(Date.now() + 3600_000),
};

describe("redis FederationTokenStore (encryption = required)", () => {
	let redis: ReturnType<typeof createFakeRedis>;
	beforeEach(() => {
		redis = createFakeRedis();
	});

	it("kind is 'redis'", () => {
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "required", key: encryptionKey },
		});
		expect(store.kind).toBe("redis");
	});

	it("attach encrypts refreshToken at rest", async () => {
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "required", key: encryptionKey },
		});
		await store.attach("sid-1", "google", tokens);
		const values = [...redis.data.values()];
		expect(values).toHaveLength(1);
		const raw = values[0] as string;
		expect(raw).not.toContain("rt-secret");
		// round-trip
		expect(await store.get("sid-1", "google")).toEqual(tokens);
	});

	it("removeBySid removes all federations for sid", async () => {
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "required", key: encryptionKey },
		});
		await store.attach("sid-1", "google", tokens);
		await store.attach("sid-1", "github", tokens);
		await store.attach("sid-2", "google", tokens);
		await store.removeBySid("sid-1");
		expect(await store.get("sid-1", "google")).toBeNull();
		expect(await store.get("sid-1", "github")).toBeNull();
		expect(await store.get("sid-2", "google")).toEqual(tokens);
	});

	it("missing encryption key throws at construction", () => {
		expect(() =>
			createRedisFederationTokenStore({
				client: redis,
				encryption: { mode: "required", key: Buffer.alloc(0) },
			}),
		).toThrow(/encryption key/i);
	});

	it("rejects ttl: 0 at construction", () => {
		expect(() =>
			createRedisFederationTokenStore({
				client: redis,
				encryption: { mode: "allow-plaintext" },
				ttl: 0,
			}),
		).toThrow(/ttl must be a positive finite number/i);
	});

	it("rejects ttl: -1 at construction", () => {
		expect(() =>
			createRedisFederationTokenStore({
				client: redis,
				encryption: { mode: "allow-plaintext" },
				ttl: -1,
			}),
		).toThrow(/ttl must be a positive finite number/i);
	});

	it("rejects ttl: NaN at construction", () => {
		expect(() =>
			createRedisFederationTokenStore({
				client: redis,
				encryption: { mode: "allow-plaintext" },
				ttl: Number.NaN,
			}),
		).toThrow(/ttl must be a positive finite number/i);
	});

	it("rejects ttl: Infinity at construction", () => {
		expect(() =>
			createRedisFederationTokenStore({
				client: redis,
				encryption: { mode: "allow-plaintext" },
				ttl: Number.POSITIVE_INFINITY,
			}),
		).toThrow(/ttl must be a positive finite number/i);
	});
});

describe("redis FederationTokenStore (encryption = allow-plaintext)", () => {
	let redis: ReturnType<typeof createFakeRedis>;
	beforeEach(() => {
		redis = createFakeRedis();
	});

	it("attach stores refreshToken in clear (opt-in)", async () => {
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});
		await store.attach("sid-1", "google", tokens);
		const values = [...redis.data.values()];
		expect(values).toHaveLength(1);
		const raw = values[0] as string;
		expect(raw).toContain("rt-secret");
		expect(await store.get("sid-1", "google")).toEqual(tokens);
	});

	it("get() self-heals corrupt JSON by deleting the key (Copilot round 3 #5)", async () => {
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});
		redis.data.set("ft:sid-1:google", "{not-json");
		expect(await store.get("sid-1", "google")).toBeNull();
		expect(redis.del).toHaveBeenCalledWith("ft:sid-1:google");
		expect(redis.data.has("ft:sid-1:google")).toBe(false);
	});

	it("get() self-heals an empty-string value like corrupt JSON — key deleted, index member dropped (#473)", async () => {
		// `""` is a value Redis can hold and `JSON.parse` cannot read. It used
		// to be answered as `null` before `open()` ran, so the key stayed and
		// so did its index member: a record that is never served and never
		// reclaimed until the TTL, and a `removeBySid` that keeps naming it.
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});
		await store.attach("sid-1", "google", tokens);
		redis.data.set("ft:sid-1:google", "");
		expect(await store.get("sid-1", "google")).toBeNull();
		expect(redis.del).toHaveBeenCalledWith("ft:sid-1:google");
		expect(redis.data.has("ft:sid-1:google")).toBe(false);
		expect([...(redis.sets.get("ft:idx:sid-1") ?? [])]).toEqual([]);
	});

	it("get() self-heals when decryption fails (wrong / rotated encryption key)", async () => {
		const keyA = Buffer.alloc(32, 1);
		const keyB = Buffer.alloc(32, 2);
		// Encrypt with keyA, try to read with keyB.
		const writer = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "required", key: keyA },
		});
		await writer.attach("sid-1", "google", tokens);
		const reader = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "required", key: keyB },
		});
		expect(await reader.get("sid-1", "google")).toBeNull();
		// The corrupt key is now gone so the next get also returns null naturally.
		expect(redis.data.has("ft:sid-1:google")).toBe(false);
	});
});

describe("redis FederationTokenStore implements SupportsLock", () => {
	it("supportsLock returns true for the redis store", () => {
		const redis = createFakeRedis();
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});
		expect(supportsLock(store)).toBe(true);
	});

	it("acquireLock returns acquired: true and release cleans up", async () => {
		const redis = createFakeRedis();
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});
		const r = await (store as FederationTokenStore & SupportsLock).acquireLock({
			sid: "s",
			federationName: "google",
		});
		expect(r.acquired).toBe(true);
		if (r.acquired) await r.release();
		// After release the lock key is gone (uses lock: namespace, not ft: namespace).
		const lockKeys = [...redis.data.keys()].filter((k) => k.includes("lock:"));
		expect(lockKeys).toHaveLength(0);
	});

	it("lock key uses the lock: sub-namespace, not the token envelope namespace", async () => {
		const redis = createFakeRedis();
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});
		await store.attach("s", "google", {
			accessToken: "at",
			expiresAt: new Date(Date.now() + 3600_000),
		});
		const r = await (store as FederationTokenStore & SupportsLock).acquireLock({
			sid: "s",
			federationName: "google",
		});
		expect(r.acquired).toBe(true);
		// The lock key contains "lock:" and the token envelope key does not.
		const lockKeys = [...redis.data.keys()].filter((k) => k.includes("lock:"));
		const tokenKeys = [...redis.data.keys()].filter((k) => !k.includes("lock:"));
		expect(lockKeys).toHaveLength(1);
		expect(tokenKeys).toHaveLength(1);
		expect(lockKeys[0]).toContain("ft:lock:");
		expect(tokenKeys[0]).toMatch(/^ft:s:google$/);
		if (r.acquired) await r.release();
	});
});

describe("redis FederationTokenStore TTL is independent of access_token expiry", () => {
	let redis: ReturnType<typeof createFakeRedis>;
	beforeEach(() => {
		redis = createFakeRedis();
	});

	it("default TTL (24h) is used regardless of tokens.expiresAt", async () => {
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});
		// Access token expires in 1 hour, but the record must live long enough
		// for the refresh_token to be usable after that.
		const shortLivedAT: FederationTokens = {
			accessToken: "at",
			refreshToken: "rt",
			expiresAt: new Date(Date.now() + 3600_000),
		};
		await store.attach("sid-1", "google", shortLivedAT);
		const ttl = redis.ttls.get("ft:sid-1:google");
		expect(ttl).toBe(86400 * 1000); // 24h in ms, NOT 1h
	});

	it("custom TTL option is honored", async () => {
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "allow-plaintext" },
			ttl: 7200, // 2h
		});
		await store.attach("sid-1", "google", tokens);
		expect(redis.ttls.get("ft:sid-1:google")).toBe(7200 * 1000);
	});

	it("access token expiresAt is preserved in the envelope for consumer refresh decisions", async () => {
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});
		const accessTokenExpiry = new Date(Date.now() + 1800_000); // 30min
		await store.attach("sid-1", "google", { ...tokens, expiresAt: accessTokenExpiry });
		const round = await store.get("sid-1", "google");
		expect(round?.expiresAt).toBeInstanceOf(Date);
		expect((round?.expiresAt as Date | undefined)?.getTime()).toBe(accessTokenExpiry.getTime());
	});

	it("expiresAt=null round-trips as null (GitHub OAuth Apps classic)", async () => {
		// Regression: FederationTokens.expiresAt is `Date | null` (required).
		// `null` MUST persist as `null` in the envelope and deserialize back to `null`,
		// so F-6 refresh logic can reliably detect "no finite expiry" without falling
		// through to a Date-instanceof check that would silently convert to
		// `new Date(null)` === epoch.
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});
		await store.attach("sid-gh", "github", { ...tokens, expiresAt: null });
		const round = await store.get("sid-gh", "github");
		expect(round?.expiresAt).toBeNull();
	});
});

// ---------------------------------------------------------------------------
// OR-12 — federation-tokens production guard for `allow-plaintext` mode
// ---------------------------------------------------------------------------

describe("OR-12 — redisFederationTokenStoreBuilder env-based encryption guard", () => {
	let origEnv: string | undefined;
	let origInsecure: string | undefined;
	let warnSpy: ReturnType<typeof vi.spyOn>;
	let errorSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		origEnv = process.env.NODE_ENV;
		origInsecure = process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
		warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
	});

	afterEach(() => {
		if (origEnv === undefined) delete process.env.NODE_ENV;
		else process.env.NODE_ENV = origEnv;
		if (origInsecure === undefined) delete process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
		else process.env.FEDERATION_TOKENS_ALLOW_INSECURE = origInsecure;
		warnSpy.mockRestore();
		errorSpy.mockRestore();
	});

	const mockClient = createFakeRedis() as unknown as FederationTokenStoreClient;

	it("throws when NODE_ENV=production and mode=allow-plaintext (no override)", () => {
		process.env.NODE_ENV = "production";
		delete process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
		expect(() =>
			redisFederationTokenStoreBuilder(
				{ client: mockClient, encryption: { mode: "allow-plaintext" } },
				{},
			),
		).toThrow(/mode "allow-plaintext" is refused because the environment is "production"/);
	});

	it("throws when NODE_ENV=staging and mode=allow-plaintext (no override)", () => {
		process.env.NODE_ENV = "staging";
		delete process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
		expect(() =>
			redisFederationTokenStoreBuilder(
				{ client: mockClient, encryption: { mode: "allow-plaintext" } },
				{},
			),
		).toThrow(/mode "allow-plaintext" is refused because the environment is "staging"/);
	});

	it("succeeds in production with FEDERATION_TOKENS_ALLOW_INSECURE=1 escape hatch (emits CRITICAL)", () => {
		process.env.NODE_ENV = "production";
		process.env.FEDERATION_TOKENS_ALLOW_INSECURE = "1";
		expect(() =>
			redisFederationTokenStoreBuilder(
				{ client: mockClient, encryption: { mode: "allow-plaintext" } },
				{},
			),
		).not.toThrow();
		expect(errorSpy).toHaveBeenCalledWith(
			expect.stringContaining("FEDERATION_TOKENS_ALLOW_INSECURE=1"),
		);
	});

	it("succeeds in development with allow-plaintext (warn-only)", () => {
		process.env.NODE_ENV = "development";
		delete process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
		expect(() =>
			redisFederationTokenStoreBuilder(
				{ client: mockClient, encryption: { mode: "allow-plaintext" } },
				{},
			),
		).not.toThrow();
		expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("allow-plaintext"));
	});

	it("succeeds silently with mode=required in production (no warn, no throw)", () => {
		process.env.NODE_ENV = "production";
		delete process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
		const key32 = Buffer.alloc(32, 1).toString("base64");
		expect(() =>
			redisFederationTokenStoreBuilder(
				{
					client: mockClient,
					encryption: { mode: "required", key: key32 },
				},
				{},
			),
		).not.toThrow();
		expect(warnSpy).not.toHaveBeenCalled();
		expect(errorSpy).not.toHaveBeenCalled();
	});

	// I-1 (multi-agent-review M2): the lower-level public factory
	// `createRedisFederationTokenStore` MUST run the same OR-12 production
	// guard as the builder. Pre-fix the guard only ran in the builder, so a
	// consumer calling the factory directly with `mode: "allow-plaintext"` in
	// production shipped unencrypted refresh tokens.
	it("createRedisFederationTokenStore (lower-level export) ALSO throws in production+allow-plaintext", () => {
		process.env.NODE_ENV = "production";
		delete process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
		const fake = createFakeRedis();
		expect(() =>
			createRedisFederationTokenStore({
				client: fake,
				encryption: { mode: "allow-plaintext" },
			}),
		).toThrow(/mode "allow-plaintext" is refused because the environment is "production"/);
	});
});

// ---------------------------------------------------------------------------
// #473 — the guard keyed off NODE_ENV alone. The standalone selects its config
// by `CONFIG_ENV || NODE_ENV`, so `CONFIG_ENV=production NODE_ENV=test` ran
// production.conf with the development guard; and `deployment.mode = "multi"`
// — a deployment that has said it runs more than one replica — could store
// upstream refresh tokens in clear because NODE_ENV happened to be unset.
// ---------------------------------------------------------------------------

describe("#473 — the plaintext guard reads the selected environment and deployment.mode", () => {
	let origEnv: string | undefined;
	let origInsecure: string | undefined;
	let warnSpy: ReturnType<typeof vi.spyOn>;
	let errorSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		origEnv = process.env.NODE_ENV;
		origInsecure = process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
		process.env.NODE_ENV = "development";
		delete process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
		warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
	});

	afterEach(() => {
		if (origEnv === undefined) delete process.env.NODE_ENV;
		else process.env.NODE_ENV = origEnv;
		if (origInsecure === undefined) delete process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
		else process.env.FEDERATION_TOKENS_ALLOW_INSECURE = origInsecure;
		warnSpy.mockRestore();
		errorSpy.mockRestore();
	});

	const plaintext = { mode: "allow-plaintext" } as const;

	it("refuses plaintext when the explicit environment is production, whatever NODE_ENV says", () => {
		// NODE_ENV=development (see beforeEach): the config was selected by
		// CONFIG_ENV=production, and that is the environment that counts.
		expect(() =>
			createRedisFederationTokenStore({
				client: createFakeRedis(),
				encryption: plaintext,
				environment: "production",
			}),
		).toThrow(/mode "allow-plaintext" is refused because the environment is "production"/);
	});

	it("still refuses on NODE_ENV=production when the explicit environment is not — the guard unions the two", () => {
		// Passing an environment adds a signal; it does not take NODE_ENV's
		// away. A process that says production anywhere is production.
		process.env.NODE_ENV = "production";
		expect(() =>
			createRedisFederationTokenStore({
				client: createFakeRedis(),
				encryption: plaintext,
				environment: "development",
			}),
		).toThrow(/mode "allow-plaintext" is refused because the environment is "production"/);
	});

	it("falls back to NODE_ENV when no environment is passed", () => {
		process.env.NODE_ENV = "staging";
		expect(() =>
			createRedisFederationTokenStore({ client: createFakeRedis(), encryption: plaintext }),
		).toThrow(/the environment is "staging"/);
	});

	it('refuses plaintext under deployment.mode = "multi" regardless of environment', () => {
		expect(() =>
			createRedisFederationTokenStore({
				client: createFakeRedis(),
				encryption: plaintext,
				environment: "development",
				deploymentMode: "multi",
			}),
		).toThrow(/mode "allow-plaintext" is refused because deployment\.mode is "multi"/);
	});

	it("names both reasons when both apply", () => {
		expect(() =>
			createRedisFederationTokenStore({
				client: createFakeRedis(),
				encryption: plaintext,
				environment: "production",
				deploymentMode: "multi",
			}),
		).toThrow(/the environment is "production" and deployment\.mode is "multi"/);
	});

	it('warns and continues under deployment.mode = "single" in development', () => {
		expect(() =>
			createRedisFederationTokenStore({
				client: createFakeRedis(),
				encryption: plaintext,
				environment: "development",
				deploymentMode: "single",
			}),
		).not.toThrow();
		expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("allow-plaintext"));
		expect(errorSpy).not.toHaveBeenCalled();
	});

	it("keeps the FEDERATION_TOKENS_ALLOW_INSECURE=1 escape hatch for the multi refusal too, at CRITICAL", () => {
		process.env.FEDERATION_TOKENS_ALLOW_INSECURE = "1";
		expect(() =>
			createRedisFederationTokenStore({
				client: createFakeRedis(),
				encryption: plaintext,
				deploymentMode: "multi",
			}),
		).not.toThrow();
		expect(errorSpy).toHaveBeenCalledWith(
			expect.stringMatching(/CRITICAL.*FEDERATION_TOKENS_ALLOW_INSECURE=1/),
		);
		expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('deployment.mode is "multi"'));
	});

	it("the builder forwards environment and deploymentMode to the same guard", () => {
		const client = createFakeRedis() as unknown as FederationTokenStoreClient;
		expect(() =>
			redisFederationTokenStoreBuilder(
				{ client, encryption: plaintext, environment: "production" },
				{},
			),
		).toThrow(/the environment is "production"/);
		expect(() =>
			redisFederationTokenStoreBuilder(
				{ client, encryption: plaintext, deploymentMode: "multi" },
				{},
			),
		).toThrow(/deployment\.mode is "multi"/);
	});

	it('mode = "required" is silent under multi in production — the guard is about plaintext only', () => {
		expect(() =>
			createRedisFederationTokenStore({
				client: createFakeRedis(),
				encryption: { mode: "required", key: encryptionKey },
				environment: "production",
				deploymentMode: "multi",
			}),
		).not.toThrow();
		expect(warnSpy).not.toHaveBeenCalled();
		expect(errorSpy).not.toHaveBeenCalled();
	});
});

// ---------------------------------------------------------------------------
// I-2 (multi-agent-review convergent — Claude + Codex P2): builder structural
// validator must reject clients missing `compareAndDelete`. Pre-fix a custom
// client missing this method passed the builder shape check then failed at
// first lock release with an obscure runtime TypeError.
// ---------------------------------------------------------------------------

describe("redisFederationTokenStoreBuilder structural validator", () => {
	it("rejects clients missing compareAndDelete with a clear message", () => {
		const oldShapeClient = {
			get: vi.fn(),
			set: vi.fn(),
			del: vi.fn(),
			unlink: vi.fn(),
			sAddWithTtl: vi.fn(),
			sRem: vi.fn(),
			sScanIterator: vi.fn(),
			scanIterator: vi.fn(),
			// compareAndDelete intentionally absent
		};
		expect(() =>
			redisFederationTokenStoreBuilder(
				{ client: oldShapeClient, encryption: { mode: "required", key: encryptionKey } },
				{},
			),
		).toThrow(/missing required method.*compareAndDelete/);
	});
});

// ---------------------------------------------------------------------------
// #293 — the whole envelope is encrypted, not just the token fields.
//
// Before this, `accessToken` / `refreshToken` / `idToken` were AES-256-GCM
// ciphertext and everything around them — `tokenType`, `scope`, `expiresAtMs`
// and above all `rawParams`, the upstream IdP's raw token response — sat in
// Redis as plaintext JSON beside them. These pin the record shape that
// replaces it (`{ v: 2, c: <ciphertext of the JSON envelope> }`), the
// drop-on-read of the legacy per-field shape, and the AAD binding of a
// ciphertext to the key it was written under.
// ---------------------------------------------------------------------------

// Every field FederationTokens can carry, with `rawParams` shaped like a real
// IdP token response: it repeats the tokens and adds whatever the IdP felt
// like including — the unbounded, provider-specific part #293 is about.
const fullTokens: FederationTokens = {
	accessToken: "at-secret",
	refreshToken: "rt-secret",
	idToken: "it-secret",
	expiresAt: new Date(1_900_000_000_000),
	tokenType: "Bearer",
	scope: "openid email",
	rawParams: {
		access_token: "at-secret",
		refresh_token: "rt-secret",
		id_token: "it-secret",
		token_type: "Bearer",
		scope: "openid email",
		expires_in: 3599,
		account_hint: "user@example.com",
		nested: { hint: "nested-hint" },
	},
};

// Values that used to reach Redis in clear (or, for the tokens, that must
// still not). Each is long enough that a chance match inside base64url
// ciphertext is not a realistic flake.
const plaintextMarkers = [
	"at-secret",
	"rt-secret",
	"it-secret",
	"openid email",
	"user@example.com",
	"nested-hint",
];

describe("#293 — mode=required stores one ciphertext over the whole envelope", () => {
	let redis: ReturnType<typeof createFakeRedis>;
	beforeEach(() => {
		redis = createFakeRedis();
	});
	const requiredStore = () =>
		createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "required", key: encryptionKey },
		});

	it("nothing but a version and a ciphertext reaches Redis", async () => {
		await requiredStore().attach("sid-1", "google", fullTokens);
		const raw = redis.data.get("ft:sid-1:google") as string;
		for (const marker of plaintextMarkers) expect(raw).not.toContain(marker);
		// The shape, not just the values: no envelope field name is visible.
		const record = JSON.parse(raw) as Record<string, unknown>;
		expect(Object.keys(record).sort()).toEqual(["c", "v"]);
		expect(record.v).toBe(2);
		expect(record.c).toMatch(/^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
	});

	it("round-trips every field, rawParams included", async () => {
		const store = requiredStore();
		await store.attach("sid-1", "google", fullTokens);
		expect(await store.get("sid-1", "google")).toEqual(fullTokens);
	});

	it("update() writes the same shape and round-trips too", async () => {
		const store = requiredStore();
		await store.attach("sid-1", "google", tokens);
		await store.update("sid-1", "google", fullTokens);
		const record = JSON.parse(redis.data.get("ft:sid-1:google") as string) as Record<
			string,
			unknown
		>;
		expect(Object.keys(record).sort()).toEqual(["c", "v"]);
		expect(await store.get("sid-1", "google")).toEqual(fullTokens);
	});

	it("round-trips expiresAt: null inside the encrypted envelope", async () => {
		const store = requiredStore();
		await store.attach("sid-gh", "github", { ...fullTokens, expiresAt: null });
		const round = await store.get("sid-gh", "github");
		expect(round?.expiresAt).toBeNull();
		expect(round?.rawParams).toEqual(fullTokens.rawParams);
	});

	it("drops a legacy per-field envelope on read: key gone, index member gone, null returned", async () => {
		const store = requiredStore();
		// Exactly what v0.11 and earlier wrote: token fields encrypted under the
		// SAME key, the envelope around them in clear. Same key on purpose — it
		// proves the record is dropped for its shape, not because it happens to
		// be undecryptable.
		redis.data.set(
			"ft:sid-1:google",
			JSON.stringify({
				accessToken: encryptTokenField("at-secret", encryptionKey),
				refreshToken: encryptTokenField("rt-secret", encryptionKey),
				expiresAtMs: null,
				tokenType: "Bearer",
				scope: "openid email",
				rawParams: { account_hint: "user@example.com" },
			}),
		);
		redis.sets.set("ft:idx:sid-1", new Set(["google", "github"]));

		expect(await store.get("sid-1", "google")).toBeNull();
		expect(redis.data.has("ft:sid-1:google")).toBe(false);
		expect(redis.sets.get("ft:idx:sid-1")?.has("google")).toBe(false);
		// The session's other federation is not collateral.
		expect(redis.sets.get("ft:idx:sid-1")?.has("github")).toBe(true);
	});

	it("refuses a plaintext v2 record — mode=required has no plaintext-readable path", async () => {
		const store = requiredStore();
		redis.data.set(
			"ft:sid-1:google",
			JSON.stringify({ v: 2, p: { accessToken: "at-secret", expiresAtMs: null } }),
		);
		expect(await store.get("sid-1", "google")).toBeNull();
		expect(redis.data.has("ft:sid-1:google")).toBe(false);
	});

	it("a ciphertext copied under another session's key fails to decrypt and self-heals (AAD)", async () => {
		const store = requiredStore();
		await store.attach("sid-1", "google", fullTokens);
		const bytes = redis.data.get("ft:sid-1:google") as string;

		redis.data.set("ft:sid-2:google", bytes);
		redis.sets.set("ft:idx:sid-2", new Set(["google"]));
		expect(await store.get("sid-2", "google")).toBeNull();
		expect(redis.data.has("ft:sid-2:google")).toBe(false);
		expect(redis.sets.has("ft:idx:sid-2")).toBe(false);

		// Same session, another federation name: still not the key it was sealed for.
		redis.data.set("ft:sid-1:github", bytes);
		expect(await store.get("sid-1", "github")).toBeNull();
		expect(redis.data.has("ft:sid-1:github")).toBe(false);

		// The record under its own key is untouched by all of that.
		expect(await store.get("sid-1", "google")).toEqual(fullTokens);
	});

	it("the binding is to the full Redis key, keyPrefix included", async () => {
		const writer = requiredStore();
		await writer.attach("sid-1", "google", fullTokens);
		const bytes = redis.data.get("ft:sid-1:google") as string;
		redis.data.set("other:sid-1:google", bytes);
		const reader = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "required", key: encryptionKey },
			keyPrefix: "other:",
		});
		expect(await reader.get("sid-1", "google")).toBeNull();
		expect(redis.data.has("other:sid-1:google")).toBe(false);
	});
});

describe("#293 — mode=allow-plaintext keeps the envelope as plain JSON (development only)", () => {
	let redis: ReturnType<typeof createFakeRedis>;
	beforeEach(() => {
		redis = createFakeRedis();
	});
	const plaintextStore = () =>
		createRedisFederationTokenStore({ client: redis, encryption: { mode: "allow-plaintext" } });

	it("round-trips every field, rawParams and expiresAt: null included", async () => {
		const store = plaintextStore();
		await store.attach("sid-1", "google", fullTokens);
		expect(await store.get("sid-1", "google")).toEqual(fullTokens);
		await store.attach("sid-gh", "github", { ...fullTokens, expiresAt: null });
		expect((await store.get("sid-gh", "github"))?.expiresAt).toBeNull();
	});

	it("is readable in clear, under the same versioned wrapper", async () => {
		await plaintextStore().attach("sid-1", "google", fullTokens);
		const raw = redis.data.get("ft:sid-1:google") as string;
		for (const marker of plaintextMarkers) expect(raw).toContain(marker);
		const record = JSON.parse(raw) as Record<string, unknown>;
		expect(Object.keys(record).sort()).toEqual(["p", "v"]);
		expect(record.v).toBe(2);
	});

	it("drops a legacy per-field envelope here too — one read path, no shape sniffing", async () => {
		const store = plaintextStore();
		redis.data.set(
			"ft:sid-1:google",
			JSON.stringify({ accessToken: "at-secret", expiresAtMs: null, scope: "openid" }),
		);
		redis.sets.set("ft:idx:sid-1", new Set(["google"]));
		expect(await store.get("sid-1", "google")).toBeNull();
		expect(redis.data.has("ft:sid-1:google")).toBe(false);
		expect(redis.sets.has("ft:idx:sid-1")).toBe(false);
	});

	it("refuses a ciphertext record — allow-plaintext has no key to read it with", async () => {
		const writer = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "required", key: encryptionKey },
		});
		await writer.attach("sid-1", "google", fullTokens);
		expect(await plaintextStore().get("sid-1", "google")).toBeNull();
		expect(redis.data.has("ft:sid-1:google")).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// #293 (PR #450 review) — the inner envelope is validated, not just the wrapper.
//
// `open()` checked only `{ v: 2, c | p }`. A v2 record whose inner envelope
// was malformed — an array, no `accessToken`, `expiresAtMs: "soon"` — got past
// it, and `fromEnvelope()` then returned `{ accessToken: undefined,
// expiresAt: Invalid Date }` instead of throwing, so the self-heal in `get()`
// never ran and the corrupt record stayed in Redis, returned on every read.
// Every malformed shape below must take the same path as corrupt JSON: key
// gone, index member gone, `null` returned — in both modes.
// ---------------------------------------------------------------------------

describe("#293 — a v2 record with a malformed inner envelope self-heals like corrupt JSON", () => {
	let redis: ReturnType<typeof createFakeRedis>;
	beforeEach(() => {
		redis = createFakeRedis();
	});

	type Mode = "required" | "allow-plaintext";
	const storeFor = (mode: Mode) =>
		createRedisFederationTokenStore({
			client: redis,
			encryption: mode === "required" ? { mode, key: encryptionKey } : { mode: "allow-plaintext" },
		});

	// Write a well-formed v2 wrapper around `innerJson` under `key`. Under
	// `required` the inner JSON is sealed with the right key and the right
	// AAD, so the only thing wrong with the record is its inner shape. The
	// inner bytes are spliced in verbatim in both modes — a JSON round-trip
	// here would turn `1e999` into `null` and hide the non-finite case.
	const writeV2 = (mode: Mode, key: string, innerJson: string) => {
		redis.data.set(
			key,
			mode === "required"
				? JSON.stringify({ v: 2, c: encryptTokenField(innerJson, encryptionKey, key) })
				: `{"v":2,"p":${innerJson}}`,
		);
	};

	const malformed: ReadonlyArray<[label: string, innerJson: string]> = [
		["an array", "[]"],
		["a string", '"at"'],
		["null", "null"],
		["missing accessToken", '{"expiresAtMs":null}'],
		["accessToken not a string", '{"accessToken":42,"expiresAtMs":null}'],
		["accessToken empty", '{"accessToken":"","expiresAtMs":null}'],
		["missing expiresAtMs", '{"accessToken":"at"}'],
		["expiresAtMs a string", '{"accessToken":"at","expiresAtMs":"soon"}'],
		// JSON.parse turns 1e999 into Infinity; new Date(Infinity) is Invalid Date.
		["expiresAtMs not finite", '{"accessToken":"at","expiresAtMs":1e999}'],
		["refreshToken not a string", '{"accessToken":"at","expiresAtMs":null,"refreshToken":42}'],
		["idToken not a string", '{"accessToken":"at","expiresAtMs":null,"idToken":{}}'],
		["tokenType not a string", '{"accessToken":"at","expiresAtMs":null,"tokenType":1}'],
		["scope not a string", '{"accessToken":"at","expiresAtMs":null,"scope":["openid"]}'],
		["rawParams an array", '{"accessToken":"at","expiresAtMs":null,"rawParams":[]}'],
		["rawParams a string", '{"accessToken":"at","expiresAtMs":null,"rawParams":"x"}'],
		["rawParams null", '{"accessToken":"at","expiresAtMs":null,"rawParams":null}'],
	];

	for (const mode of ["required", "allow-plaintext"] as const) {
		describe(`mode=${mode}`, () => {
			it.each(malformed)("inner envelope is %s", async (_label, innerJson) => {
				const store = storeFor(mode);
				writeV2(mode, "ft:sid-1:google", innerJson);
				redis.sets.set("ft:idx:sid-1", new Set(["google", "github"]));

				expect(await store.get("sid-1", "google")).toBeNull();
				expect(redis.data.has("ft:sid-1:google")).toBe(false);
				expect(redis.sets.get("ft:idx:sid-1")?.has("google")).toBe(false);
				expect(redis.sets.get("ft:idx:sid-1")?.has("github")).toBe(true);
			});

			it("still reads the minimal valid envelope — optional fields may be absent", async () => {
				const store = storeFor(mode);
				writeV2(mode, "ft:sid-1:google", '{"accessToken":"at","expiresAtMs":null}');
				expect(await store.get("sid-1", "google")).toEqual({
					accessToken: "at",
					expiresAt: null,
				});
				expect(redis.data.has("ft:sid-1:google")).toBe(true);
			});

			it("still reads a finite expiresAtMs as a Date", async () => {
				const store = storeFor(mode);
				writeV2(mode, "ft:sid-1:google", '{"accessToken":"at","expiresAtMs":1900000000000}');
				expect((await store.get("sid-1", "google"))?.expiresAt).toEqual(
					new Date(1_900_000_000_000),
				);
			});
		});
	}
});
