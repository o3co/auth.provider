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
import type {
	FederationTokenRemoveIfInput,
	FederationTokenReplaceIfInput,
	FederationTokenStoreClient,
} from "#/clients.mjs";
import {
	createRedisFederationTokenStore,
	redisFederationTokenStoreBuilder,
} from "#/federation-tokens.mjs";
import { encryptTokenField } from "#/internal/crypto.mjs";

/** The `g` a stored value carries, as the scripts read it. */
const generationIn = (raw: string): string | undefined => {
	try {
		const record = JSON.parse(raw) as Record<string, unknown> | null;
		const g = record?.g;
		return typeof g === "string" ? g : undefined;
	} catch {
		return undefined;
	}
};

/** Whether a stored value is a JSON object with no `g`: what the versioned read mints into. */
const lacksGeneration = (raw: string): boolean => {
	try {
		const record = JSON.parse(raw) as unknown;
		return record !== null && typeof record === "object" && !("g" in record);
	} catch {
		return false;
	}
};

function createFakeRedis() {
	const data = new Map<string, string>();
	// The per-session key index lives in a SET, kept separate from the
	// string-valued envelopes so assertions on `data` still see only envelopes.
	const sets = new Map<string, Set<string>>();
	const ttls = new Map<string, number>();
	// Each conditional write's answer, by its replay key, as the scripts keep it.
	const replays = new Map<string, string>();
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
		) as FederationTokenStoreClient["set"],
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
		// The scripts' semantics, in process: the generation is the wrapper's `g`.
		readVersioned: vi.fn(async (k: string, candidate: string) => {
			const stored = data.get(k);
			if (stored === undefined) return null;
			const g = generationIn(stored);
			if (g !== undefined) return { raw: stored, generation: g };
			if (stored.startsWith('{"v":2,') && lacksGeneration(stored)) {
				const minted = `{"g":${JSON.stringify(candidate)},${stored.slice(1)}`;
				data.set(k, minted);
				return { raw: minted, generation: candidate };
			}
			return { raw: stored, generation: "" };
		}),
		replaceIfGeneration: vi.fn(async (k: string, input: FederationTokenReplaceIfInput) => {
			if (Date.now() > input.deadlineMs) return "late" as const;
			const kept = replays.get(input.replayKey) as "updated" | "missing" | "conflict" | undefined;
			if (kept !== undefined) return kept;
			const stored = data.get(k);
			let answer: "updated" | "missing" | "conflict" = "updated";
			if (stored === undefined) answer = "missing";
			else if (generationIn(stored) !== input.expected) answer = "conflict";
			else {
				data.set(k, input.value);
				ttls.set(k, input.ttlMs);
			}
			replays.set(input.replayKey, answer);
			return answer;
		}),
		removeIfGeneration: vi.fn(async (k: string, input: FederationTokenRemoveIfInput) => {
			if (Date.now() > input.deadlineMs) return "late" as const;
			const kept = replays.get(input.replayKey) as "removed" | "missing" | "conflict" | undefined;
			if (kept !== undefined) return kept;
			const stored = data.get(k);
			let answer: "removed" | "missing" | "conflict" = "removed";
			if (stored === undefined) answer = "missing";
			else if (generationIn(stored) !== input.expected) answer = "conflict";
			else removeKey(k);
			replays.set(input.replayKey, answer);
			return answer;
		}),
		pExpireGT: vi.fn(async (key: string, ttlMs: number) => {
			const held = ttls.get(key);
			if (held !== undefined && held < ttlMs) ttls.set(key, ttlMs);
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
	tokenType: undefined,
	scope: undefined,
	grantedScope: undefined,
};

describe("redis FederationTokenStore (encryption = required)", () => {
	let redis: ReturnType<typeof createFakeRedis>;
	beforeEach(() => {
		redis = createFakeRedis();
	});

	it("kind is 'redis'", () => {
		const store = createRedisFederationTokenStore({
			deploymentMode: "unset",
			client: redis,
			encryption: { mode: "required", key: encryptionKey },
		});
		expect(store.kind).toBe("redis");
	});

	it("attach encrypts refreshToken at rest", async () => {
		const store = createRedisFederationTokenStore({
			deploymentMode: "unset",
			client: redis,
			encryption: { mode: "required", key: encryptionKey },
		});
		await store.attach("sid-1", "google", tokens);
		const values = [...redis.data.values()];
		expect(values).toHaveLength(1);
		const raw = values[0] as string;
		expect(raw).not.toContain("rt-secret");
		// round-trip
		expect(await store.get("sid-1", "google")).toStrictEqual(tokens);
	});

	it("round-trips grantedScope, and a record written without one", async () => {
		// The ceiling a refresh is bounded by has to survive the store, and a
		// record written before the field existed has to keep opening.
		const store = createRedisFederationTokenStore({
			deploymentMode: "unset",
			client: redis,
			encryption: { mode: "required", key: encryptionKey },
		});
		const withCeiling = { ...tokens, scope: "openid", grantedScope: "openid email" };
		await store.attach("sid-1", "google", withCeiling);
		expect(await store.get("sid-1", "google")).toStrictEqual(withCeiling);

		await store.attach("sid-2", "google", tokens);
		const legacy = await store.get("sid-2", "google");
		expect(legacy?.grantedScope).toBeUndefined();
	});

	it("removeBySid removes all federations for sid", async () => {
		const store = createRedisFederationTokenStore({
			deploymentMode: "unset",
			client: redis,
			encryption: { mode: "required", key: encryptionKey },
		});
		await store.attach("sid-1", "google", tokens);
		await store.attach("sid-1", "github", tokens);
		await store.attach("sid-2", "google", tokens);
		await store.removeBySid("sid-1");
		expect(await store.get("sid-1", "google")).toBeNull();
		expect(await store.get("sid-1", "github")).toBeNull();
		expect(await store.get("sid-2", "google")).toStrictEqual(tokens);
	});

	it("missing encryption key throws at construction", () => {
		expect(() =>
			createRedisFederationTokenStore({
				deploymentMode: "unset",
				client: redis,
				encryption: { mode: "required", key: Buffer.alloc(0) },
			}),
		).toThrow(/encryption key/i);
	});

	it("names itself when it refuses plaintext: the guard is shared, the message is not", () => {
		// The guard lives in `internal/encryption-mode.mts` and the federation
		// grant store uses it too, with its own label. An operator reading
		// a boot failure has to be told which store refused.
		const previous = process.env.NODE_ENV;
		process.env.NODE_ENV = "production";
		try {
			expect(() =>
				createRedisFederationTokenStore({
					deploymentMode: "unset",
					client: redis,
					encryption: { mode: "allow-plaintext" },
				}),
			).toThrow(/\[federation-tokens\] mode "allow-plaintext" is refused/);
		} finally {
			if (previous === undefined) delete process.env.NODE_ENV;
			else process.env.NODE_ENV = previous;
		}
	});

	it("refuses an unusable ttl with a RangeError, as the shared expiry rule refuses every lifetime", () => {
		for (const ttl of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, 1e13]) {
			expect(
				() =>
					createRedisFederationTokenStore({
						deploymentMode: "unset",
						client: redis,
						encryption: { mode: "allow-plaintext" },
						ttl,
					}),
				String(ttl),
			).toThrow(RangeError);
		}
	});

	it("rejects ttl: 0 at construction", () => {
		expect(() =>
			createRedisFederationTokenStore({
				deploymentMode: "unset",
				client: redis,
				encryption: { mode: "allow-plaintext" },
				ttl: 0,
			}),
		).toThrow(/ttl must be a positive finite number/i);
	});

	it("rejects ttl: -1 at construction", () => {
		expect(() =>
			createRedisFederationTokenStore({
				deploymentMode: "unset",
				client: redis,
				encryption: { mode: "allow-plaintext" },
				ttl: -1,
			}),
		).toThrow(/ttl must be a positive finite number/i);
	});

	it("rejects ttl: NaN at construction", () => {
		expect(() =>
			createRedisFederationTokenStore({
				deploymentMode: "unset",
				client: redis,
				encryption: { mode: "allow-plaintext" },
				ttl: Number.NaN,
			}),
		).toThrow(/ttl must be a positive finite number/i);
	});

	it("rejects ttl: Infinity at construction", () => {
		expect(() =>
			createRedisFederationTokenStore({
				deploymentMode: "unset",
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
			deploymentMode: "unset",
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});
		await store.attach("sid-1", "google", tokens);
		const values = [...redis.data.values()];
		expect(values).toHaveLength(1);
		const raw = values[0] as string;
		expect(raw).toContain("rt-secret");
		expect(await store.get("sid-1", "google")).toStrictEqual(tokens);
	});

	it("get() self-heals corrupt JSON by deleting the key, only while it holds the bytes read", async () => {
		const store = createRedisFederationTokenStore({
			deploymentMode: "unset",
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});
		redis.data.set("ft:sid-1:google", "{not-json");
		expect(await store.get("sid-1", "google")).toBeNull();
		expect(redis.compareAndDelete).toHaveBeenCalledWith("ft:sid-1:google", "{not-json");
		expect(redis.del).not.toHaveBeenCalled();
		expect(redis.data.has("ft:sid-1:google")).toBe(false);
	});

	it("get() self-heals an empty-string value like corrupt JSON — key deleted, index member kept", async () => {
		// `""` is a value Redis can hold and `JSON.parse` cannot read. Answered
		// as `null` before `open()` ran, it would keep the key: a record that is
		// never served and never reclaimed until the TTL. The index member stays:
		// a concurrent `attach` may have just added it.
		const store = createRedisFederationTokenStore({
			deploymentMode: "unset",
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});
		await store.attach("sid-1", "google", tokens);
		redis.data.set("ft:sid-1:google", "");
		expect(await store.get("sid-1", "google")).toBeNull();
		expect(redis.compareAndDelete).toHaveBeenCalledWith("ft:sid-1:google", "");
		expect(redis.data.has("ft:sid-1:google")).toBe(false);
		expect([...(redis.sets.get("ft:idx:sid-1") ?? [])]).toEqual(["google"]);
	});

	it("get() self-heals when decryption fails (wrong / rotated encryption key)", async () => {
		const keyA = Buffer.alloc(32, 1);
		const keyB = Buffer.alloc(32, 2);
		// Encrypt with keyA, try to read with keyB.
		const writer = createRedisFederationTokenStore({
			deploymentMode: "unset",
			client: redis,
			encryption: { mode: "required", key: keyA },
		});
		await writer.attach("sid-1", "google", tokens);
		const reader = createRedisFederationTokenStore({
			deploymentMode: "unset",
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
			deploymentMode: "unset",
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});
		expect(supportsLock(store)).toBe(true);
	});

	it("acquireLock returns acquired: true and release cleans up", async () => {
		const redis = createFakeRedis();
		const store = createRedisFederationTokenStore({
			deploymentMode: "unset",
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
			deploymentMode: "unset",
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});
		await store.attach("s", "google", {
			accessToken: "at",
			expiresAt: new Date(Date.now() + 3600_000),
			refreshToken: undefined,
			idToken: undefined,
			tokenType: undefined,
			scope: undefined,
			grantedScope: undefined,
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
			deploymentMode: "unset",
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});
		// Access token expires in 1 hour, but the record must live long enough
		// for the refresh_token to be usable after that.
		const shortLivedAT: FederationTokens = {
			accessToken: "at",
			refreshToken: "rt",
			expiresAt: new Date(Date.now() + 3600_000),
			idToken: undefined,
			tokenType: undefined,
			scope: undefined,
			grantedScope: undefined,
		};
		await store.attach("sid-1", "google", shortLivedAT);
		const ttl = redis.ttls.get("ft:sid-1:google");
		expect(ttl).toBe(86400 * 1000); // 24h in ms, NOT 1h
	});

	it("custom TTL option is honored", async () => {
		const store = createRedisFederationTokenStore({
			deploymentMode: "unset",
			client: redis,
			encryption: { mode: "allow-plaintext" },
			ttl: 7200, // 2h
		});
		await store.attach("sid-1", "google", tokens);
		expect(redis.ttls.get("ft:sid-1:google")).toBe(7200 * 1000);
	});

	it("access token expiresAt is preserved in the envelope for consumer refresh decisions", async () => {
		const store = createRedisFederationTokenStore({
			deploymentMode: "unset",
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
		// FederationTokens.expiresAt is `Date | null` (required). `null` MUST
		// persist as `null` in the envelope and read back as `null`, so refresh
		// logic can detect "no finite expiry" rather than get `new Date(null)`,
		// the epoch.
		const store = createRedisFederationTokenStore({
			deploymentMode: "unset",
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});
		await store.attach("sid-gh", "github", { ...tokens, expiresAt: null });
		const round = await store.get("sid-gh", "github");
		expect(round?.expiresAt).toBeNull();
	});
});

// ---------------------------------------------------------------------------
// The federation-tokens production guard for `allow-plaintext` mode
// ---------------------------------------------------------------------------

describe("redisFederationTokenStoreBuilder env-based encryption guard", () => {
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
				{ deploymentMode: "unset", client: mockClient, encryption: { mode: "allow-plaintext" } },
				{},
			),
		).toThrow(/mode "allow-plaintext" is refused because the environment is "production"/);
	});

	it("throws when NODE_ENV=staging and mode=allow-plaintext (no override)", () => {
		process.env.NODE_ENV = "staging";
		delete process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
		expect(() =>
			redisFederationTokenStoreBuilder(
				{ deploymentMode: "unset", client: mockClient, encryption: { mode: "allow-plaintext" } },
				{},
			),
		).toThrow(/mode "allow-plaintext" is refused because the environment is "staging"/);
	});

	it("succeeds in production with FEDERATION_TOKENS_ALLOW_INSECURE=1 escape hatch (logs federation_store_plaintext_override at error)", () => {
		process.env.NODE_ENV = "production";
		process.env.FEDERATION_TOKENS_ALLOW_INSECURE = "1";
		expect(() =>
			redisFederationTokenStoreBuilder(
				{ deploymentMode: "unset", client: mockClient, encryption: { mode: "allow-plaintext" } },
				{},
			),
		).not.toThrow();
		expect(errorSpy.mock.calls).toEqual([
			[
				expect.objectContaining({
					store: "federation-tokens",
					environment: "production",
					override: "FEDERATION_TOKENS_ALLOW_INSECURE",
				}),
				"federation_store_plaintext_override",
			],
		]);
	});

	it("succeeds in development with allow-plaintext (warn-only)", () => {
		process.env.NODE_ENV = "development";
		delete process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
		expect(() =>
			redisFederationTokenStoreBuilder(
				{ deploymentMode: "unset", client: mockClient, encryption: { mode: "allow-plaintext" } },
				{},
			),
		).not.toThrow();
		expect(warnSpy.mock.calls).toEqual([
			[{ store: "federation-tokens", mode: "allow-plaintext" }, "federation_store_plaintext"],
		]);
	});

	it("succeeds silently with mode=required in production (no warn, no throw)", () => {
		process.env.NODE_ENV = "production";
		delete process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
		const key32 = Buffer.alloc(32, 1).toString("base64");
		expect(() =>
			redisFederationTokenStoreBuilder(
				{
					deploymentMode: "unset",
					client: mockClient,
					encryption: { mode: "required", key: key32 },
				},
				{},
			),
		).not.toThrow();
		expect(warnSpy).not.toHaveBeenCalled();
		expect(errorSpy).not.toHaveBeenCalled();
	});

	// The lower-level public factory `createRedisFederationTokenStore` MUST
	// run the same production guard as the builder: otherwise a consumer
	// calling the factory directly with `mode: "allow-plaintext"` in
	// production ships unencrypted refresh tokens.
	it("createRedisFederationTokenStore (lower-level export) ALSO throws in production+allow-plaintext", () => {
		process.env.NODE_ENV = "production";
		delete process.env.FEDERATION_TOKENS_ALLOW_INSECURE;
		const fake = createFakeRedis();
		expect(() =>
			createRedisFederationTokenStore({
				deploymentMode: "unset",
				client: fake,
				encryption: { mode: "allow-plaintext" },
			}),
		).toThrow(/mode "allow-plaintext" is refused because the environment is "production"/);
	});
});

// ---------------------------------------------------------------------------
// The guard reads the selected environment and `core.deployment.mode`, not
// NODE_ENV alone. The standalone selects its config by
// `CONFIG_ENV || NODE_ENV`, so `CONFIG_ENV=production NODE_ENV=test` runs
// production.conf and must get the production guard; and under
// `core.deployment.mode = "multi"`, a deployment that has said it runs more than one
// replica, plaintext is refused regardless of environment unless
// FEDERATION_TOKENS_ALLOW_INSECURE=1 overrides it.
// ---------------------------------------------------------------------------

describe("the plaintext guard reads the selected environment and core.deployment.mode", () => {
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
				deploymentMode: "unset",
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
				deploymentMode: "unset",
				client: createFakeRedis(),
				encryption: plaintext,
				environment: "development",
			}),
		).toThrow(/mode "allow-plaintext" is refused because the environment is "production"/);
	});

	it("falls back to NODE_ENV when no environment is passed", () => {
		process.env.NODE_ENV = "staging";
		expect(() =>
			createRedisFederationTokenStore({
				deploymentMode: "unset",
				client: createFakeRedis(),
				encryption: plaintext,
			}),
		).toThrow(/the environment is "staging"/);
	});

	it('refuses plaintext under core.deployment.mode = "multi" regardless of environment', () => {
		expect(() =>
			createRedisFederationTokenStore({
				client: createFakeRedis(),
				encryption: plaintext,
				environment: "development",
				deploymentMode: "multi",
			}),
		).toThrow(/mode "allow-plaintext" is refused because core\.deployment\.mode is "multi"/);
	});

	it("names both reasons when both apply", () => {
		expect(() =>
			createRedisFederationTokenStore({
				client: createFakeRedis(),
				encryption: plaintext,
				environment: "production",
				deploymentMode: "multi",
			}),
		).toThrow(/the environment is "production" and core\.deployment\.mode is "multi"/);
	});

	it('warns and continues under core.deployment.mode = "single" in development', () => {
		expect(() =>
			createRedisFederationTokenStore({
				client: createFakeRedis(),
				encryption: plaintext,
				environment: "development",
				deploymentMode: "single",
			}),
		).not.toThrow();
		expect(warnSpy.mock.calls).toEqual([
			[{ store: "federation-tokens", mode: "allow-plaintext" }, "federation_store_plaintext"],
		]);
		expect(errorSpy).not.toHaveBeenCalled();
	});

	it("keeps the FEDERATION_TOKENS_ALLOW_INSECURE=1 escape hatch for the multi refusal too, logged at error", () => {
		process.env.FEDERATION_TOKENS_ALLOW_INSECURE = "1";
		expect(() =>
			createRedisFederationTokenStore({
				client: createFakeRedis(),
				encryption: plaintext,
				deploymentMode: "multi",
			}),
		).not.toThrow();
		expect(errorSpy.mock.calls).toEqual([
			[
				{
					store: "federation-tokens",
					mode: "allow-plaintext",
					deploymentMode: "multi",
					override: "FEDERATION_TOKENS_ALLOW_INSECURE",
				},
				"federation_store_plaintext_override",
			],
		]);
	});

	it("the builder forwards environment and deploymentMode to the same guard", () => {
		const client = createFakeRedis() as unknown as FederationTokenStoreClient;
		expect(() =>
			redisFederationTokenStoreBuilder(
				{ deploymentMode: "unset", client, encryption: plaintext, environment: "production" },
				{},
			),
		).toThrow(/the environment is "production"/);
		expect(() =>
			redisFederationTokenStoreBuilder(
				{ client, encryption: plaintext, deploymentMode: "multi" },
				{},
			),
		).toThrow(/core\.deployment\.mode is "multi"/);
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
// The builder's structural validator must reject clients missing
// `compareAndDelete`. Otherwise a custom client missing this method passes the
// builder shape check, then fails at the first lock release with an obscure
// runtime TypeError.
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
				{
					deploymentMode: "unset",
					client: oldShapeClient,
					encryption: { mode: "required", key: encryptionKey },
				},
				{},
			),
		).toThrow(/missing required method.*compareAndDelete/);
	});
});

// ---------------------------------------------------------------------------
// The whole envelope is encrypted, not just the token fields: `tokenType`,
// `scope` and `expiresAtMs` do not sit in Redis as plaintext beside the
// tokens. These pin the record shape (`{ v: 2, c: <ciphertext of the JSON
// envelope> }`), the drop-on-read of the legacy per-field shape, and the AAD
// binding of a ciphertext to the key it was written under.
// ---------------------------------------------------------------------------

// Every field FederationTokens can carry.
const fullTokens: FederationTokens = {
	accessToken: "at-secret",
	refreshToken: "rt-secret",
	idToken: "it-secret",
	expiresAt: new Date(1_900_000_000_000),
	tokenType: "Bearer",
	scope: "openid email",
	grantedScope: "openid email profile",
};

// Values that must not reach Redis in clear. Each is long enough that a
// chance match inside base64url ciphertext is not a realistic flake.
const plaintextMarkers = ["at-secret", "rt-secret", "it-secret", "openid email"];

describe("mode=required stores one ciphertext over the whole envelope", () => {
	let redis: ReturnType<typeof createFakeRedis>;
	beforeEach(() => {
		redis = createFakeRedis();
	});
	const requiredStore = () =>
		createRedisFederationTokenStore({
			deploymentMode: "unset",
			client: redis,
			encryption: { mode: "required", key: encryptionKey },
		});

	it("nothing but a version and a ciphertext reaches Redis", async () => {
		await requiredStore().attach("sid-1", "google", fullTokens);
		const raw = redis.data.get("ft:sid-1:google") as string;
		for (const marker of plaintextMarkers) expect(raw).not.toContain(marker);
		// The shape, not just the values: no envelope field name is visible.
		const record = JSON.parse(raw) as Record<string, unknown>;
		expect(Object.keys(record).sort()).toEqual(["c", "g", "v"]);
		expect(record.v).toBe(2);
		expect(record.c).toMatch(/^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
	});

	it("round-trips every field", async () => {
		const store = requiredStore();
		await store.attach("sid-1", "google", fullTokens);
		expect(await store.get("sid-1", "google")).toStrictEqual(fullTokens);
	});

	it("update() writes the same shape and round-trips too", async () => {
		const store = requiredStore();
		await store.attach("sid-1", "google", tokens);
		await store.update("sid-1", "google", fullTokens);
		const record = JSON.parse(redis.data.get("ft:sid-1:google") as string) as Record<
			string,
			unknown
		>;
		expect(Object.keys(record).sort()).toEqual(["c", "g", "v"]);
		expect(await store.get("sid-1", "google")).toStrictEqual(fullTokens);
	});

	it("round-trips expiresAt: null inside the encrypted envelope", async () => {
		const store = requiredStore();
		await store.attach("sid-gh", "github", { ...fullTokens, expiresAt: null });
		const round = await store.get("sid-gh", "github");
		expect(round?.expiresAt).toBeNull();
		expect(round?.accessToken).toBe(fullTokens.accessToken);
	});

	it("drops a legacy per-field envelope on read: key gone, index member kept, null returned", async () => {
		const store = requiredStore();
		// The legacy per-field shape: token fields encrypted under the SAME key,
		// the envelope around them in clear. Same key on purpose — it
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
		expect(redis.sets.get("ft:idx:sid-1")?.has("google")).toBe(true);
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
		// The index member stays: a concurrent attach may have just added it.
		expect(redis.sets.get("ft:idx:sid-2")?.has("google")).toBe(true);

		// Same session, another federation name: still not the key it was sealed for.
		redis.data.set("ft:sid-1:github", bytes);
		expect(await store.get("sid-1", "github")).toBeNull();
		expect(redis.data.has("ft:sid-1:github")).toBe(false);

		// The record under its own key is untouched by all of that.
		expect(await store.get("sid-1", "google")).toStrictEqual(fullTokens);
	});

	it("the binding is to the full Redis key, keyPrefix included", async () => {
		const writer = requiredStore();
		await writer.attach("sid-1", "google", fullTokens);
		const bytes = redis.data.get("ft:sid-1:google") as string;
		redis.data.set("other:sid-1:google", bytes);
		const reader = createRedisFederationTokenStore({
			deploymentMode: "unset",
			client: redis,
			encryption: { mode: "required", key: encryptionKey },
			keyPrefix: "other:",
		});
		expect(await reader.get("sid-1", "google")).toBeNull();
		expect(redis.data.has("other:sid-1:google")).toBe(false);
	});
});

describe("mode=allow-plaintext keeps the envelope as plain JSON (development only)", () => {
	let redis: ReturnType<typeof createFakeRedis>;
	beforeEach(() => {
		redis = createFakeRedis();
	});
	const plaintextStore = () =>
		createRedisFederationTokenStore({
			deploymentMode: "unset",
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});

	it("round-trips every field, expiresAt: null included", async () => {
		const store = plaintextStore();
		await store.attach("sid-1", "google", fullTokens);
		expect(await store.get("sid-1", "google")).toStrictEqual(fullTokens);
		await store.attach("sid-gh", "github", { ...fullTokens, expiresAt: null });
		expect((await store.get("sid-gh", "github"))?.expiresAt).toBeNull();
	});

	it("is readable in clear, under the same versioned wrapper", async () => {
		await plaintextStore().attach("sid-1", "google", fullTokens);
		const raw = redis.data.get("ft:sid-1:google") as string;
		for (const marker of plaintextMarkers) expect(raw).toContain(marker);
		const record = JSON.parse(raw) as Record<string, unknown>;
		expect(Object.keys(record).sort()).toEqual(["g", "p", "v"]);
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
		// The index member stays: a concurrent attach may have just added it.
		expect(redis.sets.get("ft:idx:sid-1")?.has("google")).toBe(true);
	});

	it("refuses a ciphertext record — allow-plaintext has no key to read it with", async () => {
		const writer = createRedisFederationTokenStore({
			deploymentMode: "unset",
			client: redis,
			encryption: { mode: "required", key: encryptionKey },
		});
		await writer.attach("sid-1", "google", fullTokens);
		expect(await plaintextStore().get("sid-1", "google")).toBeNull();
		expect(redis.data.has("ft:sid-1:google")).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// The inner envelope is validated, not just the wrapper. A check of
// `{ v: 2, c | p }` alone would pass a malformed inner envelope (an array, no
// `accessToken`, `expiresAtMs: "soon"`), `fromEnvelope()` would return
// `{ accessToken: undefined, expiresAt: Invalid Date }` instead of throwing,
// and the self-heal in `get()` would never run. Every malformed shape below
// takes the same path as corrupt JSON: key gone, index member kept, `null`
// returned, in both modes.
// ---------------------------------------------------------------------------

describe("a v2 record with a malformed inner envelope self-heals like corrupt JSON", () => {
	let redis: ReturnType<typeof createFakeRedis>;
	beforeEach(() => {
		redis = createFakeRedis();
	});

	type Mode = "required" | "allow-plaintext";
	const storeFor = (mode: Mode) =>
		createRedisFederationTokenStore({
			deploymentMode: "unset",
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
		["obtainedAtMs a string", '{"accessToken":"at","expiresAtMs":null,"obtainedAtMs":"soon"}'],
		// JSON.stringify writes NaN as null.
		["obtainedAtMs null", '{"accessToken":"at","expiresAtMs":null,"obtainedAtMs":null}'],
		["obtainedAtMs not finite", '{"accessToken":"at","expiresAtMs":null,"obtainedAtMs":1e999}'],
		[
			"obtainedAtMs past the Date range",
			'{"accessToken":"at","expiresAtMs":null,"obtainedAtMs":8640000000000001}',
		],
		[
			"obtainedAtMs not a whole millisecond",
			'{"accessToken":"at","expiresAtMs":null,"obtainedAtMs":1.5}',
		],
	];

	for (const mode of ["required", "allow-plaintext"] as const) {
		describe(`mode=${mode}`, () => {
			it.each(malformed)("inner envelope is %s", async (_label, innerJson) => {
				const store = storeFor(mode);
				writeV2(mode, "ft:sid-1:google", innerJson);
				redis.sets.set("ft:idx:sid-1", new Set(["google", "github"]));

				expect(await store.get("sid-1", "google")).toBeNull();
				expect(redis.data.has("ft:sid-1:google")).toBe(false);
				expect(redis.sets.get("ft:idx:sid-1")?.has("google")).toBe(true);
				expect(redis.sets.get("ft:idx:sid-1")?.has("github")).toBe(true);
			});

			it("still reads the minimal valid envelope — optional fields may be absent", async () => {
				const store = storeFor(mode);
				writeV2(mode, "ft:sid-1:google", '{"accessToken":"at","expiresAtMs":null}');
				// Absent from the envelope, but named on the record it reads to.
				expect(await store.get("sid-1", "google")).toStrictEqual({
					accessToken: "at",
					expiresAt: null,
					refreshToken: undefined,
					idToken: undefined,
					tokenType: undefined,
					scope: undefined,
					grantedScope: undefined,
				});
				expect(redis.data.has("ft:sid-1:google")).toBe(true);
			});

			it.each([
				["a raw token response", '{"account_hint":"user@example.com"}'],
				["an array", "[]"],
				["null", "null"],
			])(
				"still reads an envelope that carries rawParams, which is not a field (%s), and drops it",
				async (_label, rawParams) => {
					// `rawParams` is not a field. An envelope that carries it must not
					// become unreadable, which would lose the connection's tokens; the
					// field is ignored, and the next write does not carry it.
					const store = storeFor(mode);
					writeV2(
						mode,
						"ft:sid-1:google",
						`{"accessToken":"at","expiresAtMs":null,"rawParams":${rawParams}}`,
					);

					const read = await store.get("sid-1", "google");
					expect(read?.accessToken).toBe("at");
					expect(read && "rawParams" in read).toBe(false);
				},
			);

			it("reads an envelope carrying a key it does not know, and drops it", async () => {
				// What lets a replica read a record a newer release wrote: an added
				// envelope field is ignored, and the wrapper version stays.
				const store = storeFor(mode);
				writeV2(
					mode,
					"ft:sid-1:google",
					'{"accessToken":"at","expiresAtMs":null,"addedLater":{"x":1}}',
				);
				const read = await store.get("sid-1", "google");
				expect(read?.accessToken).toBe("at");
				expect(read && "addedLater" in read).toBe(false);
			});

			it("reads obtainedAtMs as obtainedAt, and its absence as no key", async () => {
				const store = storeFor(mode);
				writeV2(
					mode,
					"ft:sid-1:google",
					'{"accessToken":"at","expiresAtMs":null,"obtainedAtMs":1899999000000}',
				);
				const read = await store.get("sid-1", "google");
				expect(read?.accessToken).toBe("at");
				expect(read?.obtainedAt).toEqual(new Date(1_899_999_000_000));
				writeV2(mode, "ft:sid-2:google", '{"accessToken":"at","expiresAtMs":null}');
				expect(Object.hasOwn((await store.get("sid-2", "google")) ?? {}, "obtainedAt")).toBe(false);
			});

			it.each([
				["the end of the Date range", 8_640_000_000_000_000],
				["the start of the Date range", -8_640_000_000_000_000],
				["an instant before 1970", -86_400_000],
			])("reads obtainedAtMs at %s as a Date", async (_label, ms) => {
				const store = storeFor(mode);
				writeV2(
					mode,
					"ft:sid-1:google",
					`{"accessToken":"at","expiresAtMs":null,"obtainedAtMs":${ms}}`,
				);
				expect((await store.get("sid-1", "google"))?.obtainedAt).toEqual(new Date(ms));
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

// ---------------------------------------------------------------------------
// The conditional members' adapter logic, over the in-process fake: the
// self-heal by the bytes read, a malformed generation, the deadline's answer
// and the wait the adapter bounds, and the builder's check of the primitives.
// The scripts themselves are pinned on a real Redis.
// ---------------------------------------------------------------------------

describe("redis FederationTokenStore conditional members", () => {
	let redis: ReturnType<typeof createFakeRedis>;
	beforeEach(() => {
		redis = createFakeRedis();
	});
	afterEach(() => {
		vi.useRealTimers();
	});
	const storeOver = (client: FederationTokenStoreClient = redis) =>
		createRedisFederationTokenStore({
			deploymentMode: "unset",
			client,
			encryption: { mode: "required", key: encryptionKey },
		});

	it("getVersioned removes an unreadable record only while it holds the bytes read, and keeps the index member", async () => {
		const store = storeOver();
		await store.attach("sid-1", "google", tokens);
		redis.data.set("ft:sid-1:google", "{not-json");
		// A write lands between the read and the removal: it is kept.
		const removal = redis.compareAndDelete.getMockImplementation();
		redis.compareAndDelete.mockImplementationOnce(async (k, expected) => {
			redis.data.set(k, "rewritten");
			return (await removal?.(k, expected)) ?? false;
		});
		expect(await store.getVersioned("sid-1", "google")).toBeNull();
		expect(redis.compareAndDelete).toHaveBeenCalledWith("ft:sid-1:google", "{not-json");
		expect(redis.data.get("ft:sid-1:google")).toBe("rewritten");
		expect(redis.sets.get("ft:idx:sid-1")?.has("google")).toBe(true);
		expect(redis.sRem).not.toHaveBeenCalled();
	});

	it("reads a record whose generation is malformed as unreadable, through get and getVersioned alike", async () => {
		const store = storeOver();
		for (const g of ["", "has space", 42, null]) {
			await store.attach("sid-1", "google", tokens);
			const record = JSON.parse(redis.data.get("ft:sid-1:google") as string) as Record<
				string,
				unknown
			>;
			redis.data.set("ft:sid-1:google", JSON.stringify({ ...record, g }));
			expect(await store.get("sid-1", "google")).toBeNull();
			await store.attach("sid-1", "google", tokens);
			redis.data.set("ft:sid-1:google", JSON.stringify({ ...record, g }));
			expect(await store.getVersioned("sid-1", "google")).toBeNull();
			expect(redis.data.has("ft:sid-1:google")).toBe(false);
		}
	});

	it("rejects a conditional write answered late as an unknown outcome, never as written nothing", async () => {
		const store = storeOver();
		await store.attach("sid-1", "google", tokens);
		const read = await store.getVersioned("sid-1", "google");
		if (read === null) throw new Error("not live");
		redis.replaceIfGeneration.mockResolvedValueOnce("late");
		await expect(store.replaceIf("sid-1", "google", read.generation, tokens)).rejects.toThrow(
			/replaceIf was answered past its deadline; its outcome is unknown/,
		);
		redis.removeIfGeneration.mockResolvedValueOnce("late");
		await expect(store.removeIf("sid-1", "google", read.generation)).rejects.toThrow(
			/removeIf was answered past its deadline; its outcome is unknown/,
		);
		// No add to the index on an unknown outcome.
		expect(redis.sAddWithTtl).toHaveBeenCalledTimes(1);
	});

	// The driver sends a write again after a reconnect: copy 1 commits just
	// before the deadline and its reply is lost, and copy 2 reaches the server
	// past the deadline, whose check runs before the replay key's, so it answers
	// `late`. That answer is all the adapter sees, and copy 1 wrote.
	const firstCopyLandsThenLateCopy = <I extends { deadlineMs: number }, A>(
		write: (k: string, input: I) => Promise<A>,
	) => {
		return async (k: string, input: I): Promise<A> => {
			await write(k, input);
			vi.setSystemTime(input.deadlineMs + 1);
			return write(k, input);
		};
	};

	it("rejects with an unknown outcome when a resent replace answers late after its first copy wrote, and the record holds that write", async () => {
		const store = storeOver();
		await store.attach("sid-1", "google", tokens);
		const read = await store.getVersioned("sid-1", "google");
		if (read === null) throw new Error("not live");
		vi.useFakeTimers({ toFake: ["Date"] });
		const write = redis.replaceIfGeneration.getMockImplementation();
		if (write === undefined) throw new Error("no fake replace");
		let written: string | undefined;
		redis.replaceIfGeneration.mockImplementationOnce(
			firstCopyLandsThenLateCopy(async (k, input: FederationTokenReplaceIfInput) => {
				written = input.value;
				return write(k, input);
			}),
		);
		const next = { ...tokens, accessToken: "at-2" };
		await expect(store.replaceIf("sid-1", "google", read.generation, next)).rejects.toThrow(
			/replaceIf was answered past its deadline; its outcome is unknown: it may have committed/,
		);
		expect(redis.data.get("ft:sid-1:google")).toBe(written);
		expect((await store.get("sid-1", "google"))?.accessToken).toBe("at-2");
	});

	it("rejects with an unknown outcome when a resent removal answers late after its first copy removed, and the record is gone", async () => {
		const store = storeOver();
		await store.attach("sid-1", "google", tokens);
		const read = await store.getVersioned("sid-1", "google");
		if (read === null) throw new Error("not live");
		vi.useFakeTimers({ toFake: ["Date"] });
		const remove = redis.removeIfGeneration.getMockImplementation();
		if (remove === undefined) throw new Error("no fake removal");
		redis.removeIfGeneration.mockImplementationOnce(firstCopyLandsThenLateCopy(remove));
		await expect(store.removeIf("sid-1", "google", read.generation)).rejects.toThrow(
			/removeIf was answered past its deadline; its outcome is unknown: it may have committed/,
		);
		expect(redis.data.has("ft:sid-1:google")).toBe(false);
	});

	it("stamps each conditional write with a deadline 1 s past its issue, and stops waiting there with an unknown outcome", async () => {
		const store = storeOver();
		await store.attach("sid-1", "google", tokens);
		const read = await store.getVersioned("sid-1", "google");
		if (read === null) throw new Error("not live");
		vi.useFakeTimers({ now: 1_000_000, toFake: ["Date", "setTimeout", "clearTimeout"] });
		redis.replaceIfGeneration.mockImplementationOnce(() => new Promise(() => {}));
		const replaced = store.replaceIf("sid-1", "google", read.generation, tokens);
		const settled = expect(replaced).rejects.toThrow(
			/replaceIf had no answer within 1000 ms; its outcome is unknown: it may have committed/,
		);
		await vi.advanceTimersByTimeAsync(1_000);
		await settled;
		expect(redis.replaceIfGeneration).toHaveBeenLastCalledWith(
			"ft:sid-1:google",
			expect.objectContaining({ expected: read.generation, deadlineMs: 1_001_000 }),
		);
		// No add to the index on an unknown outcome.
		expect(redis.sAddWithTtl).toHaveBeenCalledTimes(1);
	});

	it("the builder refuses a client without the conditional primitives", () => {
		for (const missing of [
			"readVersioned",
			"replaceIfGeneration",
			"removeIfGeneration",
			"pExpireGT",
		] as const) {
			const { [missing]: _dropped, ...client } = createFakeRedis();
			expect(() =>
				redisFederationTokenStoreBuilder(
					{
						deploymentMode: "unset",
						client,
						encryption: { mode: "required", key: encryptionKey },
					},
					{},
				),
			).toThrow(new RegExp(`missing required method.*${missing}`));
		}
	});
});
