/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * What every adapter hands Redis as a key's life: a whole number of
 * milliseconds, rounded up, and never one made from an expiry that is not a
 * number.
 *
 * `PX` and `PEXPIREAT` take whole milliseconds, so a fractional expiry has to
 * be rounded, and only one direction is safe: up. A record whose life is
 * rounded down dies before the instant its caller asked for — a replay record
 * before the proof stops being acceptable, a revocation before the token
 * expires, a session before its own `expiresAt`. Sent unrounded, it is worse:
 * Redis refuses a fractional `PX` outright, and a script that has already
 * written its record when its `PEXPIREAT` is refused leaves that record with no
 * TTL at all. The contract suites cannot tell `Math.ceil` from `Math.round`
 * against a real Redis (the difference is under a millisecond), so a recording
 * client pins it: the life each adapter sends is a whole number no smaller
 * than the life it was asked for, on a clock frozen so that life is exact.
 *
 * An expiry that is not a finite number — NaN, from an Invalid Date or an
 * unset setting, or ±Infinity — is a caller fault, refused before the client
 * is asked: `PX NaN` is a Redis error at best, and at worst the one command of
 * a pair that fails, after the other has written.
 */
import type {
	CreateCodeInput,
	CreateUserSessionInput,
	FederationTokens,
	RefreshTokenFamily,
} from "@o3co/auth-provider-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createRedisAccessTokenDenylist } from "#/access-token-denylist.mjs";
import { createRedisChallengeStore } from "#/challenges.mjs";
import type {
	AccessTokenDenylistClient,
	ChallengeStoreClient,
	CodeRepositoryClient,
	ConsentStoreClient,
	CreateDeviceCodeRecordInput,
	DeviceCodeStoreClient,
	FederationTokenStoreClient,
	PendingConsentStoreClient,
	RefreshTokenFamilyClient,
	RefreshTokenFamilyMultiClient,
	ReplaySeenSetClient,
	UserSessionStoreClient,
} from "#/clients.mjs";
import { RedisCodeRepository } from "#/code-repository.mjs";
import { createRedisConsentStore, createRedisPendingConsentStore } from "#/consent-store.mjs";
import { createRedisDeviceCodeStore } from "#/device-code-store.mjs";
import { createRedisFederationTokenStore } from "#/federation-tokens.mjs";
import { createFederationGrantLock } from "#/internal/federation-grant-lock.mjs";
import { createRedisLock, type RedisLockClient } from "#/internal/lock.mjs";
import { createRedisRefreshTokenFamilyStore } from "#/refresh-token-family.mjs";
import { createRedisReplaySeenSet } from "#/replay-seen-set.mjs";
import { createRedisUserSessionStore } from "#/userSessionStore.mjs";

const NOW = Date.UTC(2026, 8, 24, 12, 0, 0);

beforeEach(() => {
	vi.useFakeTimers();
	vi.setSystemTime(NOW);
});

afterEach(() => {
	vi.useRealTimers();
});

/** Records every `PX` a `SET` is sent with. */
const recorder = () => {
	const px: number[] = [];
	const set = async (_key: string, _value: string, _mode: "PX", ttlMs: number) => {
		px.push(ttlMs);
		return "OK" as const;
	};
	return { px, set };
};

/** Lives whose rounding differs by direction: .4 rounds down under Math.round, .5 up. */
const FRACTIONAL_LIVES = [1_234.4, 1_234.5, 0.2, 59_999.999];

const NOT_FINITE = [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY];

const expectRoundedUp = (sent: readonly number[], lives: readonly number[]) => {
	expect(sent).toHaveLength(lives.length);
	sent.forEach((px, i) => {
		const life = lives[i] as number;
		expect(Number.isInteger(px), `PX ${px} for a life of ${life} ms`).toBe(true);
		expect(px, `PX ${px} for a life of ${life} ms`).toBeGreaterThanOrEqual(life);
		expect(px - life, `PX ${px} for a life of ${life} ms`).toBeLessThan(1);
	});
};

/** A refresh-token-family client whose `SET … NX` and `MULTI` `SET` both record their `PX`. */
const familyRecorder = (stored?: { raw: string; pttl: number }) => {
	const px: number[] = [];
	const multiPx: number[] = [];
	const multi: RefreshTokenFamilyMultiClient = {
		set: (_key, _value, _mode, ttlMs) => {
			multiPx.push(ttlMs);
			return multi;
		},
		exec: async () => ["OK"],
	};
	const client: RefreshTokenFamilyClient = {
		set: async (_key, _value, _mode, ttlMs) => {
			px.push(ttlMs);
			return "OK";
		},
		get: async () => stored?.raw ?? null,
		pttl: async () => stored?.pttl ?? -2,
		watch: async () => "OK",
		unwatch: async () => "OK",
		multi: () => multi,
		duplicate: () => Object.assign({ ...client }, { [Symbol.asyncDispose]: async () => {} }),
	};
	return { px, multiPx, client };
};

const family = (expiresAtMs: number): RefreshTokenFamily => ({
	familyId: "fam-1",
	activeJti: "jti-1",
	revoked: false,
	expiresAtMs,
});

/** A resident family that lives another day, as the recorder hands it to an updater. */
const residentFamily = () => ({
	raw: JSON.stringify(family(NOW + 86_400_000)),
	pttl: 86_400_000,
});

/** A device-code client that records the deadline each `create` hands it. */
const deviceCodeRecorder = () => {
	const created: CreateDeviceCodeRecordInput[] = [];
	const unused = async (): Promise<never> => {
		throw new Error("not reached by create");
	};
	const client: DeviceCodeStoreClient = {
		create: async (_keys, input) => {
			created.push(input);
			return true;
		},
		findPending: unused,
		decide: unused,
		poll: unused,
		remove: unused,
	};
	return { created, client };
};

const deviceInput = (expiresAtMs: number, i = 0) => ({
	deviceCode: `dc-${i}`,
	userCode: `UC${i}`,
	clientId: "tv-app",
	requestedScope: undefined,
	expiresAtMs,
	intervalSeconds: 5,
});

const codeInput = (expiresIn: number): CreateCodeInput => ({
	client_id: "client-1",
	redirect_uri: "https://rp.example/cb",
	code_challenge: undefined,
	code_challenge_method: undefined,
	nonce: undefined,
	sid: undefined,
	acr: undefined,
	grantedScope: undefined,
	grantedAudience: undefined,
	expiresIn,
});

const codeClient = (set: CodeRepositoryClient["set"]): CodeRepositoryClient => ({
	set,
	get: async () => null,
	getDel: async () => null,
	del: async () => 0,
});

/** A federation-token client that records the `PX` of each envelope and the TTL of each index write. */
const federationTokenRecorder = () => {
	const px: number[] = [];
	const indexTtls: number[] = [];
	const nothing = (async function* () {})();
	const client: FederationTokenStoreClient = {
		get: async () => null,
		set: (async (_key: string, _value: string, _mode: "PX", ttlMs: number) => {
			px.push(ttlMs);
			return "OK";
		}) as FederationTokenStoreClient["set"],
		del: async () => 0,
		unlink: async () => 0,
		sAddWithTtl: async (_key, _member, ttlMs) => {
			indexTtls.push(ttlMs);
		},
		sRem: async () => 0,
		sScanIterator: () => nothing,
		scanIterator: () => nothing,
		compareAndDelete: async () => true,
	};
	return { px, indexTtls, client };
};

const federationTokens: FederationTokens = {
	accessToken: "at",
	refreshToken: "rt",
	idToken: undefined,
	expiresAt: null,
	tokenType: "Bearer",
	scope: undefined,
	grantedScope: undefined,
};

/** A lock client that records the `PX` of each attempt, and takes every one. */
const lockRecorder = () => {
	const px: number[] = [];
	const client: RedisLockClient = {
		set: async (_key, _value, opts) => {
			px.push(opts?.PX as number);
			return "OK";
		},
		compareAndDelete: async () => true,
	};
	return { px, client };
};

const sessionInput = (expiresAt: Date): CreateUserSessionInput => ({
	sid: "sid-1",
	sub: "user-1",
	authTime: new Date(NOW),
	expiresAt,
	claims: {},
	amr: undefined,
});

describe("the PX an adapter sends is its record's life, rounded up to a whole millisecond", () => {
	it("ReplaySeenSet.markSeen", async () => {
		const client = recorder();
		const set = createRedisReplaySeenSet({
			client: { set: client.set, exists: async () => 0 } as ReplaySeenSetClient,
			keyPrefix: "replay:",
		});
		for (const [i, life] of FRACTIONAL_LIVES.entries()) {
			await set.markSeen("scope", `k${i}`, NOW + life);
		}
		expectRoundedUp(client.px, FRACTIONAL_LIVES);
	});

	it("ChallengeStore.issue", async () => {
		const client = recorder();
		const store = createRedisChallengeStore({
			client: {
				set: client.set,
				pttl: async () => -2,
				del: async () => 0,
			} as ChallengeStoreClient,
			keyPrefix: "chal:",
		});
		for (const [i, life] of FRACTIONAL_LIVES.entries()) {
			await store.issue("scope", `v${i}`, NOW + life);
		}
		expectRoundedUp(client.px, FRACTIONAL_LIVES);
	});

	it("AccessTokenDenylist.add", async () => {
		const client = recorder();
		const denylist = createRedisAccessTokenDenylist({
			client: { set: client.set, exists: async () => 0 } as AccessTokenDenylistClient,
			keyPrefix: "atdeny:",
		});
		for (const [i, life] of FRACTIONAL_LIVES.entries()) {
			await denylist.add(`j${i}`, NOW + life);
		}
		expectRoundedUp(client.px, FRACTIONAL_LIVES);
	});

	it("RefreshTokenFamilyStore.registerFamily", async () => {
		// Sent unrounded, Redis refused the SET, and the refresh token the
		// family was registered for could never be redeemed.
		const recording = familyRecorder();
		const store = createRedisRefreshTokenFamilyStore({
			client: recording.client,
			keyPrefix: "rtfam:",
		});
		for (const life of FRACTIONAL_LIVES) {
			await store.registerFamily(family(NOW + life));
		}
		expectRoundedUp(recording.px, FRACTIONAL_LIVES);
	});

	it("RefreshTokenFamilyStore.updateFamily", async () => {
		const recording = familyRecorder(residentFamily());
		const store = createRedisRefreshTokenFamilyStore({
			client: recording.client,
			keyPrefix: "rtfam:",
		});
		for (const life of FRACTIONAL_LIVES) {
			const result = await store.updateFamily("fam-1", (current) => ({
				action: "commit",
				family: { ...current, expiresAtMs: NOW + life },
			}));
			expect(result.outcome).toBe("committed");
		}
		expectRoundedUp(recording.multiPx, FRACTIONAL_LIVES);
	});

	it("RefreshTokenFamilyStore stores the expiry it rounded to, which its own reader accepts", async () => {
		// The stored JSON's `expiresAtMs` is read back through a schema that
		// takes whole epoch milliseconds only, so a fractional one written
		// there turned the family into `corrupt-data` on its first read.
		let stored = "";
		const recording = familyRecorder();
		const store = createRedisRefreshTokenFamilyStore({
			client: {
				...recording.client,
				set: async (_key, value) => {
					stored = value;
					return "OK";
				},
			},
			keyPrefix: "rtfam:",
		});
		await store.registerFamily(family(NOW + 1_234.4));
		const written = JSON.parse(stored) as RefreshTokenFamily;
		expect(written.expiresAtMs).toBe(NOW + 1_235);

		const reader = createRedisRefreshTokenFamilyStore({
			client: familyRecorder({ raw: stored, pttl: 1_235 }).client,
			keyPrefix: "rtfam:",
		});
		expect(await reader.findFamily("fam-1")).toMatchObject({ familyId: "fam-1" });
	});

	it("CodeRepository.createCode, for a lifetime given in fractional seconds", async () => {
		// `expiresIn` is seconds, so a per-call lifetime of 1.2345 s asked
		// Redis for `PX 1234.5` — refused, and /authorize answered server_error.
		const client = recorder();
		const repo = new RedisCodeRepository(codeClient(client.set));
		const lifetimes = [1.2344, 1.2345, 0.0002, 59.999999];
		for (const expiresIn of lifetimes) {
			await repo.createCode(codeInput(expiresIn));
		}
		expectRoundedUp(
			client.px,
			lifetimes.map((s) => s * 1000),
		);
	});

	it("FederationTokenStore, for a store TTL given in fractional seconds: the envelope and the index", async () => {
		const lifetimes = [1.2344, 1.2345, 0.0002, 59.999999];
		for (const ttl of lifetimes) {
			const recording = federationTokenRecorder();
			const store = createRedisFederationTokenStore({
				client: recording.client,
				encryption: { mode: "required", key: Buffer.alloc(32, 7) },
				ttl,
			});
			await store.attach("sid-1", "google", federationTokens);
			await store.update("sid-1", "google", federationTokens);
			expectRoundedUp(recording.px, [ttl * 1000, ttl * 1000]);
			expectRoundedUp(recording.indexTtls, [ttl * 1000, ttl * 1000]);
		}
	});

	it("the federation-token lock, for a fractional ttlMs", async () => {
		const recording = lockRecorder();
		const lock = createRedisLock({ client: recording.client });
		for (const [i, ttlMs] of FRACTIONAL_LIVES.entries()) {
			const held = await lock.acquireLock({ sid: `s${i}`, federationName: "google", ttlMs });
			expect(held.acquired).toBe(true);
		}
		expectRoundedUp(recording.px, FRACTIONAL_LIVES);
	});
});

describe("the PEXPIREAT deadline DeviceCodeStore.create hands its client is a whole millisecond, rounded up", () => {
	it("rounds the keys' deadline up and keeps the record's own expiry exact", async () => {
		// The script writes the record and its index, then sets their deadline:
		// a fractional one was refused by `PEXPIREAT` after both were written,
		// leaving two keys with no TTL — and the endpoint, reading the error as
		// a code collision, drew again and left another pair.
		const recording = deviceCodeRecorder();
		const store = createRedisDeviceCodeStore({ client: recording.client, keyPrefix: "devauth:" });
		for (const [i, life] of FRACTIONAL_LIVES.entries()) {
			await store.create(deviceInput(NOW + life, i));
		}
		expectRoundedUp(
			recording.created.map((input) => input.expiresAtMs - NOW),
			FRACTIONAL_LIVES,
		);
		// `poll` answers `expired` from the record's own field, so that stays
		// what the caller asked for.
		expect(recording.created.map((input) => Number(input.fields.expiresAtMs))).toEqual(
			FRACTIONAL_LIVES.map((life) => NOW + life),
		);
	});
});

describe("an expiry that is not a finite number is refused before Redis is asked", () => {
	it("RefreshTokenFamilyStore.registerFamily", async () => {
		const recording = familyRecorder();
		const store = createRedisRefreshTokenFamilyStore({
			client: recording.client,
			keyPrefix: "rtfam:",
		});
		for (const bad of NOT_FINITE) {
			await expect(store.registerFamily(family(bad))).rejects.toThrow(RangeError);
		}
		expect(recording.px).toEqual([]);
	});

	it("RefreshTokenFamilyStore.updateFamily: an updater that commits one", async () => {
		const recording = familyRecorder(residentFamily());
		const store = createRedisRefreshTokenFamilyStore({
			client: recording.client,
			keyPrefix: "rtfam:",
		});
		for (const bad of NOT_FINITE) {
			await expect(
				store.updateFamily("fam-1", (current) => ({
					action: "commit",
					family: { ...current, expiresAtMs: bad },
				})),
			).rejects.toThrow(RangeError);
		}
		expect(recording.multiPx).toEqual([]);
	});

	it("DeviceCodeStore.create", async () => {
		const recording = deviceCodeRecorder();
		const store = createRedisDeviceCodeStore({ client: recording.client, keyPrefix: "devauth:" });
		for (const bad of NOT_FINITE) {
			await expect(store.create(deviceInput(bad))).rejects.toThrow(RangeError);
		}
		expect(recording.created).toEqual([]);
	});

	it("CodeRepository.createCode: a lifetime that is not a positive number of seconds", async () => {
		const client = recorder();
		const repo = new RedisCodeRepository(codeClient(client.set));
		for (const bad of [...NOT_FINITE, 0, -1]) {
			await expect(repo.createCode(codeInput(bad))).rejects.toThrow(RangeError);
		}
		expect(client.px).toEqual([]);
	});

	it("the federation-token lock: a ttlMs that is not a positive number, or a waitForMs that is not a number", async () => {
		// A TTL of NaN is `PX NaN`; a wait of NaN is a deadline no clock
		// reaches, so a held lock is waited on for ever.
		const recording = lockRecorder();
		const lock = createRedisLock({ client: recording.client });
		for (const ttlMs of [...NOT_FINITE, 0, -5]) {
			await expect(lock.acquireLock({ sid: "s", federationName: "google", ttlMs })).rejects.toThrow(
				RangeError,
			);
		}
		for (const waitForMs of [...NOT_FINITE, -1]) {
			await expect(
				lock.acquireLock({ sid: "s", federationName: "google", waitForMs }),
			).rejects.toThrow(RangeError);
		}
		expect(recording.px).toEqual([]);
	});

	it("UserSessionStore.create: an Invalid Date", async () => {
		// `getTime()` of an Invalid Date is NaN, and `NaN <= 0` is false, so
		// the past-expiry check let it through to `PX NaN`.
		const client = recorder();
		const store = createRedisUserSessionStore({
			client: {
				set: client.set,
				get: async () => null,
				del: async () => 0,
			} as UserSessionStoreClient,
			keyPrefix: "ss:us:",
		});
		await expect(store.create(sessionInput(new Date(Number.NaN)))).rejects.toThrow(RangeError);
		expect(client.px).toEqual([]);
	});
});

/**
 * Past ECMAScript's Date range (±8.64e15 ms) a number is no deadline a Date
 * can hold or Redis can take: `1e21` is sent as `1e+21`, and a whole but
 * enormous value overflows the server's expiry. A script that writes its
 * record before setting the deadline then leaves the record with no TTL.
 */
const PAST_THE_DATE_RANGE = [8_640_000_000_000_001, 1e20, 1e21, -1e21];

describe("an expiry or lifetime past the Date range is refused before Redis is asked", () => {
	/** A client every method of which records that it was called, and answers nothing. */
	const recordingAny = <T,>() => {
		const calls: string[] = [];
		const client = new Proxy(
			{},
			{
				get: (_target, name) => async () => {
					calls.push(String(name));
					return null;
				},
			},
		) as T;
		return { calls, client };
	};

	it("ChallengeStore.issue, ReplaySeenSet.markSeen and AccessTokenDenylist.add", async () => {
		const client = recorder();
		const challenges = createRedisChallengeStore({
			client: { set: client.set, pttl: async () => -2, del: async () => 0 } as ChallengeStoreClient,
			keyPrefix: "chal:",
		});
		const seen = createRedisReplaySeenSet({
			client: { set: client.set, exists: async () => 0 } as ReplaySeenSetClient,
			keyPrefix: "replay:",
		});
		const denylist = createRedisAccessTokenDenylist({
			client: { set: client.set, exists: async () => 0 } as AccessTokenDenylistClient,
			keyPrefix: "atdeny:",
		});
		for (const bad of PAST_THE_DATE_RANGE) {
			await expect(challenges.issue("scope", "v", bad), String(bad)).rejects.toThrow(RangeError);
			await expect(seen.markSeen("scope", "k", bad), String(bad)).rejects.toThrow(RangeError);
			await expect(denylist.add("j", bad), String(bad)).rejects.toThrow(RangeError);
		}
		expect(client.px).toEqual([]);
	});

	it("RefreshTokenFamilyStore.registerFamily and updateFamily", async () => {
		const recording = familyRecorder(residentFamily());
		const store = createRedisRefreshTokenFamilyStore({
			client: recording.client,
			keyPrefix: "rtfam:",
		});
		for (const bad of PAST_THE_DATE_RANGE) {
			await expect(store.registerFamily(family(bad)), String(bad)).rejects.toThrow(RangeError);
			await expect(
				store.updateFamily("fam-1", (current) => ({
					action: "commit",
					family: { ...current, expiresAtMs: bad },
				})),
				String(bad),
			).rejects.toThrow(RangeError);
		}
		expect(recording.px).toEqual([]);
		expect(recording.multiPx).toEqual([]);
	});

	it("DeviceCodeStore.create", async () => {
		const recording = deviceCodeRecorder();
		const store = createRedisDeviceCodeStore({ client: recording.client, keyPrefix: "devauth:" });
		for (const bad of PAST_THE_DATE_RANGE) {
			await expect(store.create(deviceInput(bad)), String(bad)).rejects.toThrow(RangeError);
		}
		expect(recording.created).toEqual([]);
	});

	it("ConsentStore.grant and PendingConsentStore.set", async () => {
		const consent = recordingAny<ConsentStoreClient>();
		const pending = recordingAny<PendingConsentStoreClient>();
		const consents = createRedisConsentStore({ client: consent.client, keyPrefix: "consent:" });
		const parked = createRedisPendingConsentStore({
			client: pending.client,
			keyPrefix: "consent:",
		});
		for (const bad of PAST_THE_DATE_RANGE) {
			await expect(
				consents.grant({
					sub: "u-1",
					clientId: "app",
					scopes: ["read"],
					grantedAt: NOW,
					expiresAt: bad,
				}),
				String(bad),
			).rejects.toThrow(RangeError);
			await expect(
				parked.set({
					challenge: "ch-1",
					sessionId: "sess-1",
					sub: "u-1",
					clientId: "app",
					scopes: ["read"],
					grantedScopes: [],
					authorizeUrl: "https://issuer.example/oauth/authorize?client_id=app",
					redirectUri: "https://app.example/cb",
					state: undefined,
					createdAt: NOW,
					expiresAt: bad,
				}),
				String(bad),
			).rejects.toThrow(RangeError);
		}
		expect(consent.calls).toEqual([]);
		expect(pending.calls).toEqual([]);
	});

	it("CodeRepository.createCode, and FederationTokenStore's ttl, as seconds from now", async () => {
		const client = recorder();
		const repo = new RedisCodeRepository(codeClient(client.set));
		// 1e13 s is 1e16 ms, which runs past the Date range from any today.
		for (const expiresIn of [1e13, 1e18]) {
			await expect(repo.createCode(codeInput(expiresIn)), String(expiresIn)).rejects.toThrow(
				RangeError,
			);
			expect(() =>
				createRedisFederationTokenStore({
					client: federationTokenRecorder().client,
					encryption: { mode: "required", key: Buffer.alloc(32, 7) },
					ttl: expiresIn,
				}),
			).toThrow(RangeError);
		}
		expect(client.px).toEqual([]);
	});

	it("the federation-token lock and the federation-grant lock: a TTL or a wait no clock reaches", async () => {
		const recording = lockRecorder();
		const lock = createRedisLock({ client: recording.client });
		const attempts: number[] = [];
		const grantLock = createFederationGrantLock({
			client: {
				tryLock: async (_key, _token, ttlMs) => {
					attempts.push(ttlMs);
					return true;
				},
				unlock: async () => {},
			},
			lockKey: (id) => `fg:{${id}}:lock`,
		});
		for (const huge of [1e16, 1e21]) {
			await expect(
				lock.acquireLock({ sid: "s", federationName: "google", ttlMs: huge }),
				`ttlMs ${huge}`,
			).rejects.toThrow(RangeError);
			await expect(
				lock.acquireLock({ sid: "s", federationName: "google", waitForMs: huge }),
				`waitForMs ${huge}`,
			).rejects.toThrow(RangeError);
			await expect(
				grantLock.acquire("g-1", { ttlMs: huge, waitForMs: 0 }),
				`grant ttlMs ${huge}`,
			).rejects.toThrow(RangeError);
			await expect(
				grantLock.acquire("g-1", { ttlMs: 30_000, waitForMs: huge }),
				`grant waitForMs ${huge}`,
			).rejects.toThrow(RangeError);
		}
		expect(recording.px).toEqual([]);
		expect(attempts).toEqual([]);
	});
});
