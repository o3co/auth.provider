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

// The credential's extension in the Redis federation grant store, against a
// real Redis: the access token's `effectiveExpiresAt` kept beside a credential
// whose tuple, authenticated data and format stay what v0.15 and v0.16 read.
//
// The extension is sealed under the credential's whole binding and the digest
// of the exact credential envelope written with it. Whatever does not open
// under that — another grant's, an earlier credential's, one rewritten by a
// release that does not know the field, one tampered with — reads as absent,
// and the token then ends at `obtainedAt + issuedLifetime`, as it did before.

import type {
	FederationGrantAuthorization,
	FederationGrantCredentialsInput,
	FederationGrantStore,
} from "@o3co/auth-provider-core";
import { Redis } from "ioredis";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
	createRedisFederationGrantStore,
	type FederationGrantKey,
} from "#/federation-grant-store.mjs";
import { openSealedCredential, sealCredential } from "#/internal/crypto.mjs";
import {
	credentialAad,
	credentialDigest,
	credentialExtensionAad,
	type FederationGrantCredentialBinding,
} from "#/internal/federation-grant-codec.mjs";
import { makeIoredisFederationGrantStoreClient } from "#/ioredis.mjs";
import { testRedis } from "./support/redis.mjs";

let redis: Redis;
let run = 0;

beforeAll(async () => {
	redis = new Redis(await testRedis());
});

afterAll(async () => {
	await redis?.quit();
});

const MIN = 60_000;
const DAY = 86_400_000;
const material = (byte: number): Buffer => Buffer.alloc(32, byte);
const KEY_A: FederationGrantKey = { id: "k-a", key: material(1) };
const KEY_B: FederationGrantKey = { id: "k-b", key: material(2) };
const KEY_C: FederationGrantKey = { id: "k-c", key: material(3) };

let prefix = "";
let T0 = new Date();
const at = (ms: number): Date => new Date(T0.getTime() + ms);

beforeEach(() => {
	run += 1;
	prefix = `fgx${run}:`;
	T0 = new Date(Math.floor(Date.now() / 1000) * 1000 + 137);
});

const sealed = (keys: readonly FederationGrantKey[] = [KEY_A]): FederationGrantStore =>
	createRedisFederationGrantStore({
		client: makeIoredisFederationGrantStoreClient(redis),
		keyPrefix: prefix,
		encryption: { mode: "required", keys },
	});

const plaintext = (): FederationGrantStore =>
	createRedisFederationGrantStore({
		client: makeIoredisFederationGrantStoreClient(redis),
		keyPrefix: prefix,
		encryption: { mode: "allow-plaintext" },
	});

const key = (id: string, part: "grant" | "cred"): string =>
	`${prefix}{${Buffer.from(JSON.stringify(id), "utf8").toString("base64url")}}:${part}`;

const SCOPES = ["openid", "offline_access"];
const authorization = (): FederationGrantAuthorization => ({
	identityRevision: "identity-1",
	authorizationRevision: "authorization-1",
	upstream: { issuer: "https://dev-1.okta.test", subject: "00u-alice" },
	resource: undefined,
	scopes: [...SCOPES],
	consent: { at: at(MIN), sid: "sid-1", scopes: [...SCOPES] },
	authorizedAt: at(2 * MIN),
	expiresAt: at(30 * DAY),
});

/**
 * A token obtained at +2 min, issued for an hour, that the upstream said ends
 * at `end`. Without `end` it is what an earlier release wrote, which no writer
 * of this one compiles, so it is cast.
 */
const credentials = (end: Date | undefined, tag = "1"): FederationGrantCredentialsInput =>
	({
		refreshToken: `rt-${tag}`,
		accessToken: {
			value: `at-${tag}`,
			tokenType: "Bearer",
			obtainedAt: at(2 * MIN),
			issuedLifetime: 3600,
			...(end === undefined ? {} : { effectiveExpiresAt: end }),
			scopes: [...SCOPES],
		},
	}) as FederationGrantCredentialsInput;

const END = (): Date => at(12 * MIN);

/** A grant taken to `active` (version 2) with `credentials`. */
const activated = async (
	held: FederationGrantStore,
	given: FederationGrantCredentialsInput,
	id = "g-1",
): Promise<void> => {
	await held.createPending({
		id,
		subject: "u-1",
		clientId: "agent",
		connection: "okta-calendar",
		intent: { handle: `h-${id}`, expiresAt: at(10 * MIN) },
		now: T0,
	});
	const written = await held.activate({
		grantId: id,
		intentHandle: `h-${id}`,
		authorization: authorization(),
		credentials: given,
		now: at(2 * MIN),
	});
	expect(written.ok).toBe(true);
};

/** The token the store hands out for the grant, or `undefined` when it hands out no credential. */
const token = async (held: FederationGrantStore, id = "g-1") => {
	const opened = await held.open(id, at(5 * MIN));
	expect(opened?.credentials.state).toBe("ok");
	return opened?.credentials.state === "ok" ? opened.credentials.value.accessToken : undefined;
};

/** The binding a credential of grant `id` is sealed under, read from the record as stored. */
const bindingOf = async (id = "g-1"): Promise<FederationGrantCredentialBinding> => {
	const fields = (await redis.hgetall(key(id, "grant"))) as Record<string, string>;
	const [, subject, clientId, connection] = JSON.parse(fields.base as string) as string[];
	return {
		credentialKey: key(id, "cred"),
		id,
		subject: subject as string,
		clientId: clientId as string,
		connection: connection as string,
		authorization: fields.authorization as string,
	};
};

/** An extension sealed exactly as the store seals one, for the credential stored now, with `text` inside. */
const forged = async (
	text: string,
	ring: readonly FederationGrantKey[] = [KEY_A],
	id = "g-1",
): Promise<string> => {
	const credential = (await redis.get(key(id, "cred"))) as string;
	return sealCredential(text, ring, credentialExtensionAad(await bindingOf(id), credential));
};

/** What the extension of grant `id` holds, opened as the store opens it. */
const openedExtension = async (id = "g-1"): Promise<unknown> => {
	const ext = (await redis.hget(key(id, "grant"), "ext")) as string;
	const credential = (await redis.get(key(id, "cred"))) as string;
	const opened = openSealedCredential(
		ext,
		[KEY_A, KEY_B],
		credentialExtensionAad(await bindingOf(id), credential),
	);
	expect(opened.state).toBe("ok");
	return opened.state === "ok" ? JSON.parse(opened.value) : undefined;
};

/**
 * A credential write by a release that does not know the extension, as
 * v0.16's REPLACE does it: the version bumped, the credential set, every other
 * field as it was.
 */
const rewrittenByAnOldRelease = async (credential: string, id = "g-1"): Promise<void> => {
	await redis.eval(
		`local v = tonumber(redis.call('HGET', KEYS[1], 'version'))
redis.call('HSET', KEYS[1], 'version', string.format('%.0f', v + 1))
redis.call('SET', KEYS[2], ARGV[1])
return 1`,
		2,
		key(id, "grant"),
		key(id, "cred"),
		credential,
	);
};

describe("the token's end, kept beside the credential", () => {
	it("comes back from activation and from every replacement as it was written", async () => {
		const held = sealed();
		await activated(held, credentials(END()));
		expect((await token(held))?.effectiveExpiresAt).toStrictEqual(END());

		const replaced = await held.replaceCredentials({
			grantId: "g-1",
			expectedVersion: 2,
			credentials: credentials(at(20 * MIN), "2"),
			ineligible: null,
			now: at(3 * MIN),
		});
		expect(replaced.ok).toBe(true);
		const after = await token(held);
		expect(after?.value).toBe("at-2");
		expect(after?.effectiveExpiresAt).toStrictEqual(at(20 * MIN));
	});

	it("is not there for a token that has none, nor for a credential without a token, and no field is left behind", async () => {
		const held = sealed();
		await activated(held, credentials(END()));
		await held.replaceCredentials({
			grantId: "g-1",
			expectedVersion: 2,
			credentials: credentials(undefined, "2"),
			ineligible: null,
			now: at(3 * MIN),
		});
		expect(await token(held)).not.toHaveProperty("effectiveExpiresAt");
		expect(await redis.hexists(key("g-1", "grant"), "ext")).toBe(0);

		await activated(held, { refreshToken: "rt-0", accessToken: undefined }, "g-2");
		expect(await token(held, "g-2")).toBeUndefined();
		expect(await redis.hexists(key("g-2", "grant"), "ext")).toBe(0);
	});

	it("passes an end at or before the token's start through as it was written: judging it is core's", async () => {
		const held = sealed();
		await activated(held, credentials(at(MIN)));
		expect((await token(held))?.effectiveExpiresAt).toStrictEqual(at(MIN));
	});

	it("goes with the token a refresh keeps, so the kept token keeps its end", async () => {
		const held = sealed();
		await activated(held, credentials(END()));
		const kept = await token(held);
		const replaced = await held.replaceCredentials({
			grantId: "g-1",
			expectedVersion: 2,
			// Read back with its end, as a refresh writes back the token it keeps.
			credentials: {
				refreshToken: "rt-rotated",
				accessToken: kept as FederationGrantCredentialsInput["accessToken"],
			},
			ineligible: null,
			now: at(3 * MIN),
		});
		expect(replaced.ok).toBe(true);
		expect((await token(held))?.effectiveExpiresAt).toStrictEqual(END());
	});

	it("refuses a write whose end is not an instant, and leaves the grant as it was", async () => {
		const held = sealed();
		await activated(held, credentials(END()));
		const before = (await redis.hgetall(key("g-1", "grant"))) as Record<string, string>;
		for (const end of [new Date(Number.NaN), "2026-10-02" as unknown as Date]) {
			expect(
				(
					await held.replaceCredentials({
						grantId: "g-1",
						expectedVersion: 2,
						credentials: credentials(end, "2"),
						ineligible: null,
						now: at(3 * MIN),
					})
				).ok,
			).toBe(false);
		}
		expect(await redis.hgetall(key("g-1", "grant"))).toStrictEqual(before);

		await held.createPending({
			id: "g-2",
			subject: "u-1",
			clientId: "agent",
			connection: "okta-calendar",
			intent: { handle: "h-g-2", expiresAt: at(10 * MIN) },
			now: T0,
		});
		const refused = await held.activate({
			grantId: "g-2",
			intentHandle: "h-g-2",
			authorization: authorization(),
			credentials: credentials(new Date(Number.NaN)),
			now: at(2 * MIN),
		});
		expect(refused.ok).toBe(false);
		expect(await redis.hget(key("g-2", "grant"), "status")).toBe("pending");
	});

	it("refuses an end whose own value is no instant, whatever its methods say", async () => {
		const held = sealed();
		await activated(held, credentials(END()));
		const disguised = new Date(Number.NaN);
		disguised.getTime = () => END().getTime();
		const written = await held.replaceCredentials({
			grantId: "g-1",
			expectedVersion: 2,
			credentials: credentials(disguised, "2"),
			ineligible: null,
			now: at(3 * MIN),
		});
		expect(written.ok).toBe(false);
		expect((await token(held))?.value).toBe("at-1");
	});

	it("stores the credentials as they were when the write was asked for, read once", async () => {
		const held = sealed();
		await activated(held, credentials(END()));
		// An end read once as the token's, and as nothing after: what was
		// judged is what is kept.
		let reads = 0;
		const given = credentials(undefined, "2");
		Object.defineProperty(given.accessToken as object, "effectiveExpiresAt", {
			enumerable: true,
			get: () => {
				reads += 1;
				return reads === 1 ? at(20 * MIN) : undefined;
			},
		});
		const replaced = await held.replaceCredentials({
			grantId: "g-1",
			expectedVersion: 2,
			credentials: given,
			ineligible: null,
			now: at(3 * MIN),
		});
		expect(replaced.ok).toBe(true);
		expect((await token(held))?.effectiveExpiresAt).toStrictEqual(at(20 * MIN));

		// Dates changed by the caller while the write is under way change nothing.
		const end = at(30 * MIN);
		const obtained = at(2 * MIN);
		const next = credentials(end, "3");
		const changing = {
			...next,
			accessToken: { ...(next.accessToken as object), obtainedAt: obtained },
		} as FederationGrantCredentialsInput;
		const writing = held.replaceCredentials({
			grantId: "g-1",
			expectedVersion: 3,
			credentials: changing,
			ineligible: null,
			now: at(3 * MIN),
		});
		end.setTime(Number.NaN);
		obtained.setTime(Number.NaN);
		expect((await writing).ok).toBe(true);
		const after = await token(held);
		expect(after?.obtainedAt).toStrictEqual(at(2 * MIN));
		expect(after?.effectiveExpiresAt).toStrictEqual(at(30 * MIN));
	});

	it("is taken away with the credential when the user is asked again and when the grant is revoked", async () => {
		const held = sealed();
		await activated(held, credentials(END()));
		await held.requireReauthorization({ grantId: "g-1", expectedVersion: 2, now: at(3 * MIN) });
		expect(await redis.hexists(key("g-1", "grant"), "ext")).toBe(0);

		await activated(held, credentials(END()), "g-2");
		await held.revoke("g-2", "client", at(3 * MIN));
		expect(await redis.hexists(key("g-2", "grant"), "ext")).toBe(0);
	});
});

describe("an extension that is not the credential's own reads as absent", () => {
	it("after a release that does not know it rewrites the credential, even with the same token in it", async () => {
		const held = sealed();
		await activated(held, credentials(END()));
		const binding = await bindingOf();
		const opened = openSealedCredential(
			(await redis.get(key("g-1", "cred"))) as string,
			[KEY_A],
			credentialAad(binding),
		);
		expect(opened.state).toBe("ok");
		// The same plaintext sealed again: what an old release writes when it
		// keeps the token, and a different envelope, since every seal draws a new IV.
		await rewrittenByAnOldRelease(
			sealCredential(opened.state === "ok" ? opened.value : "", [KEY_A], credentialAad(binding)),
		);
		const after = await token(held);
		expect(after?.value).toBe("at-1");
		expect(after).not.toHaveProperty("effectiveExpiresAt");
	});

	it("when it is copied from another grant", async () => {
		const held = sealed();
		await activated(held, credentials(at(50 * MIN)), "g-2");
		await activated(held, credentials(END()));
		await redis.hset(
			key("g-1", "grant"),
			"ext",
			(await redis.hget(key("g-2", "grant"), "ext")) as string,
		);
		expect(await token(held)).not.toHaveProperty("effectiveExpiresAt");
	});

	it("when it is put back from an earlier credential of the same grant", async () => {
		const held = sealed();
		await activated(held, credentials(at(50 * MIN)));
		const earlier = (await redis.hget(key("g-1", "grant"), "ext")) as string;
		await held.replaceCredentials({
			grantId: "g-1",
			expectedVersion: 2,
			credentials: credentials(END(), "2"),
			ineligible: null,
			now: at(3 * MIN),
		});
		await redis.hset(key("g-1", "grant"), "ext", earlier);
		const after = await token(held);
		expect(after?.value).toBe("at-2");
		expect(after).not.toHaveProperty("effectiveExpiresAt");
	});

	it("when it is the credential's own envelope, moved into the field", async () => {
		const held = sealed();
		await activated(held, credentials(END()));
		await redis.hset(key("g-1", "grant"), "ext", (await redis.get(key("g-1", "cred"))) as string);
		expect(await token(held)).not.toHaveProperty("effectiveExpiresAt");
	});

	it.each([
		["tampered", (ext: string) => `${ext.slice(0, -2)}${ext.endsWith("AA") ? "AB" : "AA"}`],
		["oversized", (ext: string) => `${ext}${"A".repeat(1_000_000)}`],
		["not an envelope", () => "not an envelope"],
		["empty", () => ""],
		["the plaintext spelling", () => `p2.${Buffer.from("{}").toString("base64url")}`],
	])("when it is %s, and the credential still opens", async (_, edit) => {
		const held = sealed();
		await activated(held, credentials(END()));
		const ext = (await redis.hget(key("g-1", "grant"), "ext")) as string;
		await redis.hset(key("g-1", "grant"), "ext", edit(ext));
		const after = await token(held);
		expect(after?.value).toBe("at-1");
		expect(after).not.toHaveProperty("effectiveExpiresAt");
	});

	it.each([
		["not JSON", "{"],
		["an array", `["${12 * MIN}"]`],
		["an end that is a JSON number", JSON.stringify({ effectiveExpiresAt: 1 })],
		["an end past the Date range", JSON.stringify({ effectiveExpiresAt: "8640000000000001" })],
		["text past the bound", JSON.stringify({ pad: "x".repeat(70_000) })],
	])("when it opens to %s", async (_, text) => {
		const held = sealed();
		await activated(held, credentials(END()));
		await redis.hset(key("g-1", "grant"), "ext", await forged(text));
		const after = await token(held);
		expect(after?.value).toBe("at-1");
		expect(after).not.toHaveProperty("effectiveExpiresAt");
	});
});

describe("keys it does not know", () => {
	it("are ignored on read, and dropped when the credential is written again", async () => {
		const held = sealed();
		await activated(held, credentials(undefined));
		await redis.hset(
			key("g-1", "grant"),
			"ext",
			await forged(
				JSON.stringify({ effectiveExpiresAt: String(END().getTime()), future: "about this token" }),
			),
		);
		const kept = await token(held);
		expect(kept?.effectiveExpiresAt).toStrictEqual(END());

		await held.replaceCredentials({
			grantId: "g-1",
			expectedVersion: 2,
			// Read back with its end, as a refresh writes back the token it keeps.
			credentials: {
				refreshToken: "rt-rotated",
				accessToken: kept as FederationGrantCredentialsInput["accessToken"],
			},
			ineligible: null,
			now: at(3 * MIN),
		});
		expect(await openedExtension()).toStrictEqual({
			effectiveExpiresAt: String(END().getTime()),
		});
	});
});

describe("a ring that rotates", () => {
	it("opens an extension under a key that is no longer first, and seals the next one under the first", async () => {
		await activated(sealed([KEY_A]), credentials(END()));
		const rotated = sealed([KEY_B, KEY_A]);
		expect((await token(rotated))?.effectiveExpiresAt).toStrictEqual(END());

		await rotated.replaceCredentials({
			grantId: "g-1",
			expectedVersion: 2,
			credentials: credentials(at(20 * MIN), "2"),
			ineligible: null,
			now: at(3 * MIN),
		});
		const ext = (await redis.hget(key("g-1", "grant"), "ext")) as string;
		expect(ext.split(".")[1]).toBe(Buffer.from("k-b", "utf8").toString("base64url"));
		expect((await token(rotated))?.effectiveExpiresAt).toStrictEqual(at(20 * MIN));
	});

	it("reads an extension sealed under a key the ring does not hold as absent, and still opens the credential", async () => {
		const held = sealed([KEY_A]);
		await activated(held, credentials(END()));
		await redis.hset(
			key("g-1", "grant"),
			"ext",
			await forged(JSON.stringify({ effectiveExpiresAt: String(END().getTime()) }), [KEY_C]),
		);
		const after = await token(held);
		expect(after?.value).toBe("at-1");
		expect(after).not.toHaveProperty("effectiveExpiresAt");
	});
});

describe("in plaintext mode", () => {
	const textOf = async (id = "g-1"): Promise<unknown> => {
		const ext = (await redis.hget(key(id, "grant"), "ext")) as string;
		expect(ext.startsWith("p2.")).toBe(true);
		return JSON.parse(Buffer.from(ext.slice(3), "base64url").toString("utf8"));
	};

	it("keeps the end, bound to the credential it was written with by that credential's digest", async () => {
		const held = plaintext();
		await activated(held, credentials(END()));
		expect((await token(held))?.effectiveExpiresAt).toStrictEqual(END());
		expect(await textOf()).toStrictEqual({
			bind: credentialDigest((await redis.get(key("g-1", "cred"))) as string),
			effectiveExpiresAt: String(END().getTime()),
		});
	});

	it("reads one copied from another grant, or left by an old release's rewrite, as absent", async () => {
		const held = plaintext();
		await activated(held, credentials(at(50 * MIN), "2"), "g-2");
		await activated(held, credentials(END()));
		await redis.hset(
			key("g-1", "grant"),
			"ext",
			(await redis.hget(key("g-2", "grant"), "ext")) as string,
		);
		expect(await token(held)).not.toHaveProperty("effectiveExpiresAt");

		await activated(held, credentials(END()), "g-3");
		await rewrittenByAnOldRelease((await redis.get(key("g-2", "cred"))) as string, "g-3");
		expect(await token(held, "g-3")).not.toHaveProperty("effectiveExpiresAt");
	});

	it("keeps reading the end beside a byte-identical rewrite of the credential: the same token, so the same end", async () => {
		const held = plaintext();
		await activated(held, credentials(END()));
		await rewrittenByAnOldRelease((await redis.get(key("g-1", "cred"))) as string);
		expect((await token(held))?.effectiveExpiresAt).toStrictEqual(END());
	});

	it("reads a sealed spelling, an unbound one or a malformed one as absent", async () => {
		const held = plaintext();
		await activated(held, credentials(END()));
		const plain = (o: unknown) => `p2.${Buffer.from(JSON.stringify(o)).toString("base64url")}`;
		for (const ext of [
			"v2.ay1h.aXYtaXYtaXYtaXY.Y2lwaGVy.dGFnLXRhZy10YWctdGFn",
			plain({ effectiveExpiresAt: String(END().getTime()) }),
			plain({ bind: 7, effectiveExpiresAt: String(END().getTime()) }),
			"p2.not base64url!",
		]) {
			await redis.hset(key("g-1", "grant"), "ext", ext);
			const after = await token(held);
			expect(after?.value, ext).toBe("at-1");
			expect(after, ext).not.toHaveProperty("effectiveExpiresAt");
		}
	});
});

describe("a release that does not know the field", () => {
	/**
	 * The credential payload as v0.15 and v0.16 decode it, restated from the
	 * format: `[1, refreshToken, []]` or `[1, refreshToken, [[value,
	 * tokenType, obtainedAtMs, issuedLifetime, scopes]]]`, nothing else.
	 */
	const oldDecoderAccepts = (payload: string): boolean => {
		const parsed: unknown = JSON.parse(payload);
		if (!Array.isArray(parsed) || parsed.length !== 3 || parsed[0] !== 1) return false;
		if (typeof parsed[1] !== "string" || parsed[1].length === 0) return false;
		if (!Array.isArray(parsed[2]) || parsed[2].length > 1) return false;
		if (parsed[2].length === 0) return true;
		const tokenTuple: unknown = parsed[2][0];
		return Array.isArray(tokenTuple) && tokenTuple.length === 5;
	};

	it("reads the same credential, under the same authenticated data, and the same fields: the extension is one more field", async () => {
		const held = sealed();
		await activated(held, credentials(END()));
		await activated(held, credentials(undefined), "g-2");
		const opened = openSealedCredential(
			(await redis.get(key("g-1", "cred"))) as string,
			[KEY_A],
			credentialAad(await bindingOf()),
		);
		expect(opened.state).toBe("ok");
		expect(oldDecoderAccepts(opened.state === "ok" ? opened.value : "")).toBe(true);

		const withEnd = Object.keys(await redis.hgetall(key("g-1", "grant"))).sort();
		const without = Object.keys(await redis.hgetall(key("g-2", "grant"))).sort();
		expect(withEnd).toStrictEqual([...without, "ext"].sort());
		expect(await redis.hget(key("g-1", "grant"), "format")).toBe("1");
	});
});
