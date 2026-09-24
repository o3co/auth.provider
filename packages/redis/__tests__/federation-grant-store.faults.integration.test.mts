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

// What the Redis federation grant store does when the keyspace is not what it
// wrote (#593, D16): a field someone edited, a credential copied from another
// grant, a key that is gone, a ring a key was taken out of, a script cache
// that was flushed.
//
// The contract suite proves the port; none of this is reachable through it,
// because through the port the store is the only writer. Here it is not — a
// mismatched restore, an operator with redis-cli, or a second deployment
// pointed at the same keyspace all look like this.

import {
	type FederationGrantAuthorization,
	type FederationGrantCredentials,
	type FederationGrantStore,
	hasFederationGrantAuthorization,
} from "@o3co/auth-provider-core";
import { Redis } from "ioredis";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
	createRedisFederationGrantStore,
	type FederationGrantKey,
} from "../src/federation-grant-store.mjs";
import { makeIoredisFederationGrantStoreClient } from "../src/ioredis.mjs";
import { testRedis } from "./support/redis.mjs";

let redis: Redis;
let run = 0;

beforeAll(async () => {
	const at = await testRedis();
	redis = new Redis(at);
});

afterAll(async () => {
	await redis?.quit();
});

const MIN = 60_000;
const DAY = 86_400_000;
const material = (byte: number): Buffer => Buffer.alloc(32, byte);
const KEY_A: FederationGrantKey = { id: "k-a", key: material(1) };
const KEY_B: FederationGrantKey = { id: "k-b", key: material(2) };

let prefix = "";
let T0 = new Date();
const at = (ms: number): Date => new Date(T0.getTime() + ms);

beforeEach(() => {
	run += 1;
	prefix = `fgf${run}:`;
	T0 = new Date(Math.floor(Date.now() / 1000) * 1000 + 137);
});

const store = (keys: readonly FederationGrantKey[] = [KEY_A]): FederationGrantStore =>
	createRedisFederationGrantStore({
		client: makeIoredisFederationGrantStoreClient(redis),
		keyPrefix: prefix,
		encryption: { mode: "required", keys },
	});

const key = (id: string, part: "grant" | "cred" | "lock"): string =>
	`${prefix}{${Buffer.from(JSON.stringify(id), "utf8").toString("base64url")}}:${part}`;

/**
 * Which Cluster slot a key falls in: CRC16-CCITT of what is between the first
 * `{` and the next `}`, modulo 16384, exactly as the Cluster specification
 * defines it. Computed here rather than asked of the server, because
 * `CLUSTER KEYSLOT` is refused by an instance with cluster support disabled,
 * which is what a test container is.
 */
const slot = (name: string): number => {
	const open = name.indexOf("{");
	const close = open === -1 ? -1 : name.indexOf("}", open + 1);
	const tag = open !== -1 && close > open + 1 ? name.slice(open + 1, close) : name;
	const bytes = Buffer.from(tag, "utf8");
	let crc = 0;
	for (const byte of bytes) {
		crc ^= byte << 8;
		for (let bit = 0; bit < 8; bit += 1) {
			crc = (crc & 0x8000) !== 0 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
		}
	}
	return crc % 16384;
};

const SCOPES = ["openid", "offline_access"];
const authorization = (
	over: Partial<FederationGrantAuthorization> = {},
): FederationGrantAuthorization => ({
	identityRevision: "identity-1",
	authorizationRevision: "authorization-1",
	upstream: { issuer: "https://dev-1.okta.test", subject: "00u-alice" },
	resource: undefined,
	scopes: [...SCOPES],
	consent: { at: at(MIN), sid: "sid-1", scopes: [...SCOPES] },
	authorizedAt: at(2 * MIN),
	expiresAt: at(30 * DAY),
	...over,
});

const credentials = (tag = "1"): FederationGrantCredentials => ({
	refreshToken: `rt-${tag}`,
	accessToken: {
		value: `at-${tag}`,
		tokenType: "Bearer",
		obtainedAt: at(2 * MIN),
		issuedLifetime: 3600,
		scopes: [...SCOPES],
	},
});

/** A grant taken to `active`, version 2, with a credential sealed under `keys`. */
const activated = async (
	id = "g-1",
	keys: readonly FederationGrantKey[] = [KEY_A],
	subject = "u-1",
): Promise<FederationGrantStore> => {
	const held = store(keys);
	await held.createPending({
		id,
		subject,
		clientId: "agent",
		connection: "okta-calendar",
		intent: { handle: `h-${id}`, expiresAt: at(10 * MIN) },
		now: T0,
	});
	const written = await held.activate({
		grantId: id,
		intentHandle: `h-${id}`,
		authorization: authorization(),
		credentials: credentials(),
		now: at(2 * MIN),
	});
	expect(written.ok).toBe(true);
	return held;
};

/** Names a renewal's intent on an authorized grant, and insists it took. */
const client_nameIntentOk = async (held: FederationGrantStore): Promise<void> => {
	const written = await held.nameIntent({
		grantId: "g-1",
		intent: { handle: "h-re", expiresAt: at(DAY + 10 * MIN) },
		now: at(DAY),
	});
	expect(written.ok).toBe(true);
};

describe("a field someone edited (#593, D16)", () => {
	it("refuses the credential when any field the authorization is bound to is changed, and takes nothing away", async () => {
		const held = await activated();
		const original = (await redis.hgetall(key("g-1", "grant"))) as Record<string, string>;
		const sealed = await redis.get(key("g-1", "cred"));

		// Every field inside the authenticated data, one at a time. The key name
		// is in there too, which the copy case below covers.
		// Well-formed, and a different value: a `base` that no longer parses
		// would make the record unreadable rather than the credential, which is
		// the case below.
		const base = JSON.parse(original.base as string) as string[];
		const tampered: Record<string, string> = {
			base: JSON.stringify([base[0], "u-2", base[2], base[3], base[4]]),
			authorization: JSON.stringify([
				"identity-1",
				"authorization-2",
				"https://dev-1.okta.test",
				"00u-alice",
				[],
				SCOPES,
				String(at(MIN).getTime()),
				"sid-1",
				SCOPES,
				String(at(2 * MIN).getTime()),
				String(at(30 * DAY).getTime()),
			]),
		};
		for (const [field, value] of Object.entries(tampered)) {
			await redis.hset(key("g-1", "grant"), field, value);
			const opened = await held.open("g-1", at(DAY));
			expect(opened?.credentials.state, field).toBe("unreadable");
			// And nothing was reclaimed on the way: a record that cannot be read
			// is never deleted on read (D16), because wrong key material or a bad
			// restore must not durably flip every grant.
			expect(await redis.exists(key("g-1", "grant")), field).toBe(1);
			expect(await redis.get(key("g-1", "cred")), field).toBe(sealed);
			await redis.hset(key("g-1", "grant"), field, original[field] as string);
		}
		// Put back, and it opens again.
		expect((await held.open("g-1", at(DAY)))?.credentials.state).toBe("ok");
	});

	it("refuses the credential when a field the scripts guard on no longer agrees with the text", async () => {
		// `expiresAtMs` and the three upstream fields are copies, outside the
		// envelope: the text is authoritative, so tampering one of these would
		// otherwise leave a credential that still authenticates under a record
		// the store did not write.
		const held = await activated();
		for (const [field, value] of [
			["expiresAtMs", String(at(60 * DAY).getTime())],
			["identityRevision", "identity-2"],
			["upstreamIssuer", "https://evil.test"],
			["upstreamSubject", "00u-bob"],
		] as const) {
			const original = await redis.hget(key("g-1", "grant"), field);
			await redis.hset(key("g-1", "grant"), field, value);
			expect((await held.open("g-1", at(DAY)))?.credentials.state, field).toBe("unreadable");
			await redis.hset(key("g-1", "grant"), field, original as string);
		}
		expect((await held.open("g-1", at(DAY)))?.credentials.state).toBe("ok");
	});

	it("keeps opening it when a field the authorization does not decide is changed", async () => {
		// The usage fields are outside the envelope on purpose (D1): they change
		// while the grant is in use, and none of them decides what it allows.
		const held = await activated();
		await redis.hset(key("g-1", "grant"), {
			lastUsedAt: String(at(3 * MIN).getTime()),
			ineligible: JSON.stringify(["no_finite_lifetime", String(at(3 * MIN).getTime()), "0"]),
			failureAt: String(at(3 * MIN).getTime()),
			failureKind: "unavailable",
			failureCount: "4",
		});
		const opened = await held.open("g-1", at(DAY));
		expect(opened?.credentials.state).toBe("ok");
		expect(opened?.grant.status).toBe("active");
	});

	it("answers nothing at all for a record whose own shape is broken, and keeps it", async () => {
		const held = await activated();
		await redis.hset(key("g-1", "grant"), "base", "not json");
		expect(await held.find("g-1", at(DAY))).toBeNull();
		expect(await held.open("g-1", at(DAY))).toBeNull();
		expect(await held.inspect("g-1", at(DAY))).toBeNull();
		expect(await redis.exists(key("g-1", "grant"))).toBe(1);
		// Nor is it listed — and its member is not dropped either, since the
		// record is still physically there.
		expect(await held.listBySubject("u-1", at(DAY))).toStrictEqual([]);
	});
});

describe("what the port may disclose (#593, D1, D16)", () => {
	it("hands out nothing for a grant that is not active, even with a credential still resident", async () => {
		// Every transition away from `active` deletes the credential, so this
		// cannot arise from the store. The status is checked all the same: a
		// transition that one day forgot the delete must still disclose nothing.
		const held = await activated();
		const sealed = (await redis.get(key("g-1", "cred"))) as string;
		await held.requireReauthorization({ grantId: "g-1", expectedVersion: 2, now: at(DAY) });
		await redis.set(key("g-1", "cred"), sealed);
		const opened = await held.open("g-1", at(DAY));
		expect(opened?.grant.status).toBe("reauthorization_required");
		expect(opened?.credentials.state).toBe("absent");
		expect((await held.inspect("g-1", at(DAY)))?.credentials).toBe("absent");
	});

	it("says a credential that is there and empty does not open, rather than that there is none", async () => {
		// An empty value is not something this store writes. Reporting it as
		// absent would read as "this grant never had one"; it has one, and it
		// does not open.
		const held = await activated();
		await redis.set(key("g-1", "cred"), "");
		expect((await held.open("g-1", at(DAY)))?.credentials.state).toBe("unreadable");
	});

	it("answers from the authenticated text even where the arithmetic field says otherwise", async () => {
		// `expiresAtMs` is a copy the scripts compare. Rewritten to the past, it
		// must not make the record read as expired: what the upstream consented
		// to is in the authenticated text, and that is what a caller is told.
		const held = await activated();
		// Far enough back that even with the retention added it is long past: a
		// horizon read from this field would put the record out of reach.
		await redis.hset(key("g-1", "grant"), "expiresAtMs", String(at(-60 * DAY).getTime()));
		const found = await held.find("g-1", at(DAY));
		expect(found?.status).toBe("active");
		expect(
			hasFederationGrantAuthorization(found as never) &&
				(found as { expiresAt: Date }).expiresAt.getTime(),
		).toBe(at(30 * DAY).getTime());
		expect((await held.listBySubject("u-1", at(DAY))).map((grant) => grant.id)).toStrictEqual([
			"g-1",
		]);
	});
});

describe("a field the envelope does not cover (#593, D16, the reviewer)", () => {
	it("answers nothing for a record whose retention is gone, rather than a grant nothing can end", async () => {
		// `retentionMs` is in neither the envelope nor the guard comparison, and
		// every script derives the horizon from it. Read through the configured
		// value instead, the record would go on disclosing its credential while
		// every write — a revocation included — was refused for ever. A grant
		// that cannot be ended is the one thing this store may never produce, so
		// a record without it answers nothing at all.
		const held = await activated();
		await redis.hdel(key("g-1", "grant"), "retentionMs");
		expect(await held.find("g-1", at(DAY))).toBeNull();
		expect(await held.open("g-1", at(DAY))).toBeNull();
		expect(await held.inspect("g-1", at(DAY))).toBeNull();
		expect(await held.listBySubject("u-1", at(DAY))).toStrictEqual([]);
	});

	it("still ends a grant whose horizon cannot even be computed: the credential does not outlive the attempt", async () => {
		// The other half of the retention case, and the one that matters most:
		// reads failing closed is no use if the credential stays at rest with no
		// way to end it. A revocation has no version to match and always wins,
		// so a horizon it cannot compute is not a reason to refuse — the record
		// is broken, and that is exactly when an operator reaches for this
		// (Copilot).
		const held = await activated();
		await redis.hdel(key("g-1", "grant"), "retentionMs");
		await held.revoke("g-1", "operator", at(DAY));
		expect(await redis.hget(key("g-1", "grant"), "status")).toBe("revoked");
		expect(await redis.hget(key("g-1", "grant"), "revokedBy")).toBe("operator");
		expect(await redis.exists(key("g-1", "cred"))).toBe(0);
	});

	it("still refuses a revocation for a record whose horizon says it has gone", async () => {
		// Computable and past is a different thing from not computable: a
		// tombstone is not revoked again, and the first revocation stays as it
		// was recorded.
		const held = await activated();
		expect(await held.revoke("g-1", "client", at(DAY))).toStrictEqual(
			expect.objectContaining({ ok: true }),
		);
		expect(await held.revoke("g-1", "operator", at(2 * DAY))).toStrictEqual({ ok: false });
		expect(await redis.hget(key("g-1", "grant"), "revokedBy")).toBe("client");
	});

	it("hides nothing by leaving a member behind: a record it cannot decode answers nothing to `find` either", async () => {
		// Copilot's inference from the rule above: a pending record revoked
		// without a reservation keeps its old, earlier horizon in the index, so
		// its member can be pruned while the tombstone's key lives on. It costs
		// nothing, because the reads that would disagree go through the same
		// decoding the reservation did — `find` answers null for exactly the
		// records the reservation was skipped for.
		const held = await activated();
		await redis.hset(key("g-1", "grant"), "base", "not json");
		await held.revoke("g-1", "operator", at(DAY));
		expect(await held.find("g-1", at(DAY))).toBeNull();
		expect(await held.listBySubject("u-1", at(DAY))).toStrictEqual([]);
	});

	it("still ends a grant whose record it cannot read: a revocation does not need to understand it", async () => {
		// `revoke` is the one write with no version to match, and the port has it
		// always win. Deciding from a record decoded a round trip earlier would
		// leave an operator unable to end a grant precisely when something has
		// gone wrong with it — with its credential still at rest.
		const held = await activated();
		await redis.hset(key("g-1", "grant"), "base", "not json");
		expect(await held.revoke("g-1", "operator", at(DAY))).toStrictEqual({ ok: false });
		expect(await redis.hget(key("g-1", "grant"), "status")).toBe("revoked");
		expect(await redis.exists(key("g-1", "cred"))).toBe(0);
	});

	it("refuses every write that would decide from a copy the envelope does not authenticate", async () => {
		// One `HSET` of the arithmetic copy, and a grant whose consented lifetime
		// ended an hour ago is renewable again: the scripts compare the copies,
		// so a write refused before the tamper succeeds after it. The credential
		// does read `unreadable` — but a fresh consent would then seal a new one
		// and leave a clean `active` grant with no trace of the edit.
		const held = await activated();
		const afterExpiry = at(31 * DAY);
		await redis.hset(key("g-1", "grant"), "expiresAtMs", String(at(365 * DAY).getTime()));
		expect(
			await held.nameIntent({
				grantId: "g-1",
				intent: { handle: "h-re", expiresAt: at(31 * DAY + 10 * MIN) },
				now: afterExpiry,
			}),
		).toStrictEqual({ ok: false });
		expect(
			await held.replaceCredentials({
				grantId: "g-1",
				expectedVersion: 2,
				credentials: credentials("2"),
				ineligible: null,
				now: afterExpiry,
			}),
		).toStrictEqual({ ok: false });
		expect(
			await held.activate({
				grantId: "g-1",
				intentHandle: "h-re",
				authorization: authorization({
					consent: { at: afterExpiry, sid: "sid-2", scopes: [...SCOPES] },
					authorizedAt: afterExpiry,
					expiresAt: at(60 * DAY),
				}),
				credentials: credentials("2"),
				now: afterExpiry,
			}),
		).toStrictEqual({ ok: false });
	});

	it("refuses a renewal whose upstream account was re-pointed in the keyspace", async () => {
		const held = await activated();
		await client_nameIntentOk(held);
		await redis.hset(key("g-1", "grant"), "upstreamSubject", "00u-bob");
		expect(
			await held.activate({
				grantId: "g-1",
				intentHandle: "h-re",
				authorization: authorization({
					upstream: { issuer: "https://dev-1.okta.test", subject: "00u-bob" },
					consent: { at: at(DAY), sid: "sid-2", scopes: [...SCOPES] },
					authorizedAt: at(DAY),
				}),
				credentials: credentials("bob"),
				now: at(DAY + MIN),
			}),
		).toStrictEqual({ ok: false });
	});

	it("says the same thing about an activation as the question that precedes it", async () => {
		// `isCurrentIntent` is what the connect callback asks before it exchanges
		// the code (D7), and it reads the authenticated text. An `activate` that
		// answered differently would let a code be exchanged for a grant the
		// question had already refused.
		const held = await activated();
		await client_nameIntentOk(held);
		await redis.hset(key("g-1", "grant"), "expiresAtMs", String(at(365 * DAY).getTime()));
		const afterExpiry = at(31 * DAY);
		expect(await held.isCurrentIntent("g-1", "h-re", afterExpiry)).toBe(false);
		expect(
			await held.activate({
				grantId: "g-1",
				intentHandle: "h-re",
				authorization: authorization({
					consent: { at: afterExpiry, sid: "sid-2", scopes: [...SCOPES] },
					authorizedAt: afterExpiry,
					expiresAt: at(60 * DAY),
				}),
				credentials: credentials("2"),
				now: afterExpiry,
			}),
		).toStrictEqual({ ok: false });
	});

	it("refuses an activation on a revoked record, whatever pointer it still carries", async () => {
		const held = await activated();
		await client_nameIntentOk(held);
		await redis.hset(key("g-1", "grant"), {
			status: "revoked",
			revokedBy: "operator",
			revokedAt: String(at(DAY).getTime()),
		});
		expect(
			await held.activate({
				grantId: "g-1",
				intentHandle: "h-re",
				authorization: authorization({
					consent: { at: at(DAY), sid: "sid-2", scopes: [...SCOPES] },
					authorizedAt: at(DAY),
				}),
				credentials: credentials("2"),
				now: at(DAY + MIN),
			}),
		).toStrictEqual({ ok: false });
	});

	it("keeps an optimistic guard that a version outside the safe integers would have lost", async () => {
		// `version` is compared as a number. Past 2^53 the increment is the same
		// double, so every refresh would match the version it just wrote and two
		// of them would both believe they had rotated the token.
		const held = await activated();
		await redis.hset(key("g-1", "grant"), "version", "10000000000000000000000");
		expect(await held.find("g-1", at(DAY))).toBeNull();
		expect(
			await held.replaceCredentials({
				grantId: "g-1",
				expectedVersion: 1e22,
				credentials: credentials("2"),
				ineligible: null,
				now: at(DAY),
			}),
		).toStrictEqual({ ok: false });
	});
});

describe("a credential from somewhere else (#593, D16)", () => {
	it("does not open under another grant, another subject's record, or another prefix", async () => {
		const first = await activated("g-1");
		await activated("g-2", [KEY_A], "u-2");
		const sealed = (await redis.get(key("g-2", "cred"))) as string;
		await redis.set(key("g-1", "cred"), sealed);
		expect((await first.open("g-1", at(DAY)))?.credentials.state).toBe("unreadable");
	});

	it("does not answer a record found under another grant's key, ciphertext and all (Codex on #593)", async () => {
		// The whole record copied, not just the secret: the authenticated data
		// names the credential's key, so a copied ciphertext alone fails. Copied
		// TOGETHER with the HASH that names it, it would authenticate if the key
		// in the authenticated data were rebuilt from the record's own `base.id`
		// rather than from the key actually read — and `open("g-target")` would
		// hand back another grant's record and credential as `ok`, while core
		// took its refresh lock on the ID it asked for.
		const held = await activated("g-source");
		const fields = await redis.hgetall(key("g-source", "grant"));
		const sealed = (await redis.get(key("g-source", "cred"))) as string;
		await redis.hset(key("g-target", "grant"), fields);
		await redis.set(key("g-target", "cred"), sealed);
		expect(await held.open("g-target", at(DAY))).toBeNull();
		expect(await held.find("g-target", at(DAY))).toBeNull();
		expect(await held.inspect("g-target", at(DAY))).toBeNull();
		// And the grant it was copied from is untouched.
		expect((await held.open("g-source", at(DAY)))?.credentials.state).toBe("ok");
	});

	it("does not re-seal a credential under an authorization it cannot authenticate the old one against (Codex on #593)", async () => {
		// A refresh seals the new credential under the authorization it read. If
		// that text was rewritten in the keyspace — the expiry extended, the
		// version left alone — the old ciphertext no longer authenticates under
		// it, and re-sealing would turn tampering that was detected into an
		// authorization this store had signed for.
		const held = await activated("g-1");
		const forged = JSON.parse(
			(await redis.hget(key("g-1", "grant"), "authorization")) as string,
		) as unknown[];
		forged[10] = String(at(365 * DAY).getTime());
		await redis.hset(key("g-1", "grant"), {
			authorization: JSON.stringify(forged),
			expiresAtMs: String(at(365 * DAY).getTime()),
		});
		const sealed = await redis.get(key("g-1", "cred"));
		expect(
			await held.replaceCredentials({
				grantId: "g-1",
				expectedVersion: 2,
				credentials: credentials("2"),
				ineligible: null,
				now: at(DAY),
			}),
		).toStrictEqual({ ok: false });
		expect(await redis.get(key("g-1", "cred"))).toBe(sealed);
	});

	it("does not open for a store whose key ring no longer holds the key that sealed it, and opens again when it does", async () => {
		const held = await activated("g-1", [KEY_A]);
		// The operator dropped the key. A configuration problem the status route
		// reports as `key_unavailable` (D11) and which putting the key back undoes.
		const without = store([KEY_B]);
		expect((await without.open("g-1", at(DAY)))?.credentials.state).toBe("key_unavailable");
		expect((await without.inspect("g-1", at(DAY)))?.credentials).toBe("key_unavailable");
		expect(await redis.exists(key("g-1", "cred"))).toBe(1);
		expect((await held.open("g-1", at(DAY)))?.credentials.state).toBe("ok");
	});

	it("tells wrong key material from a missing key: one never opens, the other is undone", async () => {
		await activated("g-1", [KEY_A]);
		const wrong = store([{ id: "k-a", key: material(9) }]);
		expect((await wrong.open("g-1", at(DAY)))?.credentials.state).toBe("unreadable");
	});
});

describe("a key ring that rotates (#593, D16)", () => {
	it("opens what an older key sealed, seals new writes under the first, and never re-seals what it did not write", async () => {
		await activated("g-1", [KEY_A]);
		// A key introduced later: first in the ring seals, the old one still opens.
		const rotated = store([KEY_B, KEY_A]);
		expect((await rotated.open("g-1", at(DAY)))?.credentials.state).toBe("ok");
		// A read did not re-seal it: the grant is still readable only because
		// `k-a` is in the ring, which is what the runbook's "keep the old key for
		// the one-year ceiling" is about.
		const onlyNew = store([KEY_B]);
		expect((await onlyNew.open("g-1", at(DAY)))?.credentials.state).toBe("key_unavailable");
		// A write does re-seal, under the ring's first key.
		const written = await rotated.replaceCredentials({
			grantId: "g-1",
			expectedVersion: 2,
			credentials: credentials("2"),
			ineligible: null,
			now: at(DAY),
		});
		expect(written.ok).toBe(true);
		expect((await onlyNew.open("g-1", at(DAY)))?.credentials.state).toBe("ok");
	});
});

describe("the subject index against what `find` answers (#593, D16)", () => {
	it("lists what `find` answers for at every stage of a grant's life", async () => {
		const held = await activated("g-1");
		const listed = async (now: Date): Promise<readonly string[]> =>
			(await held.listBySubject("u-1", now)).map((grant) => grant.status);
		expect(await listed(at(DAY))).toStrictEqual(["active"]);
		await held.requireReauthorization({ grantId: "g-1", expectedVersion: 2, now: at(DAY) });
		expect(await listed(at(DAY))).toStrictEqual(["reauthorization_required"]);
		await held.revoke("g-1", "client", at(2 * DAY));
		expect(await listed(at(2 * DAY))).toStrictEqual(["revoked"]);
		// Past the expiry and inside the retention: `find` still answers, so the
		// listing must too, which is why the index is scored by the horizon and
		// not by the expiry.
		expect(await held.find("g-1", at(31 * DAY))).not.toBeNull();
		expect(await listed(at(31 * DAY))).toStrictEqual(["revoked"]);
	});

	it("never hands one subject another's grant, however the index was written", async () => {
		const held = await activated("g-1", [KEY_A], "u-1");
		// A dangling member, as a lost write or a reused ID leaves behind.
		const member = Buffer.from(JSON.stringify("g-1"), "utf8").toString("base64url");
		await redis.zadd(
			`${prefix}sub:${Buffer.from(JSON.stringify("u-2"), "utf8").toString("base64url")}`,
			String(at(60 * DAY).getTime()),
			member,
		);
		expect(await held.listBySubject("u-2", at(DAY))).toStrictEqual([]);
		expect((await held.listBySubject("u-1", at(DAY))).map((g) => g.id)).toStrictEqual(["g-1"]);
	});

	it("keeps a member whose record is still being written, and drops one whose horizon is long past", async () => {
		const held = await activated("g-1");
		const index = `${prefix}sub:${Buffer.from(JSON.stringify("u-1"), "utf8").toString("base64url")}`;
		// A member for a record that does not exist: never dropped for being
		// absent, because the record may be one round trip away from existing.
		await redis.zadd(
			index,
			String(at(60 * DAY).getTime()),
			Buffer.from(JSON.stringify("g-later"), "utf8").toString("base64url"),
		);
		await held.listBySubject("u-1", at(DAY));
		expect(await redis.zcard(index)).toBe(2);
		// One whose horizon is past by more than the allowance goes.
		await redis.zadd(
			index,
			String(Date.now() - 3_600_000),
			Buffer.from(JSON.stringify("g-gone"), "utf8").toString("base64url"),
		);
		await held.listBySubject("u-1", at(DAY));
		expect(await redis.zcard(index)).toBe(2);
	});
});

describe("a retention that was changed under existing grants (#593, D16, Codex)", () => {
	it("keeps answering for a tombstone from the retention its record was created with", async () => {
		// A key's TTL and an index score are written once, so the scripts go on
		// using the retention the record carries. Decoding it under the new
		// setting instead would hide a tombstone whose keys are still there.
		await activated("g-1");
		const reopened = createRedisFederationGrantStore({
			client: makeIoredisFederationGrantStoreClient(redis),
			keyPrefix: prefix,
			encryption: { mode: "required", keys: [KEY_A] },
			tombstoneRetentionMs: 0,
		});
		const past = at(31 * DAY);
		expect((await reopened.find("g-1", past))?.status).toBe("active");
		expect((await reopened.listBySubject("u-1", past)).map((grant) => grant.id)).toStrictEqual([
			"g-1",
		]);
	});
});

describe("two clocks (#593, D16)", () => {
	it("tells a caller whose clock is far ahead nothing, and reclaims nothing on its behalf", async () => {
		const held = await activated("g-1");
		const farAhead = at(5_000 * DAY);
		expect(await held.find("g-1", farAhead)).toBeNull();
		expect(await held.open("g-1", farAhead)).toBeNull();
		expect(await held.listBySubject("u-1", farAhead)).toStrictEqual([]);
		// The keys, their deadlines and the index are exactly as they were.
		expect(await redis.exists(key("g-1", "grant"))).toBe(1);
		expect(await redis.exists(key("g-1", "cred"))).toBe(1);
		expect(Number(await redis.call("PEXPIRETIME", key("g-1", "grant")))).toBeGreaterThan(
			at(30 * DAY).getTime(),
		);
		expect((await held.find("g-1", at(DAY)))?.status).toBe("active");
		// And the index was not pruned on its behalf either: a listing prunes on
		// the adapter's own clock, so a caller in the far future cannot take the
		// members every other caller still needs.
		expect((await held.listBySubject("u-1", at(DAY))).map((grant) => grant.id)).toStrictEqual([
			"g-1",
		]);
	});
});

describe("the ring after construction (#593, D16)", () => {
	it("is not changed by the buffer the caller handed over", async () => {
		const mutable = Buffer.alloc(32, 7);
		const held = createRedisFederationGrantStore({
			client: makeIoredisFederationGrantStoreClient(redis),
			keyPrefix: prefix,
			encryption: { mode: "required", keys: [{ id: "k-m", key: mutable }] },
		});
		await held.createPending({
			id: "g-1",
			subject: "u-1",
			clientId: "agent",
			connection: "okta-calendar",
			intent: { handle: "h-g-1", expiresAt: at(10 * MIN) },
			now: T0,
		});
		await held.activate({
			grantId: "g-1",
			intentHandle: "h-g-1",
			authorization: authorization(),
			credentials: credentials(),
			now: at(2 * MIN),
		});
		mutable.fill(8);
		expect((await held.open("g-1", at(DAY)))?.credentials.state).toBe("ok");
	});
});

describe("the keyspace as a Cluster sees it (#593, D16)", () => {
	it("hashes a grant's three keys into one slot, and different grants into different ones", () => {
		const grant = slot(key("g-1", "grant"));
		expect(slot(key("g-1", "cred"))).toBe(grant);
		expect(slot(key("g-1", "lock"))).toBe(grant);
		// Different grants spread, which is the point of the per-grant tag: one
		// tag for the namespace would put every grant in a deployment on one node.
		expect(slot(key("g-2", "grant"))).not.toBe(grant);
	});

	it("keeps a hostile identifier out of the hash tag", () => {
		// An ID carrying a brace would otherwise end the tag early and scatter a
		// grant's keys across slots.
		for (const id of ["a}x{b", "{}", "}{", "a{b}c", "x".repeat(200)]) {
			expect(slot(key(id, "grant")), id).toBe(slot(key(id, "cred")));
			expect(slot(key(id, "grant")), id).toBe(slot(key(id, "lock")));
		}
	});

	it("refuses a prefix that would take the hash tag over", async () => {
		expect(() =>
			createRedisFederationGrantStore({
				client: makeIoredisFederationGrantStoreClient(redis),
				keyPrefix: "{fg}:",
				encryption: { mode: "required", keys: [KEY_A] },
			}),
		).toThrow(/keyPrefix/);
	});
});

describe("a script cache that was flushed (#593)", () => {
	it("goes on working: the next call loads the script again", async () => {
		const held = await activated("g-1");
		await redis.script("FLUSH");
		const written = await held.replaceCredentials({
			grantId: "g-1",
			expectedVersion: 2,
			credentials: credentials("2"),
			ineligible: null,
			now: at(DAY),
		});
		expect(written.ok).toBe(true);
		expect(hasFederationGrantAuthorization(written.ok ? written.grant : ({} as never))).toBe(true);
	});
});

describe("a snapshot while the grant is being renewed (#593, D16)", () => {
	it("is wholly one authorization or wholly the other, never one's record with the other's credential", async () => {
		const held = await activated("g-1");
		const renewal = authorization({
			authorizationRevision: "authorization-2",
			consent: { at: at(DAY), sid: "sid-2", scopes: [...SCOPES] },
			authorizedAt: at(DAY),
			expiresAt: at(60 * DAY),
		});
		for (let i = 0; i < 8; i += 1) {
			await held.nameIntent({
				grantId: "g-1",
				intent: { handle: `h-re-${i}`, expiresAt: at(DAY + 10 * MIN) },
				now: at(DAY),
			});
			const [opened] = await Promise.all([
				held.open("g-1", at(DAY + MIN)),
				held.activate({
					grantId: "g-1",
					intentHandle: `h-re-${i}`,
					authorization: { ...renewal, authorizationRevision: `authorization-${i + 2}` },
					credentials: credentials(`r${i}`),
					now: at(DAY + MIN),
				}),
			]);
			// Either the old pair or the new one — and never `unreadable`, which
			// is what a record read apart from its credential would give.
			expect(opened?.credentials.state, `iteration ${i}`).toBe("ok");
		}
	});
});

describe("plaintext, where an operator has allowed it (#593, D16)", () => {
	it("stores a credential neither reader takes for the other's", async () => {
		const plain = createRedisFederationGrantStore({
			client: makeIoredisFederationGrantStoreClient(redis),
			keyPrefix: prefix,
			encryption: { mode: "allow-plaintext" },
		});
		await plain.createPending({
			id: "g-1",
			subject: "u-1",
			clientId: "agent",
			connection: "okta-calendar",
			intent: { handle: "h-g-1", expiresAt: at(10 * MIN) },
			now: T0,
		});
		await plain.activate({
			grantId: "g-1",
			intentHandle: "h-g-1",
			authorization: authorization(),
			credentials: credentials(),
			now: at(2 * MIN),
		});
		expect((await plain.open("g-1", at(DAY)))?.credentials.state).toBe("ok");
		expect(await redis.get(key("g-1", "cred"))).toMatch(/^p2\./);
		// A store that requires encryption does not read it, and a plaintext one
		// does not read a sealed credential.
		expect((await store([KEY_A]).open("g-1", at(DAY)))?.credentials.state).toBe("unreadable");
	});

	it("is refused where plaintext is not acceptable, whatever the environment is called", async () => {
		for (const guard of [
			{ environment: "production" },
			{ environment: "staging" },
			{ deploymentMode: "multi" },
		]) {
			expect(
				() =>
					createRedisFederationGrantStore({
						client: makeIoredisFederationGrantStoreClient(redis),
						keyPrefix: prefix,
						encryption: { mode: "allow-plaintext" },
						guard,
					}),
				JSON.stringify(guard),
			).toThrow(/federation-grants/);
		}
	});

	it("refuses to be built with encryption required and no key to seal with", () => {
		expect(() =>
			createRedisFederationGrantStore({
				client: makeIoredisFederationGrantStoreClient(redis),
				keyPrefix: prefix,
				encryption: { mode: "required", keys: [] },
			}),
		).toThrow(/encryption key/);
		expect(() =>
			createRedisFederationGrantStore({
				client: makeIoredisFederationGrantStoreClient(redis),
				keyPrefix: prefix,
				encryption: { mode: "required", keys: [{ id: "k", key: Buffer.alloc(16, 1) }] },
			}),
		).toThrow(/32 bytes/);
	});
});

// ---------------------------------------------------------------------------
// What the store refuses to be built with. The scripts write a record or its
// subject-index entry and set the key's deadline last, so a deadline Redis
// refuses leaves what was written with no TTL at all. A retention past 2^53
// fails differently: the record it is written into does not read back.
// ---------------------------------------------------------------------------

describe("a retention or allowance whose deadline no clock reaches (the Date range)", () => {
	// 1e20 ms runs past ECMAScript's Date range from any today. Through
	// configuration it is `tombstoneRetention = 1e17` seconds, or a listing
	// allowance with a few zeros too many: typos nothing bounded.
	const PAST_THE_DATE_RANGE = 1e20;

	/** The store these options build, or the refusal — which is what they should get. */
	const attempt = (
		options: Partial<Parameters<typeof createRedisFederationGrantStore>[0]>,
	): { store: FederationGrantStore } | { refusal: unknown } => {
		try {
			return {
				store: createRedisFederationGrantStore({
					client: makeIoredisFederationGrantStoreClient(redis),
					keyPrefix: prefix,
					encryption: { mode: "required", keys: [KEY_A] },
					...options,
				}),
			};
		} catch (refusal) {
			return { refusal };
		}
	};

	/** Every key of this case that Redis holds with no deadline. */
	const withoutTtl = async (): Promise<string[]> => {
		const keys = await redis.keys(`${prefix}*`);
		const found: string[] = [];
		for (const name of keys) if ((await redis.pttl(name)) < 0) found.push(name);
		if (keys.length > 0) await redis.del(...keys);
		return found;
	};

	const lodge = (held: FederationGrantStore) =>
		held.createPending({
			id: "g-1",
			subject: "u-1",
			clientId: "agent",
			connection: "okta-calendar",
			intent: { handle: "h-g-1", expiresAt: at(10 * MIN) },
			now: T0,
		});

	it("refuses a tombstone retention past it when built, so no lodging fails and leaves its record behind", async () => {
		// Every record carries the retention it was written with, and one past
		// 2^53 does not read back. Such a store answered every lodging
		// `{ ok: false }`, and left the record and its index entry it had just
		// written behind — a store no grant could ever be made in, saying so
		// only as a refusal each client took for its own.
		const built = attempt({ tombstoneRetentionMs: PAST_THE_DATE_RANGE });
		const lodged = "store" in built ? await lodge(built.store) : "not built";
		const left = await redis.keys(`${prefix}*`);
		if (left.length > 0) await redis.del(...left);
		expect({ lodged, left }).toEqual({ lodged: "not built", left: [] });
		expect("refusal" in built && built.refusal).toBeInstanceOf(RangeError);
	});

	it("refuses a listing allowance past it when built, so no lodging leaves the subject's index without a TTL", async () => {
		const built = attempt({ listingAllowanceMs: PAST_THE_DATE_RANGE });
		if ("store" in built) {
			// What such a store did: the lodging reserved the grant in its
			// subject's index, and then Redis refused the index's deadline.
			await lodge(built.store).catch(() => undefined);
		}
		expect(await withoutTtl()).toEqual([]);
		expect("refusal" in built && built.refusal).toBeInstanceOf(RangeError);
	});

	it("refuses either past it when built, however far past, and takes one that ends inside it", () => {
		// A RangeError, as the in-process store refuses its retention and as
		// the shared expiry rule refuses every lifetime: one setting, one class,
		// whichever adapter a composition builds.
		for (const bad of [8_640_000_000_000_001, PAST_THE_DATE_RANGE, 1e21, -1, Number.NaN]) {
			for (const option of ["tombstoneRetentionMs", "listingAllowanceMs"] as const) {
				const built = attempt({ [option]: bad });
				expect(built, `${option} ${String(bad)}`).toHaveProperty("refusal");
				expect("refusal" in built && built.refusal, `${option} ${String(bad)}`).toBeInstanceOf(
					RangeError,
				);
			}
		}
		expect(attempt({ tombstoneRetentionMs: 365 * DAY })).toHaveProperty("store");
		expect(attempt({ listingAllowanceMs: 365 * DAY })).toHaveProperty("store");
	});
});
