import { createHash, generateKeyPairSync, type KeyObject, randomBytes, sign } from "node:crypto";
import { isUnavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { z } from "zod";
import { keptPasskeys } from "./records.ts";
import type { section } from "./section.ts";
import type {
	ChallengeStore,
	PasskeyRecords,
	PasskeyStore,
	StoredChallenge,
	StoredPasskey,
} from "./store.ts";

export type WebauthnSettings = z.input<typeof section>;

export const testOrigin = "https://rp.example";

/** The webauthn part of a test's configuration: a relying party at `rp.example`. */
export function webauthnConfig(settings: Partial<WebauthnSettings> = {}) {
	return {
		webauthn: { "rp-id": "rp.example", "rp-name": "RP", origins: [testOrigin], ...settings },
	};
}

/** Where a ceremony runs, as the browser reports it in the client data. */
export interface Client {
	readonly origin: string;
	readonly crossOrigin?: boolean;
	readonly topOrigin?: string;
}

/** What an authenticator may be told to do otherwise, for a test of a refusal. */
export interface Twist {
	/** The relying party the authenticator data names, instead of the one the options name. */
	readonly rpId?: string;
	/** The user handle an assertion carries; null carries none. */
	readonly userHandle?: string | null;
	/** The count an assertion carries. */
	readonly counter?: number;
	/** The id a new credential takes, instead of 16 random bytes. */
	readonly credentialId?: string;
	/** The client data, encoded as given instead of as JSON in base64url. */
	readonly clientDataJSON?: (json: string) => string;
	/** Answers what a browser would refuse: the options' rules and its own limits are not checked. */
	readonly overlook?: boolean;
}

/** Credential creation options, as a relying party sends them in JSON. */
export interface CreationOptions {
	readonly rp: { readonly id?: string };
	readonly user: { readonly id: string };
	readonly challenge: string;
	readonly pubKeyCredParams: readonly { readonly alg: number; readonly type: string }[];
	readonly excludeCredentials?: readonly { readonly id: string; readonly type: string }[];
	readonly authenticatorSelection?: {
		readonly residentKey?: string;
		readonly requireResidentKey?: boolean;
		readonly userVerification?: string;
	};
}

/** Credential request options, as a relying party sends them in JSON. */
export interface RequestOptions {
	readonly challenge: string;
	readonly rpId?: string;
	readonly allowCredentials?: readonly { readonly id: string; readonly type: string }[];
	readonly userVerification?: string;
}

type Cbor = number | string | Uint8Array | Map<Cbor, Cbor>;

/** CBOR for the few kinds WebAuthn uses: integers, text, bytes and maps. */
function cbor(value: Cbor): number[] {
	const head = (major: number, n: number) =>
		n < 24
			? [(major << 5) | n]
			: n < 256
				? [(major << 5) | 24, n]
				: [(major << 5) | 25, n >> 8, n & 255];
	if (typeof value === "number") return value >= 0 ? head(0, value) : head(1, -1 - value);
	if (typeof value === "string") {
		const bytes = Buffer.from(value);
		return [...head(3, bytes.length), ...bytes];
	}
	if (value instanceof Uint8Array) return [...head(2, value.length), ...value];
	return [...head(5, value.size), ...[...value].flatMap(([k, v]) => [...cbor(k), ...cbor(v)])];
}

const b64 = (bytes: Uint8Array | string) => Buffer.from(bytes).toString("base64url");

/** Authenticator data flags: user present, user verified, backup eligible, backed up, attested data. */
const [UP, UV, BE, BS, AT] = [1, 4, 8, 16, 64];

/** A browser's refusal, named as `navigator.credentials` names it. */
const refused = (name: string, message: string) => new DOMException(message, name);

/** Whether a browser on `host` takes `rpId`: the host, or a domain above it but no single label. */
const servesHost = (rpId: string, host: string) =>
	host === rpId || (host.endsWith(`.${rpId}`) && rpId.includes("."));

interface Kept {
	readonly key: KeyObject;
	readonly handle: string;
	readonly rpId: string;
	readonly discoverable: boolean;
	count: number;
}

/**
 * A software WebAuthn authenticator behind a browser: it makes ES256 (or ES384) credentials,
 * attests with `none`, asserts with a count that goes up unless it keeps none, and checks the
 * options as a browser does unless a twist says to overlook them.
 */
export function softwareAuthenticator(
	settings: {
		/** Whether it can verify the user; it can unless told otherwise. */
		readonly userVerified?: boolean;
		readonly backupEligible?: boolean;
		readonly countless?: boolean;
		readonly algorithm?: "ES256" | "ES384";
		/** Whether it can keep a discoverable credential; it can unless told otherwise. */
		readonly discoverable?: boolean;
	} = {},
) {
	const kept = new Map<string, Kept>();
	const alg = settings.algorithm === "ES384" ? -35 : -7;
	const canVerify = settings.userVerified !== false;
	const canDiscover = settings.discoverable !== false;
	const flags = (attested: boolean, verified: boolean) =>
		UP | (verified ? UV : 0) | (settings.backupEligible ? BE | BS : 0) | (attested ? AT : 0);
	/** Verifies the user unless told it is discouraged, and only when it can; required and unable is refused. */
	const verifies = (asked: string | undefined, twist: Twist) => {
		check(twist, asked === "required" && !canVerify, "NotAllowedError", "cannot verify the user");
		return canVerify && asked !== "discouraged";
	};
	const authData = (
		rp: string,
		attested: boolean,
		verified: boolean,
		count: number,
		rest: number[] = [],
	) => {
		const counter = Buffer.alloc(4);
		counter.writeUInt32BE(count);
		const rpHash = createHash("sha256").update(rp).digest();
		return Buffer.from([...rpHash, flags(attested, verified), ...counter, ...rest]);
	};
	const clientData = (type: string, challenge: string, client: Client, twist: Twist) => {
		// A browser names a top origin only for a page in a cross-origin frame.
		if (client.topOrigin !== undefined && client.crossOrigin !== true && !twist.overlook) {
			throw new Error("a top origin is reported only in a cross-origin frame");
		}
		const json = JSON.stringify({
			type,
			challenge,
			origin: client.origin,
			crossOrigin: client.crossOrigin ?? false,
			...(client.topOrigin ? { topOrigin: client.topOrigin } : {}),
		});
		return twist.clientDataJSON ? twist.clientDataJSON(json) : b64(json);
	};
	/** The relying party a browser on the client's page takes, or its refusal. */
	const rpFor = (asked: string | undefined, client: Client, twist: Twist) => {
		const host = new URL(client.origin).hostname;
		const rpId = asked ?? host;
		if (!twist.overlook && !servesHost(rpId, host)) {
			throw refused("SecurityError", `${rpId} is not a domain of ${host}`);
		}
		return rpId;
	};
	/** Throws the refusal a browser answers where `broken`, unless told to overlook it. */
	const check = (twist: Twist, broken: boolean, name: string, message: string) => {
		if (broken && !twist.overlook) throw refused(name, message);
	};

	const create = (options: CreationOptions, client: Client, twist: Twist = {}) => {
		const rpId = rpFor(options.rp.id, client, twist);
		const clientDataJSON = clientData("webauthn.create", options.challenge, client, twist);
		const handleBytes = Buffer.from(options.user.id, "base64url").length;
		check(twist, handleBytes < 1 || handleBytes > 64, "TypeError", "user.id is 1 to 64 bytes");
		const offered = options.pubKeyCredParams.some((p) => p.type === "public-key" && p.alg === alg);
		check(twist, !offered, "NotSupportedError", "no algorithm it has is offered");
		const excluded = (options.excludeCredentials ?? []).some((c) => kept.get(c.id)?.rpId === rpId);
		check(twist, excluded, "InvalidStateError", "it holds an excluded credential");
		const selection = options.authenticatorSelection ?? {};
		const residentKey =
			selection.residentKey ?? (selection.requireResidentKey ? "required" : "discouraged");
		check(twist, residentKey === "required" && !canDiscover, "NotAllowedError", "not discoverable");
		const verified = verifies(selection.userVerification, twist);

		const { privateKey, publicKey } = generateKeyPairSync("ec", {
			namedCurve: alg === -35 ? "P-384" : "P-256",
		});
		const jwk = publicKey.export({ format: "jwk" });
		const cose = new Map<Cbor, Cbor>([
			[1, 2],
			[3, alg],
			[-1, alg === -35 ? 2 : 1],
			[-2, Buffer.from(jwk.x ?? "", "base64url")],
			[-3, Buffer.from(jwk.y ?? "", "base64url")],
		]);
		const id = twist.credentialId ? Buffer.from(twist.credentialId, "base64url") : randomBytes(16);
		const attested = [...Buffer.alloc(16), id.length >> 8, id.length & 255, ...id, ...cbor(cose)];
		const data = authData(twist.rpId ?? rpId, true, verified, 0, attested);
		const discoverable = canDiscover && residentKey !== "discouraged";
		kept.set(b64(id), { key: privateKey, handle: options.user.id, rpId, discoverable, count: 0 });
		const attestationObject = cbor(
			new Map<Cbor, Cbor>([
				["fmt", "none"],
				["attStmt", new Map()],
				["authData", data],
			]),
		);
		return {
			id: b64(id),
			rawId: b64(id),
			type: "public-key",
			response: {
				clientDataJSON,
				attestationObject: b64(Buffer.from(attestationObject)),
				transports: ["internal"],
			},
			clientExtensionResults: {},
		};
	};

	const get = (options: RequestOptions, client: Client, twist: Twist = {}, pick?: string) => {
		const rpId = rpFor(options.rpId, client, twist);
		const clientDataJSON = clientData("webauthn.get", options.challenge, client, twist);
		const listed = (options.allowCredentials ?? []).map((c) => c.id);
		// With none listed, a browser offers the discoverable credentials it holds for the party.
		const offered = [...kept].filter(([id, c]) =>
			twist.overlook
				? true
				: c.rpId === rpId && (listed.length ? listed.includes(id) : c.discoverable),
		);
		const chosen = offered.find(([id]) => id === pick) ?? (pick ? undefined : offered.at(-1));
		if (!chosen) throw refused("NotAllowedError", "no credential it holds is asked for");
		const verified = verifies(options.userVerification, twist);
		const [id, credential] = chosen;
		if (!settings.countless) credential.count += 1;
		const count = twist.counter ?? credential.count;
		const data = authData(twist.rpId ?? credential.rpId, false, verified, count);
		const signed = Buffer.concat([
			data,
			createHash("sha256").update(Buffer.from(clientDataJSON, "base64url")).digest(),
		]);
		// An authenticator answers the handle only of a credential it keeps discoverable.
		const own = credential.discoverable ? credential.handle : null;
		const handle = twist.userHandle === undefined ? own : twist.userHandle;
		return {
			id,
			rawId: id,
			type: "public-key",
			response: {
				clientDataJSON,
				authenticatorData: b64(data),
				signature: b64(sign(alg === -35 ? "sha384" : "sha256", signed, credential.key)),
				...(handle === null ? {} : { userHandle: handle }),
			},
			clientExtensionResults: {},
		};
	};

	return {
		/** Answers creation options as `navigator.credentials.create` does. */
		create,
		/** Answers request options as `navigator.credentials.get` does, with `pick` if the user picks one. */
		get,
	};
}

/** A place that keeps webauthn's passkeys, as one implementation of its store interface offers it. */
export interface PasskeyPlace {
	readonly passkeys: PasskeyStore;
	/** Moves the place's clock on. */
	advance(ms: number): void;
	/** Before the next update of a subject's `key` writes, another writer changes its record as given. */
	raceNextUpdate(key: string, change: (record: StoredPasskey) => StoredPasskey): void;
	/** Where answers can be lost: the next write takes effect, but its answer is lost. */
	readonly loseNextAnswer?: () => void;
	/** Where the place replicates: a replica takes over, keeping only what was confirmed. */
	readonly failover?: () => Promise<void>;
	/** Where the place can restart: it does, keeping only what it holds durably. */
	readonly restart?: () => Promise<void>;
	/** Where memory can run short: it does, keeping only what is kept from eviction. */
	readonly pressMemory?: () => Promise<void>;
	/** Where reads can meet unconfirmed writes: runs `during` as the next save takes effect, unconfirmed. */
	readonly duringNextSave?: (during: () => Promise<void>) => void;
}

const handleOf = () => randomBytes(32).toString("base64url");

/** What webauthn needs from any implementation: records kept whole and apart, without end, written by webauthn in one shape. */
export function passkeyStoreContract(name: string, open: () => Promise<PasskeyPlace>): void {
	let n = 0;
	const fresh = () => `k-${++n}-${randomBytes(6).toString("hex")}`;
	const held = (value: object) => value as unknown as StoredPasskey;
	const counted = (record: StoredPasskey) => (record as unknown as { n: number }).n;
	const plus = (by: number) => (record: StoredPasskey) => ({
		value: held({ n: counted(record) + by }),
	});

	describe(`webauthn's passkey store interface: ${name}`, () => {
		it("keeps a record whole and once per key in each space, the two apart", async () => {
			const { passkeys } = await open();
			const key = fresh();
			const odd = held({ state: "unheard-of", nested: { list: [1, "two"] } });
			expect(await passkeys.credentials.save(key, odd)).toBe("created");
			expect(await passkeys.credentials.save(key, held({ n: 1 }))).toBe("exists");
			expect(await passkeys.subjects.read(key)).toBeUndefined();
			expect(await passkeys.subjects.save(key, held({ n: 1 }))).toBe("created");
			expect(await passkeys.credentials.read(key)).toEqual(odd);
			expect(await passkeys.subjects.update(key, plus(1))).toEqual({
				before: held({ n: 1 }),
				after: held({ n: 2 }),
			});
			expect(await passkeys.credentials.update(fresh(), plus(1))).toBeUndefined();
		});

		it("changes a record only from what it holds, again after a racing writer", async () => {
			const place = await open();
			const key = fresh();
			await place.passkeys.subjects.save(key, held({ n: 1 }));
			place.raceNextUpdate(key, (record) => held({ n: counted(record) * 10 }));
			expect((await place.passkeys.subjects.update(key, plus(1)))?.after).toEqual(held({ n: 11 }));
		});

		it("keeps records without end, through a restart and through memory pressure", async () => {
			const place = await open();
			const key = fresh();
			await place.passkeys.credentials.save(key, held({ n: 1 }));
			place.advance(10 * 365 * 86_400_000);
			await place.restart?.();
			await place.pressMemory?.();
			expect(await place.passkeys.credentials.read(key)).toEqual(held({ n: 1 }));
		});

		it("settles writes whose answers were lost, and keeps them through a failover", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover } = place;
			if (!lose || !failover) return context.skip();
			const key = fresh();
			lose();
			expect(await place.passkeys.subjects.save(key, held({ n: 1 }))).toBe("created");
			lose();
			expect((await place.passkeys.subjects.update(key, plus(1)))?.after).toEqual(held({ n: 2 }));
			await failover();
			expect(await place.passkeys.subjects.read(key)).toEqual(held({ n: 2 }));
		});

		// The writer gives up once the clock passes its patience, so only the read could have kept it.
		it("reads a record another request wrote only as a failover keeps it", async (context) => {
			const place = await open();
			const { duringNextSave, failover } = place;
			if (!duringNextSave || !failover) return context.skip();
			const key = fresh();
			let seen: StoredPasskey | undefined;
			duringNextSave(async () => {
				seen = await place.passkeys.credentials.read(key);
				await failover();
				place.advance(60_000);
			});
			await place.passkeys.credentials.save(key, held({ n: 1 })).catch(() => undefined);
			expect(await place.passkeys.credentials.read(key)).toEqual(seen);
		});

		it("is never given a handle or a credential id webauthn would not write", async () => {
			const { passkeys } = await open();
			const records = keptPasskeys(passkeys);
			const subject = fresh();
			const padded = `${handleOf()}=`;
			await expect(records.handleFor(subject, padded)).rejects.toThrow(
				"a handle must be canonical",
			);
			expect(await records.holder(subject)).toBeUndefined();
			const handle = await records.handleFor(subject, handleOf());
			const credential = {
				id: "AAAA",
				publicKey: "pQ",
				signCount: 0,
				userHandle: handle,
				backupEligible: false,
				backedUp: false,
			};
			for (const [name, twisted] of Object.entries({
				"id not canonical": { ...credential, id: "AAB" },
				"id padded": { ...credential, id: "AAAA==" },
				"handle padded": { ...credential, userHandle: `${handle}=` },
			})) {
				expect(await records.register(subject, twisted, 10), name).toBe("malformed");
			}
			expect(await records.passkey("AAB")).toBeUndefined();
			expect((await records.holder(subject))?.credentials).toEqual([]);
			expect(await records.register(subject, credential, 10)).toBe("registered");
			expect((await records.passkey("AAAA"))?.subject).toBe(subject);
		});

		it("answers unavailable for a record not in the shape webauthn writes", async () => {
			const { passkeys } = await open();
			const keys: string[] = [];
			const spied = (records: PasskeyRecords): PasskeyRecords => ({
				...records,
				save: (key, record) => {
					keys.push(key);
					return records.save(key, record);
				},
			});
			const [subject, id] = [fresh(), randomBytes(16).toString("base64url")];
			const watched = {
				credentials: spied(passkeys.credentials),
				subjects: spied(passkeys.subjects),
			};
			const records = keptPasskeys(watched);
			const userHandle = await records.handleFor(subject, handleOf());
			const kept = {
				id,
				publicKey: "pQ",
				signCount: 0,
				userHandle,
				backupEligible: false,
				backedUp: false,
			};
			expect(await records.register(subject, kept, 10)).toBe("registered");
			const [holderKey = "", credentialKey = ""] = keys;
			const twist = (record: StoredPasskey) => ({ value: held({ ...record, v: 2 }) });
			await passkeys.subjects.update(holderKey, twist);
			await passkeys.credentials.update(credentialKey, twist);
			for (const read of [() => records.holder(subject), () => records.passkey(id)]) {
				await expect(read()).rejects.toSatisfy(isUnavailable);
			}
		});
	});
}

/** A place that keeps webauthn's challenges, as one implementation of its store interface offers it. */
export interface ChallengePlace {
	readonly challenges: ChallengeStore;
	/** Moves the place's clock on, so lifetimes run out. */
	advance(ms: number): void;
	/** Where answers can be lost: the next write takes effect, but its answer is lost. */
	readonly loseNextAnswer?: () => void;
	/** Where the place replicates: a replica takes over, keeping only what was confirmed. */
	readonly failover?: () => Promise<void>;
	/** Where the place can restart: it does, keeping only what it holds durably. */
	readonly restart?: () => Promise<void>;
	/** Where what the place was given can be searched: whether any of it carried `text`. */
	readonly holds?: (text: string) => boolean;
}

/** What webauthn needs from any implementation: a challenge kept once for its lifetime, taken once, never in clear. */
export function challengeStoreContract(name: string, open: () => Promise<ChallengePlace>): void {
	const fresh = () => randomBytes(32).toString("base64url");
	const held = (value: object) => value as unknown as StoredChallenge;
	const mark = held({ taken: true });

	describe(`webauthn's challenge store interface: ${name}`, () => {
		it("keeps a challenge once, and puts the mark in its place for the rest of its lifetime", async () => {
			const place = await open();
			const challenge = fresh();
			const record = held({ kind: "assertion", nested: [1, "two"] });
			expect(await place.challenges.open(challenge, record, 1000)).toBe("created");
			expect(await place.challenges.open(challenge, held({ n: 1 }), 1000)).toBe("exists");
			place.advance(500);
			expect(await place.challenges.take(challenge, mark)).toEqual({ before: record, after: mark });
			expect(await place.challenges.take(challenge, mark)).toEqual({ before: mark, after: mark });
			place.advance(500);
			expect(await place.challenges.take(challenge, mark)).toBeUndefined();
			expect(await place.challenges.take(fresh(), mark)).toBeUndefined();
		});

		it("never gives a challenge to what the place holds, in clear", async (context) => {
			const place = await open();
			const { holds } = place;
			if (!holds) return context.skip();
			const [challenge, kept] = [fresh(), fresh()];
			await place.challenges.open(challenge, held({ kept }), 60_000);
			await place.challenges.take(challenge, mark);
			expect([holds(kept), holds(challenge)]).toEqual([true, false]);
		});

		it("keeps a taken mark through a restart, a lost answer and a failover", async (context) => {
			const place = await open();
			const { restart, loseNextAnswer: lose, failover } = place;
			if (!restart || !lose || !failover) return context.skip();
			const challenge = fresh();
			await place.challenges.open(challenge, held({ n: 1 }), 60_000);
			lose();
			expect((await place.challenges.take(challenge, mark))?.before).toEqual(held({ n: 1 }));
			await restart();
			await failover();
			expect((await place.challenges.take(challenge, mark))?.before).toEqual(mark);
		});
	});
}
