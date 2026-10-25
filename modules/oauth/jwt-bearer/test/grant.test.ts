import { generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientsModule from "@mod/clients/module";
import { clientsConfig, confidentialClient } from "@mod/clients/testing";
import externalJwtModule from "@mod/external-jwt/module";
import { testSigner } from "@mod/external-jwt/testing";
import { type GrantOutcome, targetRules } from "@mod/grants";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import {
	assemble,
	BootRefused,
	defineModule,
	kernelConfig,
	type Module,
	Unavailable,
} from "@mod/kernel";
import {
	quietRuntime,
	recordingLog,
	switchedModule,
	takesUnused,
	unavailableSwitch,
} from "@mod/kernel/testing";
import { type Narrower, type Outbound, outbound } from "@mod/outbound";
import outboundModule from "@mod/outbound/module";
import { memoryRecords } from "@mod/records/testing";
import secretHashModule from "@mod/secret-hash/module";
import { simulatedStore } from "@mod/store/testing";
import { revocations } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { tokenEndpointLocation } from "@mod/token-endpoint";
import { grantCaller, grantCalls } from "@mod/token-endpoint/testing";
import { type IssuanceRequest, issuancePolicies, tokens } from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { calculateJwkThumbprint, exportJWK, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import {
	type JtiLedger,
	jtiLedgers,
	type LinkedSubjects,
	linkedSubjects,
	type SignerKeys,
	signerKeys,
	spentAssertions,
} from "../src/contract.ts";
import jwtBearer from "../src/module.ts";

const now = 1_800_000_000_000;
/** The kernel's time, which a test may move and must put back. */
const clock = { at: now };
const runtime = quietRuntime({
	clock: { now: () => clock.at },
	random: { bytes: (n) => new Uint8Array(n).fill(3) },
});
const issuer = "https://as.example";
const pem = (k: KeyObject, type: "pkcs8" | "spki") => k.export({ format: "pem", type }).toString();
const upstream = generateKeyPairSync("ed25519");
const stranger = generateKeyPairSync("ed25519");
const grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const trustedUpstream = [
	{
		issuer: "https://idp.example",
		subject: "as-is",
		"accept-any-subject": true,
		keys: [{ alg: "EdDSA", "public-key": pem(upstream.publicKey, "spki") }],
	},
];

/** Each name the store was asked to save, in order, across the tests, and the lifetime asked for it. */
const saved: string[] = [];
const keptFor: number[] = [];
/** Spent assertions on records' stand-in, whose own clock runs `aheadMs` past the kernel's. */
const spentOn = (aheadMs = 0) =>
	defineModule({ name: "spent-assertions", takes: [] }, (m) => [
		m.provide(spentAssertions).by(() => {
			const stand = memoryRecords<true>(() => clock.at + aheadMs, { shards: 1, perShard: 1 });
			return {
				save: (name: string, lifetimeMs: number) => {
					saved.push(name);
					keptFor.push(lifetimeMs);
					return stand.records.create(name, true, lifetimeMs);
				},
			};
		}),
	]);

/** The grant's assembly; `located` is where the token endpoint answers, null for no public origin. */
function assembly(
	storeAheadMs = 0,
	named = issuer,
	located: string | null = `${issuer}/oauth/token`,
	issuers: readonly Record<string, unknown>[] = trustedUpstream,
	out: Module = outboundModule,
	extra: readonly Module[] = [],
) {
	const location = defineModule({ name: "token-endpoint-location", takes: [] }, (m) => [
		m.provide(tokenEndpointLocation).by(() => ({ url: located ?? undefined })),
	]);
	return {
		modules: [
			location,
			http,
			tokensStandIn(),
			issuerModule,
			clientsModule,
			secretHashModule,
			grantCaller,
			clientAllowanceModule,
			out,
			externalJwtModule,
			simulatedStore().module,
			subjectRevocationStandIn,
			jwtBearer,
			spentOn(storeAheadMs),
			...extra,
		],
		config: {
			...kernelConfig(),
			...httpConfig(),
			...issuerConfig({ url: named }),
			...clientsConfig([
				confidentialClient({
					id: "app",
					sections: allowancesFor({
						grants: [grantType],
						scopes: ["read"],
						"default-scopes": ["read"],
					}),
				}),
			]),
			"jwt-bearer": { issuers },
		},
		runtime,
	};
}

/** Where the token endpoint answers; null for a deployment without a public origin. */
async function serve(...given: Parameters<typeof assembly>) {
	const app = await assemble(assembly(...given));
	/** Calls the grant as the token endpoint would for the client "app". */
	const grant = (a: string, more: Record<string, string> = {}) =>
		app.get(grantCalls).call(grantType, "app", { grant_type: grantType, assertion: a, ...more });
	return {
		grant,
		verify: (token: string) => app.get(tokens).verifyAccess(token),
		revoke: (subject: string, keepDelegations = false) =>
			app.get(revocations).record(subject, { keepDelegations }),
	};
}

function assertion(
	claims: Record<string, unknown>,
	key: KeyObject = upstream.privateKey,
	header: { kid?: string } = {},
) {
	return new SignJWT({ jti: `j-${Math.random()}`, ...claims })
		.setProtectedHeader({ alg: "EdDSA", ...header })
		.sign(key);
}
const base = { iss: "https://idp.example", sub: "alice", aud: issuer, exp: now / 1000 + 120 };

const errorOf = (outcome: GrantOutcome) => (outcome.kind === "error" ? outcome.error : "issued");
const saidOf = (outcome: GrantOutcome) =>
	outcome.kind === "error" ? `${outcome.error}: ${outcome.description}` : "issued";

/** A rule narrowing to the `resource` asked when the issuance may have it, as resource indicators do. */
const narrowing = defineModule({ name: "narrowing", takes: [] }, (m) => [
	m.contribute(targetRules).by(() => ({
		target: ({ param, audience, within }) => {
			const asked = param("resource");
			if (!asked) return { kind: "audience", audience };
			return within(asked)
				? { kind: "audience", audience: [asked] }
				: { kind: "error", error: "invalid_target", description: `not ${asked}` };
		},
		// A grant that takes no audience gets no resource.
		untargeted: ({ param }) =>
			param("resource")
				? { kind: "error", error: "invalid_target", description: "takes no resource" }
				: undefined,
	})),
]);

describe("jwt-bearer", () => {
	it("issues for the audience asked within the client's, refusing another before the jti is used up", async () => {
		const s = await serve(
			undefined,
			issuer,
			`${issuer}/oauth/token`,
			trustedUpstream,
			outboundModule,
			[narrowing],
		);
		const signed = await assertion(base);
		expect(saidOf(await s.grant(signed, { resource: "https://api" }))).toBe(
			"invalid_target: not https://api",
		);
		const issued = await s.grant(signed, { resource: issuer });
		if (issued.kind !== "issued") throw new Error(issued.error);
		expect(await s.verify(String(issued.body.access_token))).toMatchObject({
			kind: "valid",
			grant: { audience: [issuer] },
		});
	});

	it("takes a resource as a grant that asks it, where the rule refuses one to a grant that takes none", async () => {
		const s = await serve(
			undefined,
			issuer,
			`${issuer}/oauth/token`,
			trustedUpstream,
			outboundModule,
			[narrowing],
		);
		expect(saidOf(await s.grant(await assertion(base), { resource: issuer }))).toBe("issued");
	});

	it("reads no resource where no rule is composed", async () => {
		const s = await serve();
		expect(errorOf(await s.grant(await assertion(base), { resource: "https://api" }))).toBe(
			"issued",
		);
	});

	it("still refuses a replay while the store clock runs ahead", async () => {
		const s = await serve(200_000);
		const signed = await assertion(base);
		expect(errorOf(await s.grant(signed))).toBe("issued");
		expect(errorOf(await s.grant(signed))).toBe("invalid_grant");
	});

	it("issues a token for the assertion's subject, capped at its expiry, once per jti", async () => {
		const s = await serve();
		const signed = await assertion(base);
		const first = await s.grant(signed);
		if (first.kind !== "issued") throw new Error(first.error);
		expect(first.body.expires_in).toBe(120);
		expect(await s.verify(String(first.body.access_token))).toMatchObject({
			kind: "valid",
			grant: { subject: "alice", issuedTo: "app", scope: ["read"] },
		});
		expect(errorOf(await s.grant(signed))).toBe("invalid_grant");
	});

	it("refuses as expired an assertion with less than a second left when its jti would be used up, or a token with less once issued", async () => {
		/** How long each asking of the issuance policies takes: before the jti is used up, then in issuing. */
		let waits: number[] = [];
		const waiting = defineModule({ name: "test-policy", takes: [] }, (m) => [
			m.contribute(issuancePolicies).by(() => ({
				name: "test-policy",
				judge: async () => {
					clock.at += waits.shift() ?? 0;
					return { kind: "allowed" };
				},
			})),
		]);
		const s = await serve(
			undefined,
			issuer,
			`${issuer}/oauth/token`,
			trustedUpstream,
			outboundModule,
			[waiting],
		);
		try {
			const before = saved.length;
			// Past its end within the clock allowance: no token, and its jti left unused.
			expect(saidOf(await s.grant(await assertion({ ...base, exp: now / 1000 - 10 })))).toBe(
				"invalid_grant: expired",
			);
			// Less than a second left once the steps before the jti are done: the same.
			waits = [119_500];
			expect(saidOf(await s.grant(await assertion(base)))).toBe("invalid_grant: expired");
			expect(saved.length).toBe(before);
			// A second left then, but issuing takes it: the token is handed to no one, the jti used up.
			clock.at = now;
			waits = [0, 119_500];
			expect(saidOf(await s.grant(await assertion(base)))).toBe("invalid_grant: expired");
			expect(saved.length).toBe(before + 1);
			clock.at = now;
			waits = [0, 0];
			expect(saidOf(await s.grant(await assertion(base)))).toBe("issued");
		} finally {
			clock.at = now;
		}
	});

	it("holds an issuer's assertions to its own lifetime and clock skew, narrower than the section's", async () => {
		const own = (more: Record<string, unknown>) =>
			serve(undefined, issuer, `${issuer}/oauth/token`, [{ ...trustedUpstream[0], ...more }]);
		const short = await own({ "max-assertion-lifetime": "10m" });
		expect(saidOf(await short.grant(await assertion({ ...base, exp: now / 1000 + 1200 })))).toBe(
			"invalid_grant: lives too long",
		);
		expect(saidOf(await short.grant(await assertion(base)))).toBe("issued");
		const ahead = { ...base, nbf: now / 1000 + 10 };
		const tight = await own({ "clock-skew": "5s" });
		expect(saidOf(await tight.grant(await assertion(ahead)))).toBe("invalid_grant: not yet valid");
		// The section's own 30 seconds take it.
		expect(saidOf(await (await own({})).grant(await assertion(ahead)))).toBe("issued");
	});

	it("keeps a spent assertion past the widest clock skew any setting takes, whatever its issuer's", async () => {
		for (const skew of ["0s", "30s"]) {
			const s = await serve(undefined, issuer, `${issuer}/oauth/token`, [
				{ ...trustedUpstream[0], "clock-skew": skew },
			]);
			expect(errorOf(await s.grant(await assertion(base))), skew).toBe("issued");
			expect(keptFor.at(-1), skew).toBe(base.exp * 1000 + 300_000 + 60_000 - now);
		}
	});

	it("takes an issuer's assertion only where its verified claims meet the issuer's conditions", async () => {
		const { "accept-any-subject": _any, ...shared } = trustedUpstream[0] as Record<string, unknown>;
		const s = await serve(undefined, issuer, `${issuer}/oauth/token`, [
			{
				...shared,
				conditions: { "subject-prefix": "org:acme/", claims: { env: ["prod", "staging"] } },
			},
		]);
		const before = saved.length;
		const met = { ...base, sub: "org:acme/ci", env: "prod" };
		for (const claims of [
			{ ...met, sub: "org:other/ci" },
			{ ...met, env: "dev" },
			{ ...met, env: ["prod"] },
			{ ...base, sub: "org:acme/ci" },
		]) {
			expect(saidOf(await s.grant(await assertion(claims))), JSON.stringify(claims)).toBe(
				"invalid_grant: assertion does not meet its issuer's conditions",
			);
		}
		// Refused before its jti is used up, and telling no value of a claim or a condition.
		expect(saved.length).toBe(before);
		expect(errorOf(await s.grant(await assertion(met)))).toBe("issued");
		expect(errorOf(await s.grant(await assertion({ ...met, env: "staging" })))).toBe("issued");
	});

	it("issues within its issuer's ceiling as well as the client's allowance, refusing before the jti is used up", async () => {
		const under = (ceiling: Record<string, unknown>) =>
			serve(undefined, issuer, `${issuer}/oauth/token`, [{ ...trustedUpstream[0], ceiling }]);
		const before = saved.length;
		// The client's default, read, is outside a ceiling of write alone: refused, never issued empty.
		const write = await under({ scopes: ["write"] });
		expect(errorOf(await write.grant(await assertion(base)))).toBe("invalid_scope");
		expect(errorOf(await write.grant(await assertion(base), { scope: "read" }))).toBe(
			"invalid_scope",
		);
		// The audience the client is given, the issuer's for a client allowed none, is held to it too.
		const elsewhere = await under({ audiences: ["https://api.example"] });
		expect(errorOf(await elsewhere.grant(await assertion(base)))).toBe("invalid_target");
		expect(saved.length).toBe(before);
		expect(errorOf(await (await under({ scopes: ["read"] })).grant(await assertion(base)))).toBe(
			"issued",
		);
		expect(errorOf(await (await under({ audiences: [issuer] })).grant(await assertion(base)))).toBe(
			"issued",
		);
	});

	it("asks the issuance policies before the jti is used up, and again when issuing", async () => {
		const asked: IssuanceRequest[] = [];
		let refusing = new Set([1]);
		const policy = defineModule({ name: "test-policy", takes: [] }, (m) => [
			m.contribute(issuancePolicies).by(() => ({
				name: "test-policy",
				judge: async (request) => {
					asked.push(request);
					return refusing.has(asked.length)
						? { kind: "refused", reason: "test_reason", description: "refused here" }
						: { kind: "allowed" };
				},
			})),
		]);
		const s = await serve(
			undefined,
			issuer,
			`${issuer}/oauth/token`,
			trustedUpstream,
			outboundModule,
			[policy],
		);
		const signed = await assertion(base);
		expect(saidOf(await s.grant(signed))).toBe("invalid_grant: refused here");
		// Refused before it was used up, the same assertion is taken once allowed.
		expect(errorOf(await s.grant(signed))).toBe("issued");
		expect(asked.map(({ grantType: type, session }) => [type, session])).toEqual([
			[grantType, undefined],
			[grantType, undefined],
			[grantType, undefined],
		]);
		// Refused when issuing, the assertion stays used up.
		refusing = new Set([5]);
		const late = await assertion(base);
		expect(saidOf(await s.grant(late))).toBe("invalid_grant: refused here");
		expect(saidOf(await s.grant(late))).toBe("invalid_grant: assertion replayed");
	});

	it("gives no token for an assertion made before its subject's revocation, nor one that says not when once there is one", async () => {
		const s = await serve();
		const made = await assertion({ ...base, iat: now / 1000 });
		const unsaid = await assertion(base);
		await s.revoke("alice");
		clock.at = now + 2000;
		try {
			expect(saidOf(await s.grant(made))).toBe("invalid_grant: assertion revoked");
			expect(saidOf(await s.grant(unsaid))).toBe("invalid_grant: assertion revoked");
			// An issue time ahead of this clock is taken as now, which the boundary's second still covers.
			// Only `sessions` moves: the assertion answers to it.
			await s.revoke("alice", true);
			const ahead = await assertion({ ...base, iat: now / 1000 + 22 });
			expect(saidOf(await s.grant(ahead))).toBe("invalid_grant: assertion revoked");
			// Made past the boundary by more than the clock skew allowed (30s): issued.
			clock.at = now + 33_000;
			const past = { ...base, iat: now / 1000 + 33, exp: now / 1000 + 150 };
			expect(errorOf(await s.grant(await assertion(past)))).toBe("issued");
			expect(errorOf(await s.grant(await assertion({ ...base, sub: "bob" })))).toBe("issued");
			expect(errorOf(await s.grant(made))).toBe("invalid_grant");
		} finally {
			clock.at = now;
		}
	});

	it("refuses an assertion an issuer whose clock runs ahead signed just before its subject's revocation", async () => {
		const s = await serve();
		await s.revoke("alice");
		// Signed a moment before the boundary on a clock 20s ahead, which the skew allowed takes in.
		clock.at = now + 1000;
		try {
			const ahead = await assertion({ ...base, iat: now / 1000 + 20 });
			expect(saidOf(await s.grant(ahead))).toBe("invalid_grant: assertion revoked");
		} finally {
			clock.at = now;
		}
	});

	it("takes the token endpoint's own location as an audience, whatever path the issuer has", async () => {
		const tenant = `${issuer}/tenant`;
		const s = await serve(undefined, tenant);
		const ok = async (aud: string) => (await s.grant(await assertion({ ...base, aud }))).kind;
		expect(await ok(`${issuer}/oauth/token`)).toBe("issued");
		expect(await ok(tenant)).toBe("issued");
		expect(await ok(`${tenant}/oauth/token`)).toBe("error");
		expect(await serve(undefined, issuer, null).catch((error) => error)).toBeInstanceOf(
			BootRefused,
		);
	});

	it("refuses assertions from strangers, for others, expired, too long-lived or missing claims", async () => {
		const s = await serve();
		const error = async (a: string) => errorOf(await s.grant(a));
		expect(await error(await assertion(base, stranger.privateKey))).toBe("invalid_grant");
		expect(await error(await assertion({ ...base, aud: "https://elsewhere" }))).toBe(
			"invalid_grant",
		);
		expect(await error(await assertion({ ...base, exp: now / 1000 - 600 }))).toBe("invalid_grant");
		expect(await error(await assertion({ ...base, exp: now / 1000 + 86_400 }))).toBe(
			"invalid_grant",
		);
		expect(await error(await assertion({ ...base, sub: undefined }))).toBe("invalid_grant");
		expect(await error(await assertion({ ...base, sub: "" }))).toBe("invalid_grant");
		// A subject is 1 to 255 ASCII characters, as users bounds it.
		expect(await error(await assertion({ ...base, sub: "s".repeat(255) }))).toBe("issued");
		expect(await error(await assertion({ ...base, sub: "s".repeat(256) }))).toBe("invalid_grant");
		expect(await error(await assertion({ ...base, sub: "s\u00e9" }))).toBe("invalid_grant");
		expect(await error(await assertion({ ...base, iss: "https://unknown.example" }))).toBe(
			"invalid_grant",
		);
		expect(await error(await assertion({ ...base, jti: "j".repeat(257) }))).toBe("invalid_grant");
		expect(await error(await assertion({ ...base, jti: "j".repeat(256) }))).toBe("issued");
		expect(await error("not-a-jwt")).toBe("invalid_grant");
		expect(await error(await assertion({ ...base, jti: "j-\udc00" }))).toBe("invalid_grant");
		expect(await error("")).toBe("invalid_request");
	});

	it("refuses, rather than throws on, an assertion whose signed payload is no JSON", async () => {
		const signer = await testSigner("EdDSA");
		const s = await serve(undefined, issuer, `${issuer}/oauth/token`, [
			{
				issuer: "https://idp.example",
				subject: "as-is",
				"accept-any-subject": true,
				keys: [{ alg: "EdDSA", "public-key": signer.pem }],
			},
		]);
		// The same key's JSON claims are granted, so the refusal below is the payload's.
		expect(errorOf(await s.grant(await signer.sign({ ...base, jti: "j-json" })))).toBe("issued");
		const signed = await signer.signBytes(Buffer.from(`{"iss":"https://idp.example"`));
		expect(errorOf(await s.grant(signed))).toBe("invalid_grant");
	});

	it("takes the one key that fits: none or more than one is a refusal", async () => {
		const two = [
			{
				issuer: "https://idp.example",
				subject: "as-is",
				"accept-any-subject": true,
				keys: [
					{ alg: "EdDSA", "public-key": pem(stranger.publicKey, "spki") },
					{ alg: "EdDSA", "public-key": pem(upstream.publicKey, "spki") },
				],
			},
		];
		const ambiguous = await serve(undefined, issuer, `${issuer}/oauth/token`, two);
		expect(saidOf(await ambiguous.grant(await assertion(base)))).toBe(
			"invalid_grant: untrusted signer",
		);
		const s = await serve();
		// A header's `kid` takes only a key written with that `kid`.
		expect(saidOf(await s.grant(await assertion(base, undefined, { kid: "k1" })))).toBe(
			"invalid_grant: untrusted signer",
		);
		const named = [
			{
				issuer: "https://idp.example",
				subject: "as-is",
				"accept-any-subject": true,
				keys: [
					{ kid: "k0", alg: "EdDSA", "public-key": pem(stranger.publicKey, "spki") },
					{ kid: "k1", alg: "EdDSA", "public-key": pem(upstream.publicKey, "spki") },
				],
			},
		];
		const byKid = await serve(undefined, issuer, `${issuer}/oauth/token`, named);
		expect(errorOf(await byKid.grant(await assertion(base, undefined, { kid: "k1" })))).toBe(
			"issued",
		);
	});

	it("refuses an assertion issued longer ago than the longest lifetime and the allowance", async () => {
		const s = await serve();
		const at = (iat: number) => assertion({ ...base, iat });
		expect(errorOf(await s.grant(await at(now / 1000 - 3600 - 30)))).toBe("issued");
		expect(errorOf(await s.grant(await at(now / 1000 - 3600 - 31)))).toBe("invalid_grant");
	});

	it("takes an audience list holding one of its audiences, and only strings", async () => {
		const s = await serve();
		const aud = async (list: unknown[]) =>
			errorOf(await s.grant(await assertion({ ...base, aud: list })));
		expect(await aud(["https://elsewhere", issuer])).toBe("issued");
		expect(await aud([issuer, 5])).toBe("invalid_grant");
	});

	it("says why in its own words", async () => {
		const s = await serve();
		const said = async (a: string) => saidOf(await s.grant(a));
		expect(await said(await assertion(base, stranger.privateKey))).toBe(
			"invalid_grant: untrusted signer",
		);
		expect(await said(await assertion({ ...base, exp: now / 1000 - 600 }))).toBe(
			"invalid_grant: expired",
		);
		expect(await said(await assertion({ ...base, aud: "https://elsewhere" }))).toBe(
			"invalid_grant: wrong audience",
		);
		const late = now / 1000 + 600;
		expect(await said(await assertion({ ...base, nbf: late }))).toBe(
			"invalid_grant: not yet valid",
		);
		expect(await said(await assertion({ ...base, iat: late }))).toBe(
			"invalid_grant: issued in the future",
		);
		expect(await said(await assertion({ ...base, exp: now / 1000 + 86_400 }))).toBe(
			"invalid_grant: lives too long",
		);
		expect(await said(await assertion({ ...base, exp: undefined }))).toBe(
			"invalid_grant: malformed assertion",
		);
		const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
		const otherAlgorithm = await new SignJWT(base)
			.setProtectedHeader({ alg: "ES256" })
			.sign(ec.privateKey);
		// Refused before the signature is checked, as one with no key would be.
		expect(await said(otherAlgorithm)).toBe("invalid_grant: untrusted signer");
	});

	it("keeps each issuer's jti apart", async () => {
		const both = [
			...trustedUpstream,
			{
				issuer: "https://other.example",
				subject: "as-is",
				"accept-any-subject": true,
				keys: [{ alg: "EdDSA", "public-key": pem(stranger.publicKey, "spki") }],
			},
		];
		const s = await serve(undefined, issuer, `${issuer}/oauth/token`, both);
		const jti = "shared";
		expect(errorOf(await s.grant(await assertion({ ...base, jti })))).toBe("issued");
		const other = { ...base, iss: "https://other.example", jti };
		expect(errorOf(await s.grant(await assertion(other, stranger.privateKey)))).toBe("issued");
	});

	it("refuses to boot with a private key written where a public key goes", async () => {
		const secret = [
			{
				issuer: "https://idp.example",
				subject: "as-is",
				"accept-any-subject": true,
				keys: [{ alg: "EdDSA", "public-key": pem(upstream.privateKey, "pkcs8") }],
			},
		];
		expect(
			await serve(undefined, issuer, `${issuer}/oauth/token`, secret).catch((e) => e),
		).toBeInstanceOf(BootRefused);
	});

	it("refuses an assertion whose signature differs only in its last character's unused bits", async () => {
		const s = await serve();
		const signed = await assertion({ ...base, jti: "j-canonical" });
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
		// An Ed25519 signature leaves four unused bits in its last character; the lowest is one of them.
		const last = signed.at(-1) ?? "";
		const other = `${signed.slice(0, -1)}${alphabet[alphabet.indexOf(last) ^ 1]}`;
		expect(errorOf(await s.grant(other))).toBe("invalid_grant");
		expect(errorOf(await s.grant(signed))).toBe("issued");
	});

	it("refuses to boot with a key it cannot read", async () => {
		const unreadable = [
			{
				issuer: "https://idp.example",
				subject: "as-is",
				"accept-any-subject": true,
				keys: [{ alg: "EdDSA", "public-key": "not a PEM" }],
			},
		];
		expect(
			await serve(undefined, issuer, `${issuer}/oauth/token`, unreadable).catch((e) => e),
		).toBeInstanceOf(BootRefused);
	});

	describe("with a key set at a URL", () => {
		const located = `${issuer}/oauth/token`;
		const at = (uri: string, named = "https://idp.example") => [
			{ issuer: named, subject: "as-is", "accept-any-subject": true, "jwks-uri": uri },
		];
		/** An outbound answering the key set, keeping what it was asked. */
		function keySetAt(keys: unknown[]) {
			const asked: { url: string; narrower: Narrower | undefined }[] = [];
			const module = defineModule({ name: "outbound-stand-in", takes: [] }, (m) => [
				m.provide(outbound).by(() => ({
					fetch: async (url, _request, narrower) => {
						asked.push({ url, narrower });
						return {
							status: 200,
							headers: new Map(),
							body: new TextEncoder().encode(JSON.stringify({ keys })),
						};
					},
				})),
			]);
			return { module, asked };
		}

		it("checks the assertion with the issuer's key set, fetched only from the issuer's host", async () => {
			const signer = await testSigner("ES256", "k1");
			const set = keySetAt([signer.jwk]);
			const s = await serve(undefined, issuer, located, at("https://idp.example/jwks"), set.module);
			const signed = await signer.sign({ ...base, jti: "j-set" });
			expect(errorOf(await s.grant(signed))).toBe("issued");
			expect(set.asked).toEqual([
				{ url: "https://idp.example/jwks", narrower: { hosts: ["idp.example"] } },
			]);
			expect(saidOf(await s.grant(await assertion(base)))).toBe("invalid_grant: untrusted signer");
		});

		it("is unavailable while no key set can be had", async () => {
			const down = unavailableSwitch<Outbound>("outbound");
			down.unavailable("fetch");
			const out = switchedModule(keySetAt([]).module, outbound, down);
			const s = await serve(undefined, issuer, located, at("https://idp.example/jwks"), out);
			const signed = await (await testSigner("ES256")).sign(base);
			await expect(s.grant(signed)).rejects.toBeInstanceOf(Unavailable);
		});

		it("refuses to boot with both keys and a key set, neither, or a key set not at https on the issuer's host", async () => {
			const refused = (issuers: Record<string, unknown>[]) =>
				serve(undefined, issuer, located, issuers, keySetAt([]).module).then(
					() => "booted",
					(error) => (error instanceof BootRefused ? "refused" : error),
				);
			expect(await refused(at("https://idp.example/jwks"))).toBe("booted");
			expect(
				await refused([{ ...trustedUpstream[0], "jwks-uri": "https://idp.example/jwks" }]),
			).toBe("refused");
			expect(await refused([{ issuer: "https://idp.example", subject: "as-is" }])).toBe("refused");
			expect(await refused(at("https://keys.example/jwks"))).toBe("refused");
			expect(await refused(at("http://idp.example/jwks"))).toBe("refused");
			expect(await refused(at("https://sub.idp.example/jwks"))).toBe("refused");
			expect(await refused(at("https://idp.example/jwks", "idp.example"))).toBe("refused");
		});
	});
});

it("takes the lifetime cap and the clock allowance with their unit, in whole seconds, 1h and 30s unless set", () => {
	const takes = (settings: object) => jwtBearer.section?.safeParse(settings).success;
	expect(jwtBearer.section?.parse({})).toMatchObject({
		"max-assertion-lifetime": 3600,
		"clock-skew": 30,
	});
	expect([{ "max-assertion-lifetime": "1d" }, { "clock-skew": "0s" }].map(takes)).toEqual([
		true,
		true,
	]);
	const refused = [
		{ "max-assertion-lifetime": 3600 },
		{ "clock-skew": "301s" },
		{ "clock-skew": "1500ms" },
	];
	expect(refused.map(takes)).toEqual([false, false, false]);
});

describe("signers whose keys a module contributes, and subjects users links", () => {
	const device = generateKeyPairSync("ed25519");
	const other = generateKeyPairSync("ed25519");
	const fixedIss = "app.devices";
	const deviceKey = async (k = device) => ({ ...(await exportJWK(k.publicKey)), alg: "EdDSA" });
	const thumbOf = async (k = device) =>
		calculateJwkThumbprint(await exportJWK(k.publicKey), "sha256");
	type Answer = Awaited<ReturnType<SignerKeys["keysOf"]>>;
	/** A module contributing the device keys, answering as `answer` says now and recording each ask. */
	const signing = (answer: () => Promise<Answer>, asked: unknown[] = []) =>
		defineModule({ name: "device-keys", takes: [] }, (m) => [
			m.contribute(signerKeys).by(() => ({
				issuer: fixedIss,
				perSigner: true,
				keysOf: async (signer) => {
					asked.push(signer);
					return answer();
				},
			})),
		]);
	type Linked = Awaited<ReturnType<LinkedSubjects["subjectOf"]>>;
	/** A module resolving linked subjects as `answer` says now, recording each ask. */
	const resolving = (
		answer: () => Promise<Linked>,
		asked: unknown[] = [],
		name = "linked-subjects",
	) =>
		defineModule({ name, takes: [] }, (m) => [
			m.contribute(linkedSubjects).by(() => ({
				declaredBy: name,
				subjectOf: async (upstream: string, sub: string) => {
					asked.push([upstream, sub]);
					return answer();
				},
			})),
		]);

	const entry = (more: Record<string, unknown> = {}) => [{ issuer: fixedIss, ...more }];
	const otherIss = "app.phones";
	/** Keys contributed for the second issuer, answering none. */
	const otherSigning = defineModule({ name: "phone-keys", takes: [] }, (m) => [
		m
			.contribute(signerKeys)
			.by(() => ({ issuer: otherIss, perSigner: true, keysOf: async () => ({ kind: "none" }) })),
	]);
	const located = `${issuer}/oauth/token`;
	const serveWith = (issuers: Record<string, unknown>[], extra: Module[]) =>
		serve(undefined, issuer, located, issuers, outboundModule, extra);
	const deviceAssertion = async (sub: string, key = device.privateKey) =>
		assertion({ ...base, iss: fixedIss, sub }, key);

	it("takes a contributed key under the algorithms its answer and its issuer both take", async () => {
		const thumb = await thumbOf();
		const both = {
			kind: "keys",
			keys: [await deviceKey()],
			algorithms: ["EdDSA", "ES256"],
		} as const;
		const own = entry({ subject: "as-is", "subject-is-key-thumbprint": true });
		expect(
			errorOf(
				await (await serveWith(own, [signing(async () => both)])).grant(
					await deviceAssertion(thumb),
				),
			),
		).toBe("issued");
		const narrowed = entry({
			subject: "as-is",
			"subject-is-key-thumbprint": true,
			algorithms: ["ES256"],
		});
		const s = await serveWith(narrowed, [signing(async () => both)]);
		expect(saidOf(await s.grant(await deviceAssertion(thumb)))).toBe(
			"invalid_grant: untrusted signer",
		);
		// An answer naming only an algorithm there is to take but its issuer does not: no key, not an outage.
		const pss = { kind: "keys", keys: [await deviceKey()], algorithms: ["PS256"] } as const;
		const past = await serveWith(own, [signing(async () => pss)]);
		expect(saidOf(await past.grant(await deviceAssertion(thumb)))).toBe(
			"invalid_grant: untrusted signer",
		);
	});

	it("takes a contributed signer's keys asked for each assertion, never kept, and the thumbprint's own key only", async () => {
		const thumb = await thumbOf();
		let keys: Answer = {
			kind: "keys",
			keys: [await deviceKey(other), await deviceKey()],
			algorithms: ["EdDSA"],
		};
		const asked: unknown[] = [];
		const s = await serveWith(entry({ subject: "as-is", "subject-is-key-thumbprint": true }), [
			signing(async () => keys, asked),
		]);
		const issued = await s.grant(await deviceAssertion(thumb));
		expect(errorOf(issued)).toBe("issued");
		expect(asked).toEqual([{ subject: thumb }]);
		keys = { kind: "none" };
		expect(saidOf(await s.grant(await deviceAssertion(thumb)))).toBe(
			"invalid_grant: untrusted signer",
		);
		// A key whose thumbprint is not the subject never verifies for it.
		keys = { kind: "keys", keys: [await deviceKey(other)], algorithms: ["EdDSA"] };
		expect(saidOf(await s.grant(await deviceAssertion(thumb, other.privateKey)))).toBe(
			"invalid_grant: untrusted signer",
		);
	});

	/** An assertion signed over the header and claims as written, whatever they hold. */
	const rawSigned = (header: object, claims: object, key = device.privateKey) => {
		const part = (v: object) => Buffer.from(JSON.stringify(v)).toString("base64url");
		const data = `${part(header)}.${part(claims)}`;
		return `${data}.${sign(null, Buffer.from(data), key).toString("base64url")}`;
	};

	it("answers every refusal before the signature alike, whether the signer has keys or none", async () => {
		const thumb = await thumbOf();
		const held: Answer = { kind: "keys", keys: [await deviceKey()], algorithms: ["EdDSA"] };
		let keys: Answer = held;
		const s = await serveWith(entry({ subject: "as-is", "subject-is-key-thumbprint": true }), [
			signing(async () => keys),
		]);
		const claims = { ...base, iss: fixedIss, sub: thumb };
		const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
		const refused = {
			algorithm: await new SignJWT({ ...claims, jti: "j-alg" })
				.setProtectedHeader({ alg: "ES256" })
				.sign(ec.privateKey),
			header: rawSigned({ alg: "EdDSA", crit: ["x"], x: 1 }, { ...claims, jti: "j-crit" }),
			signature: rawSigned({ alg: "EdDSA" }, { ...claims, jti: "j-other" }, other.privateKey),
			// Not read as a JWT at all: two parts, a header or payload that is no JSON object.
			compact: "a.b",
			unreadHeader: `${Buffer.from("not json").toString("base64url")}.e30.AA`,
			unreadPayload: `${Buffer.from(JSON.stringify({ alg: "EdDSA" })).toString("base64url")}.${Buffer.from("[1]").toString("base64url")}.AA`,
		};
		for (const answer of [held, { kind: "none" } as const]) {
			keys = answer;
			for (const [why, a] of Object.entries(refused)) {
				expect(saidOf(await s.grant(a)), `${why}, ${answer.kind}`).toBe(
					"invalid_grant: untrusted signer",
				);
			}
		}
		// Once the signature holds, a claim's refusal keeps its words.
		keys = held;
		const { exp: _, ...lasting } = claims;
		expect(saidOf(await s.grant(await deviceAssertion(thumb)))).toBe("issued");
		expect(saidOf(await s.grant(await assertion(lasting, device.privateKey)))).toBe(
			"invalid_grant: malformed assertion",
		);
	});

	it("refuses an issuer that is no string, before asking for any key", async () => {
		const thumb = await thumbOf();
		const asked: unknown[] = [];
		const s = await serveWith(entry({ subject: "as-is" }), [
			signing(
				async () => ({ kind: "keys", keys: [await deviceKey()], algorithms: ["EdDSA"] }),
				asked,
			),
		]);
		for (const iss of [[fixedIss], 7, null]) {
			const a = await assertion({ ...base, iss, sub: thumb }, device.privateKey);
			expect(saidOf(await s.grant(a)), JSON.stringify(iss)).toBe("invalid_grant: untrusted signer");
		}
		expect(asked).toEqual([]);
		expect(saidOf(await s.grant(await deviceAssertion(thumb)))).toBe("issued");
	});

	it("asks for no keys for a subject of the wrong shape", async () => {
		const asked: unknown[] = [];
		const s = await serveWith(entry({ subject: "as-is", "subject-is-key-thumbprint": true }), [
			signing(async () => ({ kind: "none" }), asked),
		]);
		for (const sub of ["short", "s-\u00e9".padEnd(43, "x"), "a".repeat(300)]) {
			expect(saidOf(await s.grant(await deviceAssertion(sub))), sub).toBe(
				"invalid_grant: untrusted signer",
			);
		}
		expect(asked).toEqual([]);
	});

	it("asks for keys by a kid of 1 to 256 well-formed characters only, refusing any other unread", async () => {
		const thumb = await thumbOf();
		const asked: unknown[] = [];
		const s = await serveWith(entry({ subject: "as-is" }), [
			signing(async () => ({ kind: "none" }), asked),
		]);
		const signedWith = (kid: unknown) =>
			assertion({ ...base, iss: fixedIss, sub: thumb }, device.privateKey, { kid: kid as string });
		for (const kid of ["k".repeat(257), "k\uD800", 7]) {
			expect(saidOf(await s.grant(await signedWith(kid))), String(kid)).toBe(
				"invalid_grant: untrusted signer",
			);
		}
		expect(asked).toEqual([]);
		await s.grant(await signedWith("k1"));
		expect(asked).toEqual([{ subject: thumb, kid: "k1" }]);
	});

	it("takes a self-issued prefix of 1 to 64 printable ASCII characters, only beside contributed thumbprint keys", () => {
		const takes = (more: Record<string, unknown>) =>
			jwtBearer.section?.safeParse({
				issuers: entry({ subject: "as-is", "subject-is-key-thumbprint": true, ...more }),
			}).success;
		expect(takes({ "self-issued-prefix": "device:" })).toBe(true);
		expect(takes({ "self-issued-prefix": "~".repeat(64) })).toBe(true);
		for (const prefix of [
			"",
			"~".repeat(65),
			"d\u00e9vice:",
			"dev ice:",
			"dev\tice:",
			"dev\u0000",
		]) {
			expect(takes({ "self-issued-prefix": prefix }), JSON.stringify(prefix)).toBe(false);
		}
		expect(takes({ "self-issued-prefix": "device:", "subject-is-key-thumbprint": false })).toBe(
			false,
		);
		const key = [{ alg: "EdDSA", "public-key": pem(upstream.publicKey, "spki") }];
		expect(takes({ "self-issued-prefix": "device:", keys: key })).toBe(false);
	});

	it("refuses to boot on a self-issued prefix that starts an issuer or another prefix, whichever is written first, by place", async () => {
		const refusalsOf = (issuers: Record<string, unknown>[]) =>
			serveWith(issuers, [
				signing(async () => ({ kind: "none" })),
				...(issuers.length > 1 ? [otherSigning] : []),
			]).then(
				() => [],
				(error: BootRefused) => error.refusals,
			);
		const own = { subject: "as-is", "subject-is-key-thumbprint": true };
		const at = (i: number) => `jwt-bearer.issuers.${i}.self-issued-prefix`;
		// A prefix that starts an issuer: its own, or another's.
		expect(await refusalsOf(entry({ ...own, "self-issued-prefix": "app." }))).toEqual([
			{ where: at(0), reason: "starts the issuer of jwt-bearer.issuers.0" },
		]);
		const two = (a: string, b: string) => [
			{ issuer: fixedIss, ...own, "self-issued-prefix": a },
			{ issuer: otherIss, ...own, "self-issued-prefix": b },
		];
		for (const [a, b] of [
			["device:", "device:x"],
			["device:x", "device:"],
			["device:", "device:"],
		] as const) {
			expect(await refusalsOf(two(a, b)), `${a} ${b}`).toEqual([
				{ where: at(0), reason: "overlaps the self-issued prefix of jwt-bearer.issuers.1" },
				{ where: at(1), reason: "overlaps the self-issued prefix of jwt-bearer.issuers.0" },
			]);
		}
		expect(await refusalsOf(two("device:", "phone:"))).toEqual([]);
	});

	it("tells at boot which issuers take self-issued signers, by place and never by prefix", async () => {
		const logged = recordingLog();
		const issuers = [
			{ issuer: fixedIss, subject: "as-is", "subject-is-key-thumbprint": true },
			{
				issuer: otherIss,
				subject: "as-is",
				"subject-is-key-thumbprint": true,
				"self-issued-prefix": "device:",
			},
		];
		const given = assembly(undefined, issuer, located, issuers, outboundModule, [
			signing(async () => ({ kind: "none" })),
			otherSigning,
		]);
		await assemble({
			...given,
			runtime: quietRuntime({ clock: { now: () => clock.at }, log: logged.log }),
		});
		const told = logged.lines().filter((l) => l.event === "jwt-bearer.self_issued_signers");
		expect(told).toEqual([
			{
				level: "info",
				event: "jwt-bearer.self_issued_signers",
				fields: { at: "jwt-bearer.issuers.1" },
			},
		]);
		expect(JSON.stringify(logged.lines())).not.toContain("device:");
	});

	it("refuses to boot on an issuer named twice, and on keys contributed for an issuer it does not name, by path and never by value", async () => {
		const refusalsOf = (issuers: Record<string, unknown>[]) =>
			serveWith(issuers, [signing(async () => ({ kind: "none" }))]).then(
				() => [],
				(error: BootRefused) => error.refusals,
			);
		const twice = await refusalsOf([
			...entry({ subject: "as-is" }),
			...entry({ subject: "as-is" }),
		]);
		expect(twice).toEqual([
			{ where: "jwt-bearer.issuers.1", reason: "names the same issuer as jwt-bearer.issuers.0" },
		]);
		const unnamed = await refusalsOf([]);
		expect(unnamed).toEqual([
			{
				where: "jwt-bearer.issuers",
				reason:
					"keys are contributed for 1 issuer none of these names: name it here, or leave out the module that contributes them",
			},
		]);
		const keyless = await serveWith(entry({ subject: "as-is" }), []).then(
			() => [],
			(error: BootRefused) => error.refusals,
		);
		expect(keyless).toEqual([
			{ where: "jwt-bearer.issuers.0", reason: "has no keys written or contributed" },
		]);
		expect(JSON.stringify([twice, unnamed, keyless])).not.toContain(fixedIss);
	});

	it("tells an unknown key and a forged signature alike", async () => {
		const thumb = await thumbOf();
		let keys: Answer = { kind: "none" };
		const s = await serveWith(entry({ subject: "as-is" }), [signing(async () => keys)]);
		const unknown = await s.grant(await deviceAssertion(thumb));
		keys = { kind: "keys", keys: [await deviceKey()], algorithms: ["EdDSA"] };
		const forged = await s.grant(await deviceAssertion(thumb, other.privateKey));
		expect(forged).toEqual(unknown);
	});

	it("is unavailable, using up no jti, where the keys cannot be told or answer an algorithm the grant does not take", async () => {
		const thumb = await thumbOf();
		const signed = await deviceAssertion(thumb);
		let answer = async (): Promise<Answer> => {
			throw new Unavailable("device-keys");
		};
		const s = await serveWith(entry({ subject: "as-is" }), [signing(() => answer())]);
		await expect(s.grant(signed)).rejects.toBeInstanceOf(Unavailable);
		answer = async () => ({
			kind: "keys",
			keys: [await deviceKey()],
			algorithms: ["HS256" as "EdDSA"],
		});
		await expect(s.grant(signed)).rejects.toBeInstanceOf(Unavailable);
		answer = async () => ({ kind: "keys", keys: [await deviceKey()], algorithms: ["EdDSA"] });
		expect(errorOf(await s.grant(signed))).toBe("issued");
	});

	it("issues for the subject a linked signer stands for, refusing one none stands for without using up the jti", async () => {
		const thumb = await thumbOf();
		const keys = async (): Promise<Answer> => ({
			kind: "keys",
			keys: [await deviceKey()],
			algorithms: ["EdDSA"],
		});
		let found: Linked = { kind: "none" };
		let down = false;
		const asked: unknown[] = [];
		const s = await serveWith(entry({ subject: "linked", upstream: "device" }), [
			signing(keys),
			resolving(async () => {
				if (down) throw new Unavailable("ledger");
				return found;
			}, asked),
		]);
		const signed = await deviceAssertion(thumb);
		expect(saidOf(await s.grant(signed))).toBe("invalid_grant: unknown subject");
		down = true;
		await expect(s.grant(signed)).rejects.toBeInstanceOf(Unavailable);
		down = false;
		found = { kind: "subject", subject: "account-7" };
		const issued = await s.grant(signed);
		const token = issued.kind === "issued" ? String(issued.body.access_token) : "";
		const verified = await s.verify(token);
		expect(verified.kind === "valid" && verified.grant.subject).toBe("account-7");
		expect(asked).toEqual([
			["device", thumb],
			["device", thumb],
			["device", thumb],
		]);
	});

	describe("self-issued signers", () => {
		const prefix = "device:";
		const own = { "subject-is-key-thumbprint": true, "self-issued-prefix": prefix };
		/** The signer's key as a ledger answers it, under the `kid` its assertions name: its thumbprint. */
		const held = async (k = device): Promise<Answer> => ({
			kind: "keys",
			keys: [{ ...(await deviceKey(k)), kid: await thumbOf(k) }],
			algorithms: ["EdDSA"],
		});
		/** An assertion as a self-issued signer makes it: `iss` and `sub` its own name, `kid` its thumbprint. */
		const selfIssued = async (
			name: string,
			more: Record<string, unknown> = {},
			key = device.privateKey,
			kid?: string,
		) =>
			assertion(
				{ ...base, iss: name, sub: name, iat: now / 1000, exp: now / 1000 + 120, ...more },
				key,
				{ kid: kid ?? name.slice(prefix.length) },
			);
		const subjectOfIssued = async (s: Awaited<ReturnType<typeof serve>>, outcome: GrantOutcome) => {
			const token = outcome.kind === "issued" ? String(outcome.body.access_token) : "";
			const verified = await s.verify(token);
			return verified.kind === "valid" ? verified.grant.subject : verified.reason;
		};

		it("takes a self-issued signer as its issuer's, asking its keys by its thumbprint, the subject that thumbprint", async () => {
			const thumb = await thumbOf();
			const asked: unknown[] = [];
			const s = await serveWith(entry({ subject: "as-is", ...own }), [
				signing(() => held(), asked),
			]);
			const issued = await s.grant(await selfIssued(prefix + thumb));
			expect(errorOf(issued)).toBe("issued");
			expect(asked).toEqual([{ subject: thumb, kid: thumb }]);
			expect(await subjectOfIssued(s, issued)).toBe(thumb);
			// The same key under the issuer's own `iss` stands for the same subject.
			expect(await subjectOfIssued(s, await s.grant(await deviceAssertion(thumb)))).toBe(thumb);
		});

		it("reads only the prefix as written and a thumbprint's 43 characters, asking no key for any other", async () => {
			const thumb = await thumbOf();
			const asked: unknown[] = [];
			const s = await serveWith(entry({ subject: "as-is", ...own }), [
				signing(() => held(), asked),
			]);
			const last = thumb.at(-1) ?? "A";
			const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
			const unused = alphabet[(alphabet.indexOf(last) + 1) % 64] ?? "A";
			const unread = [
				`Device:${thumb}`,
				`device\uff1a${thumb}`,
				`${prefix}${thumb}=`,
				`${prefix}${thumb.slice(0, 42)}`,
				`${prefix}${thumb}A`,
				`${prefix}${thumb.slice(0, 42)}+`,
			];
			for (const name of unread) {
				expect(saidOf(await s.grant(await selfIssued(name))), name).toBe(
					"invalid_grant: untrusted signer",
				);
			}
			expect(asked).toEqual([]);
			// One differing only in its last character's unused bits is asked for, and no key's own:
			// under the key's own kid, so only the thumbprint computed from the key refuses it.
			const near = `${prefix}${thumb.slice(0, 42)}${unused}`;
			expect(saidOf(await s.grant(await selfIssued(near, {}, device.privateKey, thumb)))).toBe(
				"invalid_grant: untrusted signer",
			);
		});

		it("takes a self-issued signer only where its sub is its iss, and its own key only", async () => {
			const thumb = await thumbOf();
			const s = await serveWith(entry({ subject: "as-is", ...own }), [signing(() => held())]);
			const name = prefix + thumb;
			for (const sub of [thumb, prefix + (await thumbOf(other))]) {
				expect(saidOf(await s.grant(await selfIssued(name, { sub }))), sub).toBe(
					"invalid_grant: untrusted signer",
				);
			}
			// Another signer's name, signed with this key under its own kid: only the thumbprint
			// computed from the key, which is not the one the name holds, refuses it.
			const otherName = prefix + (await thumbOf(other));
			expect(saidOf(await s.grant(await selfIssued(otherName, {}, device.privateKey, thumb)))).toBe(
				"invalid_grant: untrusted signer",
			);
		});

		it("stands a linked self-issued signer for the account its thumbprint links, revoked at that account's boundary", async () => {
			const thumb = await thumbOf();
			const asked: unknown[] = [];
			let found: Linked = { kind: "none" };
			const s = await serveWith(entry({ subject: "linked", upstream: "device", ...own }), [
				signing(() => held()),
				resolving(async () => found, asked),
			]);
			expect(saidOf(await s.grant(await selfIssued(prefix + thumb)))).toBe(
				"invalid_grant: unknown subject",
			);
			found = { kind: "subject", subject: "account-7" };
			expect(await subjectOfIssued(s, await s.grant(await selfIssued(prefix + thumb)))).toBe(
				"account-7",
			);
			expect(asked).toEqual([
				["device", thumb],
				["device", thumb],
			]);
			await s.revoke("account-7");
			expect(saidOf(await s.grant(await selfIssued(prefix + thumb)))).toBe(
				"invalid_grant: assertion revoked",
			);
		});

		it("uses a self-issued assertion up once, apart from the issuer's own iss with the same jti", async () => {
			const thumb = await thumbOf();
			const s = await serveWith(entry({ subject: "as-is", ...own }), [signing(() => held())]);
			const once = await selfIssued(prefix + thumb, { jti: "j-1" });
			const [a, b] = await Promise.all([s.grant(once), s.grant(once)]);
			expect([errorOf(a), errorOf(b)].sort()).toEqual(["invalid_grant", "issued"]);
			expect(saidOf(await s.grant(once))).toBe("invalid_grant: assertion replayed");
			const fixed = await assertion(
				{ ...base, iss: fixedIss, sub: thumb, jti: "j-1" },
				device.privateKey,
			);
			expect(errorOf(await s.grant(fixed))).toBe("issued");
		});

		it("holds a self-issued assertion to the audience, times and lifetime as any other", async () => {
			const thumb = await thumbOf();
			const s = await serveWith(entry({ subject: "as-is", ...own }), [signing(() => held())]);
			const name = prefix + thumb;
			expect(saidOf(await s.grant(await selfIssued(name, { aud: "https://elsewhere" })))).toBe(
				"invalid_grant: wrong audience",
			);
			expect(saidOf(await s.grant(await selfIssued(name, { exp: now / 1000 - 600 })))).toBe(
				"invalid_grant: expired",
			);
			expect(saidOf(await s.grant(await selfIssued(name, { exp: now / 1000 + 86_400 })))).toBe(
				"invalid_grant: lives too long",
			);
		});
	});

	it("refuses to boot on an issuer that does not say how its subject is read, naming the key", async () => {
		const unsaid = await serveWith(entry(), [signing(async () => ({ kind: "none" }))]).catch(
			(error) => error,
		);
		expect(unsaid).toBeInstanceOf(BootRefused);
		expect((unsaid as BootRefused).refusals.map((r) => r.where)).toEqual([
			"jwt-bearer.issuers.0.subject",
		]);
	});

	it("refuses to boot on keys both written and contributed, neither, an upstream with as-is, none with linked, linked with no resolver, or two resolvers", async () => {
		const refused = async (issuers: Record<string, unknown>[], extra: Module[] = []) =>
			serveWith(issuers, extra).then(
				() => "booted",
				(error) => (error instanceof BootRefused ? "refused" : error),
			);
		const contributed = signing(async () => ({ kind: "none" }));
		expect(await refused(entry({ subject: "as-is" }), [contributed])).toBe("booted");
		expect(await refused(entry({ subject: "as-is" }))).toBe("refused");
		const written = [{ ...trustedUpstream[0], issuer: fixedIss, subject: "as-is" }];
		expect(await refused(written, [contributed])).toBe("refused");
		expect(await refused(entry({ subject: "as-is", upstream: "device" }), [contributed])).toBe(
			"refused",
		);
		expect(await refused(entry({ subject: "linked" }), [contributed])).toBe("refused");
		const linkedEntry = entry({ subject: "linked", upstream: "device" });
		expect(await refused(linkedEntry, [contributed])).toBe("refused");
		const resolver = resolving(async () => ({ kind: "none" }));
		expect(await refused(linkedEntry, [contributed, resolver])).toBe("booted");
		const second = resolving(async () => ({ kind: "none" }), [], "another");
		expect(await refused(linkedEntry, [contributed, resolver, second])).toBe("refused");
		// A key set fetched here cannot tell which of its keys signed.
		const fetched = {
			issuer: "https://idp.example",
			subject: "as-is",
			"jwks-uri": "https://idp.example/jwks",
		};
		expect(await refused([{ ...fetched, "subject-is-key-thumbprint": true }])).toBe("refused");
	});
});

describe("assertions used up in a ledger a module contributes for their issuer", () => {
	type Spend = Parameters<JtiLedger["spend"]>[0];
	/** A module contributing `issuer`'s ledger, answering as `answer` says now and recording each spend. */
	const ledgerOf = (
		answer: (spend: Spend) => Promise<unknown>,
		spends: Spend[] = [],
		forIssuer = "https://idp.example",
		name = "jti-ledger",
	) =>
		defineModule({ name, takes: [] }, (m) => [
			m.contribute(jtiLedgers).by(() => ({
				issuer: forIssuer,
				spend: async (spend: Spend) => {
					spends.push(spend);
					return (await answer(spend)) as "first" | "replayed";
				},
			})),
		]);
	/** A ledger keeping what it was told in memory: first once per jti, then replayed. */
	const kept = () => {
		const used = new Set<string>();
		return async ({ jti }: Spend) => {
			if (used.has(jti)) return "replayed";
			used.add(jti);
			return "first";
		};
	};
	const other = {
		issuer: "https://other.example",
		subject: "as-is",
		"accept-any-subject": true,
		keys: [{ alg: "EdDSA", "public-key": pem(stranger.publicKey, "spki") }],
	};
	const located = `${issuer}/oauth/token`;
	const serveWith = (
		extra: Module[],
		issuers: readonly Record<string, unknown>[] = trustedUpstream,
	) => serve(undefined, issuer, located, issuers, outboundModule, extra);

	it("spends an issuer's jti in its ledger alone, as sent, the store kept for an issuer with none", async () => {
		const spends: Spend[] = [];
		const s = await serveWith([ledgerOf(kept(), spends)], [...trustedUpstream, other]);
		const before = saved.length;
		const signed = await assertion({ ...base, jti: "j-ledger" });
		expect(errorOf(await s.grant(signed))).toBe("issued");
		expect(saidOf(await s.grant(signed))).toBe("invalid_grant: assertion replayed");
		expect(spends).toEqual([
			{
				sentIssuer: "https://idp.example",
				jti: "j-ledger",
				expiresAt: base.exp * 1000,
				keepUntil: base.exp * 1000 + 300_000 + 60_000,
			},
			expect.objectContaining({ jti: "j-ledger" }),
		]);
		expect(saved.length).toBe(before);
		// The other issuer has no ledger: its jti goes to the store as ever.
		const theirs = await assertion(
			{ ...base, iss: "https://other.example", jti: "j-store" },
			stranger.privateKey,
		);
		expect(errorOf(await s.grant(theirs))).toBe("issued");
		expect(saved.length).toBe(before + 1);
		expect(spends).toHaveLength(2);
	});

	it("asks no ledger for an assertion refused before its jti would be used up, or whose jti is malformed", async () => {
		const spends: Spend[] = [];
		const s = await serveWith([ledgerOf(kept(), spends), narrowing]);
		expect(
			errorOf(await s.grant(await assertion(base), { resource: "https://elsewhere.example" })),
		).toBe("invalid_target");
		await s.revoke("alice");
		expect(saidOf(await s.grant(await assertion({ ...base, iat: now / 1000 - 1 })))).toBe(
			"invalid_grant: assertion revoked",
		);
		expect(spends).toEqual([]);
		// On a grant whose subject is not revoked, so the jti's shape alone refuses it.
		const fresh = await serveWith([ledgerOf(kept(), spends)]);
		for (const jti of [undefined, "", "j".repeat(257), "lone-\ud800"]) {
			const signed = await new SignJWT({ ...base, ...(jti === undefined ? {} : { jti }) })
				.setProtectedHeader({ alg: "EdDSA" })
				.sign(upstream.privateKey);
			expect(saidOf(await fresh.grant(signed)), String(jti)).toBe(
				"invalid_grant: missing or malformed claims",
			);
		}
		expect(errorOf(await fresh.grant(await assertion(base)))).toBe("issued");
		expect(spends).toHaveLength(1);
	});

	it("is unavailable, issuing nothing and writing no store, where the ledger cannot tell or answers in another shape", async () => {
		let answer = async (): Promise<unknown> => {
			throw new Unavailable("jti-ledger");
		};
		const s = await serveWith([ledgerOf(() => answer())]);
		const before = saved.length;
		const signed = await assertion(base);
		for (const told of [
			async () => {
				throw new Unavailable("jti-ledger");
			},
			async () => {
				throw new Error("ledger said token=abc");
			},
			async () => undefined,
			async () => "ok",
			async () => ({ kind: "first" }),
		]) {
			answer = told;
			await expect(s.grant(signed)).rejects.toBeInstanceOf(Unavailable);
		}
		expect(saved.length).toBe(before);
		answer = async () => "first";
		expect(errorOf(await s.grant(signed))).toBe("issued");
	});

	it("leaves an assertion whose ledger answer was lost used up, and gives one token of two at once", async () => {
		const record = kept();
		let lose = true;
		const s = await serveWith([
			ledgerOf(async (spend) => {
				const told = await record(spend);
				if (lose) {
					lose = false;
					throw new Unavailable("jti-ledger");
				}
				return told;
			}),
		]);
		const signed = await assertion(base);
		await expect(s.grant(signed)).rejects.toBeInstanceOf(Unavailable);
		expect(saidOf(await s.grant(signed))).toBe("invalid_grant: assertion replayed");
		const twin = await assertion(base);
		const both = await Promise.all([s.grant(twin), s.grant(twin)]);
		expect(both.map(errorOf).sort()).toEqual(["invalid_grant", "issued"]);
	});

	it("refuses to boot on a ledger for an issuer it does not name, and on two ledgers for one issuer", async () => {
		const refusalsOf = (extra: Module[]) =>
			serveWith(extra).then(
				() => [],
				(error: BootRefused) => error.refusals,
			);
		expect(await refusalsOf([ledgerOf(kept(), [], "https://nowhere.example")])).toEqual([
			{
				where: "jwt-bearer.issuers",
				reason:
					"jti ledgers are contributed for 1 issuer none of these names: name it here, or leave out the module that contributes them",
			},
		]);
		const twice = await refusalsOf([
			ledgerOf(kept(), [], "https://idp.example", "one-ledger"),
			ledgerOf(kept(), [], "https://idp.example", "two-ledger"),
		]);
		expect(twice.map((r) => r.where)).toEqual(["jwt-bearer.jti-ledgers:https://idp.example"]);
	});

	it("takes an assertion until a second before its exp, one made with the longest exp it takes, and none after", async () => {
		// L = max-assertion-lifetime (1h), S = clock-skew (30s): signed at t with exp t + L + S, it is
		// taken until a second before that exp, never past it. The ledger's cutover waits (L + 2S + clock
		// differences) stay a bound above it.
		const s = await serveWith([ledgerOf(kept())]);
		const t = clock.at;
		const exp = (t + 3_600_000 + 30_000) / 1000;
		const signedAt = (jti: string) => assertion({ ...base, exp, jti });
		try {
			expect(errorOf(await s.grant(await signedAt("j-at-t")))).toBe("issued");
			clock.at = t + 3_600_000 + 30_000 - 1000;
			expect(errorOf(await s.grant(await signedAt("j-last")))).toBe("issued");
			clock.at = t + 3_600_000 + 30_000 - 999;
			expect(saidOf(await s.grant(await signedAt("j-after")))).toBe("invalid_grant: expired");
		} finally {
			clock.at = t;
		}
	});
});

it("takes all it names", async () => {
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused(assembly()))["jwt-bearer"]).toBeUndefined();
});
