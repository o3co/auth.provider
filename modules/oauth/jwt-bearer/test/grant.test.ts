import { generateKeyPairSync, type KeyObject } from "node:crypto";
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
import { quietRuntime, switchedModule, unavailableSwitch } from "@mod/kernel/testing";
import { type Narrower, type Outbound, outbound } from "@mod/outbound";
import outboundModule from "@mod/outbound/module";
import { memoryRecords } from "@mod/records/testing";
import storeModule from "@mod/store/module";
import { storeConfig } from "@mod/store/testing";
import { revocations } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { tokenEndpointLocation } from "@mod/token-endpoint";
import { grantCaller, grantCalls } from "@mod/token-endpoint/testing";
import { type IssuanceRequest, issuancePolicies, tokens } from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { calculateJwkThumbprint, exportJWK, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import {
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
		keys: [{ alg: "EdDSA", "public-key": pem(upstream.publicKey, "spki") }],
	},
];

/** Spent assertions on records' stand-in, whose own clock runs `aheadMs` past the kernel's. */
const spentOn = (aheadMs = 0) =>
	defineModule({ name: "spent-assertions" }, (m) => [
		m.provide(spentAssertions).by(() => {
			const stand = memoryRecords<true>(() => clock.at + aheadMs, { shards: 1, perShard: 1 });
			return {
				save: (name: string, lifetimeMs: number) => stand.records.create(name, true, lifetimeMs),
			};
		}),
	]);

/** Where the token endpoint answers; null for a deployment without a public origin. */
async function serve(
	storeAheadMs = 0,
	named = issuer,
	located: string | null = `${issuer}/oauth/token`,
	issuers: readonly Record<string, unknown>[] = trustedUpstream,
	out: Module = outboundModule,
	extra: readonly Module[] = [],
) {
	const location = defineModule({ name: "token-endpoint-location" }, (m) => [
		m.provide(tokenEndpointLocation).by(() => ({ url: located ?? undefined })),
	]);
	const app = await assemble({
		modules: [
			location,
			http,
			tokensStandIn(),
			issuerModule,
			clientsModule,
			grantCaller,
			clientAllowanceModule,
			out,
			externalJwtModule,
			storeModule,
			subjectRevocationStandIn,
			jwtBearer,
			spentOn(storeAheadMs),
			...extra,
		],
		config: {
			...kernelConfig(),
			...httpConfig(),
			...issuerConfig({ url: named }),
			...storeConfig(),
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
	});
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
const narrowing = defineModule({ name: "narrowing" }, (m) => [
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

	it("asks the issuance policies before the jti is used up, and again when issuing", async () => {
		const asked: IssuanceRequest[] = [];
		let refusing = new Set([1]);
		const policy = defineModule({ name: "test-policy" }, (m) => [
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
			clock.at = now + 3000;
			expect(errorOf(await s.grant(await assertion({ ...base, iat: now / 1000 + 3 })))).toBe(
				"issued",
			);
			expect(errorOf(await s.grant(await assertion({ ...base, sub: "bob" })))).toBe("issued");
			expect(errorOf(await s.grant(made))).toBe("invalid_grant");
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
		expect(await said(otherAlgorithm)).toBe("invalid_grant: algorithm not taken");
	});

	it("keeps each issuer's jti apart", async () => {
		const both = [
			...trustedUpstream,
			{
				issuer: "https://other.example",
				subject: "as-is",
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
			{ issuer: named, subject: "as-is", "jwks-uri": uri },
		];
		/** An outbound answering the key set, keeping what it was asked. */
		function keySetAt(keys: unknown[]) {
			const asked: { url: string; narrower: Narrower | undefined }[] = [];
			const module = defineModule({ name: "outbound-stand-in" }, (m) => [
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
		defineModule({ name: "device-keys" }, (m) => [
			m.contribute(signerKeys).by(() => ({
				issuer: fixedIss,
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
		defineModule({ name }, (m) => [
			m.contribute(linkedSubjects).by(() => ({
				declaredBy: name,
				subjectOf: async (upstream: string, sub: string) => {
					asked.push([upstream, sub]);
					return answer();
				},
			})),
		]);

	const entry = (more: Record<string, unknown> = {}) => [{ issuer: fixedIss, ...more }];
	const located = `${issuer}/oauth/token`;
	const serveWith = (issuers: Record<string, unknown>[], extra: Module[]) =>
		serve(undefined, issuer, located, issuers, outboundModule, extra);
	const deviceAssertion = async (sub: string, key = device.privateKey) =>
		assertion({ ...base, iss: fixedIss, sub }, key);

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

	it("asks for no keys for a subject of the wrong shape", async () => {
		const asked: unknown[] = [];
		const s = await serveWith(entry({ subject: "as-is", "subject-is-key-thumbprint": true }), [
			signing(async () => ({ kind: "none" }), asked),
		]);
		for (const sub of ["short", "s-\u00e9".padEnd(43, "x"), "a".repeat(300)]) {
			expect(errorOf(await s.grant(await deviceAssertion(sub))), sub).toBe("invalid_grant");
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
				"invalid_grant: malformed assertion",
			);
		}
		expect(asked).toEqual([]);
		await s.grant(await signedWith("k1"));
		expect(asked).toEqual([{ subject: thumb, kid: "k1" }]);
	});

	it("refuses to boot on an issuer named twice, and on keys contributed for an issuer it does not name", async () => {
		const reasonsOf = (issuers: Record<string, unknown>[]) =>
			serveWith(issuers, [signing(async () => ({ kind: "none" }))]).then(
				() => [],
				(error: BootRefused) => error.refusals.map((r) => r.reason),
			);
		expect(
			await reasonsOf([...entry({ subject: "as-is" }), ...entry({ subject: "as-is" })]),
		).toEqual([expect.stringContaining(`${fixedIss} is named more than once`)]);
		expect(await reasonsOf([])).toEqual([
			expect.stringContaining(`${fixedIss} has keys contributed but is not an issuer here`),
		]);
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
