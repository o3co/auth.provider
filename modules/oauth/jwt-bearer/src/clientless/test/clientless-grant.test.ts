import { generateKeyPairSync, type KeyObject } from "node:crypto";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import { authMethods, clients } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import { clientsConfig, confidentialClient, publicClient } from "@mod/clients/testing";
import externalJwtModule from "@mod/external-jwt/module";
import { type Grant, type GrantOutcome, grants } from "@mod/grants";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, contract, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import outboundModule from "@mod/outbound/module";
import { memoryRecords } from "@mod/records/testing";
import secretHashModule from "@mod/secret-hash/module";
import { simulatedStore } from "@mod/store/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { tlsOptionsForTests } from "@mod/tls-options/testing";
import { tokenEndpointLocation } from "@mod/token-endpoint";
import { grantCaller, grantCalls, grantInput } from "@mod/token-endpoint/testing";
import { tokens } from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { calculateJwkThumbprint, exportJWK, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import {
	type DelegatedAssertions,
	delegatedAssertions,
	jtiLedgers,
	linkedSubjects,
	type SignerKeys,
	signerKeys,
	spentAssertions,
} from "../../contract.ts";
import jwtBearer from "../../module.ts";
import { memoryJtiLedger } from "../../testing.ts";

const now = 1_800_000_000_000;
const runtime = quietRuntime({
	clock: { now: () => now },
	random: { bytes: (n) => new Uint8Array(n).fill(3) },
});
const issuer = "https://as.example";
const grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const pem = (k: KeyObject) => k.export({ format: "pem", type: "spki" }).toString();
const sharedKey = generateKeyPairSync("ed25519");
const ownKey = generateKeyPairSync("ed25519");
const stranger = generateKeyPairSync("ed25519");
const device = generateKeyPairSync("ed25519");

const shared = "https://shared.example";
const own = "https://own.example";
const devices = "app.devices";
const delegatedIss = "https://delegated.example";
const unidentified = { kind: "error", error: "invalid_grant", description: "untrusted signer" };

/** An issuer two organisations share, whose `client` takes a request naming none for one of them. */
const sharedEntry = {
	issuer: shared,
	subject: "as-is",
	keys: [{ alg: "EdDSA", "public-key": pem(sharedKey.publicKey) }],
	conditions: { "subject-prefix": "org:acme/" },
	client: "agents",
};
const ownEntry = {
	issuer: own,
	subject: "as-is",
	keys: [{ alg: "EdDSA", "public-key": pem(ownKey.publicKey) }],
	"accept-any-subject": true,
};
/** A linked issuer whose signers' keys a module contributes, its subjects those users links. */
const devicesEntry = { issuer: devices, subject: "linked", upstream: "device", client: "phones" };

const jwtOnly = allowancesFor({
	grants: [grantType],
	scopes: ["read", "write"],
	"default-scopes": ["read"],
});
const registered = [
	publicClient({ id: "agents", sections: jwtOnly }),
	publicClient({ id: "phones", sections: jwtOnly }),
	confidentialClient({ id: "app", sections: jwtOnly }),
];

/** What each fake was asked: keys, linked subjects, a delegate's checks and spends, the store's saves. */
interface Asked {
	keys: unknown[];
	linked: unknown[];
	checks: string[];
	spends: string[];
	saved: string[];
}

const deviceKey = async () => ({ ...(await exportJWK(device.publicKey)), alg: "EdDSA" });
const thumb = async () => calculateJwkThumbprint(await exportJWK(device.publicKey), "sha256");

/** The fakes around the grant: device keys, linked subjects, a delegate, and the store. */
function fakes(asked: Asked, linkedTo: string | undefined) {
	return [
		defineModule({ name: "device-keys", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(signerKeys).by(
				(): SignerKeys => ({
					issuer: devices,
					perSigner: true,
					keysOf: async (signer) => {
						asked.keys.push(signer);
						return { kind: "keys", keys: [await deviceKey()], algorithms: ["EdDSA"] };
					},
				}),
			),
		]),
		defineModule({ name: "linked-subjects", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(linkedSubjects).by(() => ({
				declaredBy: "linked-subjects",
				subjectOf: async (upstream: string, sub: string) => {
					asked.linked.push([upstream, sub]);
					return linkedTo === undefined ? { kind: "none" } : { kind: "subject", subject: linkedTo };
				},
			})),
		]),
		defineModule({ name: "delegate", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(delegatedAssertions).by(
				(): DelegatedAssertions => ({
					declaredBy: "delegate",
					issuers: [delegatedIss],
					check: async (a) => {
						asked.checks.push(a);
						return {
							kind: "valid",
							subject: "alice",
							issuedAt: now,
							expiresAt: now + 120_000,
							clients: ["agents"],
						};
					},
					spend: async (a) => {
						asked.spends.push(a);
						return "spent";
					},
				}),
			),
		]),
		defineModule({ name: "spent-assertions", replicaSafe: false, takes: [] }, (m) => [
			m.provide(spentAssertions).by(() => {
				const stand = memoryRecords<true>(() => now, { shards: 1, perShard: 1 });
				return {
					save: (name: string, lifetimeMs: number) => {
						asked.saved.push(name);
						return stand.records.create(name, true, lifetimeMs);
					},
				};
			}),
		]),
	];
}

/** The grant as composed, for calling its `identify` as the token endpoint does. */
const grantOf = contract<Grant>("test.jwt-bearer-grant");
const exposing = defineModule({ name: "test-grant", replicaSafe: true, takes: [grants] }, (m) => [
	m.provide(grantOf).by(async (c) => {
		const found = (await c.collect(grants)).find((g) => g.grantType === grantType);
		if (!found) throw new Error("no jwt-bearer grant");
		return found;
	}),
]);

async function serve(
	issuers: readonly Record<string, unknown>[] = [sharedEntry, ownEntry, devicesEntry],
	options: {
		/** The registered clients, in place of the three every test takes. */
		registered?: readonly ReturnType<typeof publicClient>[];
		linkedTo?: string | undefined;
		extra?: readonly Module[];
		log?: ReturnType<typeof recordingLog>;
	} = {},
) {
	const asked: Asked = { keys: [], linked: [], checks: [], spends: [], saved: [] };
	const location = defineModule(
		{ name: "token-endpoint-location", replicaSafe: true, takes: [] },
		(m) => [m.provide(tokenEndpointLocation).by(() => ({ url: `${issuer}/oauth/token` }))],
	);
	const app = await assemble({
		modules: [
			location,
			http,
			tokensStandIn(),
			issuerModule,
			clientsModule,
			secretHashModule,
			grantCaller,
			clientAllowanceModule,
			outboundModule,
			tlsOptionsForTests,
			externalJwtModule,
			simulatedStore().module,
			subjectRevocationStandIn,
			jwtBearer,
			exposing,
			...fakes(asked, "linkedTo" in options ? options.linkedTo : "account-7"),
			...(options.extra ?? []),
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": new URL(issuer).origin }),
			...issuerConfig({ url: issuer }),
			...clientsConfig(options.registered ?? registered),
			"jwt-bearer": { issuers, "delegated-issuers": [delegatedIss] },
		},
		runtime: options.log ? { ...runtime, log: options.log.log } : runtime,
	});
	const grant = app.get(grantOf);
	const anyClient = await (await app.get(clients)).find("agents");
	if (!anyClient) throw new Error("no client");
	/** The grant's `identify`, asked as the endpoint asks it of a request naming no client. */
	const identify = async (assertion: string, more: Record<string, string> = {}) => {
		const input = grantInput(app.get(tokens), grant, anyClient, {
			grant_type: grantType,
			assertion,
			...more,
		});
		return grant.identify?.({ request: input.request, param: input.param, value: input.value });
	};
	/** The grant's `handle` for this client, handed back what `identify` found where it found any. */
	const handle = (assertion: string, client: string, identified?: unknown, more = {}) =>
		app
			.get(grantCalls)
			.call(grantType, client, { grant_type: grantType, assertion, ...more }, { identified });
	/** A request naming no client: identified, then handled for the client identified. */
	const clientless = async (assertion: string, more: Record<string, string> = {}) => {
		const told = await identify(assertion, more);
		if (told?.kind !== "client") return told;
		return handle(assertion, told.client, told.identified, more);
	};
	const verify = (token: string) => app.get(tokens).verifyAccess(token);
	return { grant, identify, handle, clientless, verify, asked };
}

const sign = (claims: Record<string, unknown>, key: KeyObject, kid?: string) =>
	new SignJWT({ jti: `j-${Math.random()}`, aud: issuer, exp: now / 1000 + 120, ...claims })
		.setProtectedHeader({ alg: "EdDSA", ...(kid ? { kid } : {}) })
		.sign(key);
const ofShared = (more: Record<string, unknown> = {}, key = sharedKey.privateKey) =>
	sign({ iss: shared, sub: "org:acme/ci", ...more }, key);

const said = (outcome: GrantOutcome | undefined) =>
	outcome === undefined
		? "no identify"
		: outcome.kind === "error"
			? `${outcome.error}: ${outcome.description}`
			: outcome.kind;
const tokenOf = async (s: Awaited<ReturnType<typeof serve>>, outcome: GrantOutcome | undefined) => {
	if (outcome?.kind !== "issued") throw new Error(said(outcome));
	return s.verify(String(outcome.body.access_token));
};

describe("a grant naming no client, by an issuer's client", () => {
	it("identifies for an entry with a client alone, and has no identify where no entry has one", async () => {
		const log = recordingLog();
		await serve(undefined, { log });
		expect(log.lines().filter((l) => l.event === "jwt-bearer.clientless_issuer")).toEqual([
			{
				level: "warn",
				event: "jwt-bearer.clientless_issuer",
				fields: { at: "jwt-bearer.issuers.0" },
			},
			{
				level: "warn",
				event: "jwt-bearer.clientless_issuer",
				fields: { at: "jwt-bearer.issuers.2" },
			},
		]);
		const { client: _phones, ...unbound } = devicesEntry;
		const none = await serve([ownEntry, unbound]);
		expect(none.grant.identify).toBeUndefined();
	});

	it("answers one refusal for whatever fails before the subject is taken, using up no jti", async () => {
		const s = await serve(undefined, { linkedTo: undefined });
		const id = await thumb();
		for (const assertion of [
			await ofShared({}, stranger.privateKey),
			await ofShared({ aud: "https://elsewhere.example" }),
			await ofShared({ exp: now / 1000 - 600 }),
			await ofShared({ sub: "org:other/ci" }),
			await sign({ iss: own, sub: "alice" }, ownKey.privateKey),
			await sign({ iss: devices, sub: id }, device.privateKey),
			await sign({ iss: delegatedIss, sub: "alice" }, stranger.privateKey),
			await sign({ iss: "https://unknown.example", sub: "alice" }, stranger.privateKey),
		]) {
			expect(await s.identify(assertion)).toEqual(unidentified);
		}
		expect(await s.identify("not-a-jwt")).toEqual(unidentified);
		expect([s.asked.saved, s.asked.checks, s.asked.spends]).toEqual([[], [], []]);
		// A linked signer standing for no one was looked up, and is refused as the others.
		expect(s.asked.linked).toEqual([["device", id]]);
	});

	it("issues to the entry's client, handed what identify found, asking no keys or subjects again", async () => {
		const s = await serve();
		const issued = await tokenOf(s, await s.clientless(await ofShared()));
		expect(issued).toMatchObject({
			kind: "valid",
			grant: { subject: "org:acme/ci", issuedTo: "agents", scope: ["read"] },
		});
		const id = await thumb();
		const linked = await tokenOf(
			s,
			await s.clientless(await sign({ iss: devices, sub: id }, device.privateKey)),
		);
		expect(linked).toMatchObject({ grant: { subject: "account-7", issuedTo: "phones" } });
		expect([s.asked.keys.length, s.asked.linked.length]).toEqual([1, 1]);
	});

	it("binds an entry and its client both ways, refusing before the jti is used up", async () => {
		const s = await serve();
		const theirs = await ofShared();
		expect(said(await s.handle(theirs, "app"))).toBe(
			"invalid_grant: assertion is for another client",
		);
		const others = await sign({ iss: own, sub: "alice" }, ownKey.privateKey);
		expect(said(await s.handle(others, "agents"))).toBe(
			"invalid_grant: assertion is for another client",
		);
		// The entry's client never takes a delegated issuer's assertion, however its delegate names it.
		const handed = await sign({ iss: delegatedIss, sub: "alice" }, stranger.privateKey);
		expect(said(await s.handle(handed, "agents"))).toBe(
			"invalid_grant: assertion is for another client",
		);
		expect([s.asked.saved, s.asked.checks, s.asked.spends]).toEqual([[], [], []]);
		// Bound before its conditions are asked: another client is told the binding first.
		expect(said(await s.handle(await ofShared({ sub: "org:other/ci" }), "app"))).toBe(
			"invalid_grant: assertion is for another client",
		);
		expect(said(await s.handle(others, "app"))).toBe("issued");
	});

	it("takes for the entry's client named by its client_id the same token, its refusals in their own words", async () => {
		const s = await serve();
		const named = await tokenOf(s, await s.handle(await ofShared(), "agents"));
		expect(named).toMatchObject({ grant: { subject: "org:acme/ci", issuedTo: "agents" } });
		expect(said(await s.handle(await ofShared({ sub: "org:other/ci" }), "agents"))).toBe(
			"invalid_grant: assertion does not meet its issuer's conditions",
		);
		expect(said(await s.handle(await ofShared({}, stranger.privateKey), "agents"))).toBe(
			"invalid_grant: untrusted signer",
		);
	});

	it("uses an assertion up once, whether a request names its client or none, in the store and in a ledger", async () => {
		const ledger = defineModule({ name: "jti-ledger", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(jtiLedgers).by(() => memoryJtiLedger(shared, () => now)),
		]);
		for (const extra of [[], [ledger]]) {
			const s = await serve(undefined, { extra });
			const first = await ofShared();
			expect(said(await s.clientless(first))).toBe("issued");
			expect(said(await s.handle(first, "agents"))).toBe("invalid_grant: assertion replayed");
			const second = await ofShared();
			expect(said(await s.handle(second, "agents"))).toBe("issued");
			expect(said(await s.clientless(second))).toBe("invalid_grant: assertion replayed");
			const third = await ofShared();
			const both = await Promise.all([s.clientless(third), s.handle(third, "agents")]);
			expect(both.map(said).sort()).toEqual(["invalid_grant: assertion replayed", "issued"]);
		}
	});

	it("holds a request naming no client to its entry's ceiling, lifetime and clock skew", async () => {
		const s = await serve([
			{
				...sharedEntry,
				ceiling: { scopes: ["write"] },
				"max-assertion-lifetime": "10m",
				"clock-skew": "5s",
			},
			devicesEntry,
		]);
		// The client's default, read, is outside the ceiling: refused; write, inside both, is issued.
		expect(said(await s.clientless(await ofShared()))).toBe("invalid_scope: scope is required");
		const narrowed = await tokenOf(s, await s.clientless(await ofShared(), { scope: "write" }));
		expect(narrowed).toMatchObject({ grant: { scope: ["write"] } });
		// Taken by the section's own lifetime and skew, refused by the entry's.
		expect(await s.identify(await ofShared({ exp: now / 1000 + 1200 }))).toEqual(unidentified);
		expect(await s.identify(await ofShared({ nbf: now / 1000 + 10 }))).toEqual(unidentified);
	});

	it("identifies a self-issued signer as its entry's, its jti apart from the issuer's own", async () => {
		const prefix = "device:";
		const id = await thumb();
		const held = defineModule({ name: "phone-keys", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(signerKeys).by(() => ({
				issuer: "app.phones",
				perSigner: true,
				keysOf: async () => ({
					kind: "keys",
					keys: [{ ...(await deviceKey()), kid: id }],
					algorithms: ["EdDSA"],
				}),
			})),
		]);
		const phones = {
			issuer: "app.phones",
			subject: "as-is",
			"subject-is-key-thumbprint": true,
			"self-issued-prefix": prefix,
			client: "agents",
		};
		const s = await serve([phones, devicesEntry], { extra: [held] });
		const jti = "j-shared";
		const selfIssued = await sign(
			{ iss: `${prefix}${id}`, sub: `${prefix}${id}`, jti },
			device.privateKey,
			id,
		);
		const told = await s.identify(selfIssued);
		expect(told).toMatchObject({ kind: "client", client: "agents" });
		expect(said(await s.clientless(selfIssued))).toBe("issued");
		// The issuer's own assertion with the same jti is named by its own iss, apart.
		const fixed = await sign({ iss: "app.phones", sub: id, jti }, device.privateKey, id);
		expect(said(await s.clientless(fixed))).toBe("issued");
	});

	it("refuses to boot, at the entry's client, on a client with credentials, a confidential one, one not registered, and one allowed another grant", async () => {
		// A key method and another grant, composed, so nothing but jwt-bearer refuses the clients.
		const composed = defineModule({ name: "composed", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(authMethods).by(() => ({
				name: "test-key",
				claimed: () => undefined,
				verify: async () => true,
			})),
			m.contribute(grants).by(() => ({
				grantType: "urn:test:other",
				readsAmbient: "none",
				handle: async () => ({ kind: "error", error: "invalid_grant" }),
			})),
		]);
		const others = registered.filter((k) => k.id !== "agents");
		const credentials = "names a client with credentials: it needs to be public with method none";
		const cases = [
			[{ ...confidentialClient({ id: "agents", sections: jwtOnly }), kind: "public" }, credentials],
			[publicClient({ id: "agents", method: "test-key", sections: jwtOnly }), credentials],
			[confidentialClient({ id: "agents", sections: jwtOnly }), credentials],
			// Confidential with method none: registered, though never authenticated.
			[confidentialClient({ id: "agents", method: "none", sections: jwtOnly }), credentials],
			[undefined, "names no registered client"],
			[
				publicClient({
					id: "agents",
					sections: allowancesFor({ grants: [grantType, "urn:test:other"], scopes: ["read"] }),
				}),
				"names a client allowed another grant than this one",
			],
		] as const;
		for (const [agents, reason] of cases) {
			const refusals = await serve(undefined, {
				registered: [...others, ...(agents ? [agents] : [])],
				extra: [composed],
			}).then(
				() => [],
				(error: { refusals?: readonly { where: string; reason: string }[] }) => error.refusals,
			);
			expect(refusals, reason).toEqual([{ where: "jwt-bearer.issuers.0.client", reason }]);
		}
	});

	it("refuses to boot on accept-any-subject beside a client", async () => {
		await expect(serve([{ ...ownEntry, client: "agents" }, devicesEntry])).rejects.toMatchObject({
			refusals: [
				{ where: "jwt-bearer.issuers.0.accept-any-subject", reason: "is written beside client" },
			],
		});
	});
});
