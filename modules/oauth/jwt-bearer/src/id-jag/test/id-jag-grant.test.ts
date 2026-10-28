import { generateKeyPairSync, type KeyObject } from "node:crypto";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import { clients } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import { clientsConfig, confidentialClient, publicClient } from "@mod/clients/testing";
import externalJwtModule from "@mod/external-jwt/module";
import { type Grant, type GrantInput, grants, targetRules } from "@mod/grants";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { type MetadataItem, metadata } from "@mod/issuer";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, contract, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import outboundModule from "@mod/outbound/module";
import { memoryRecords } from "@mod/records/testing";
import secretHashModule from "@mod/secret-hash/module";
import {
	type SenderBinding,
	type SenderBindings,
	senderBinding,
	senderBindings,
} from "@mod/sender-binding";
import { simulatedStore } from "@mod/store/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { tokenEndpointLocation } from "@mod/token-endpoint";
import { grantCaller, grantCalls, grantInput } from "@mod/token-endpoint/testing";
import { issuancePolicies, tokens } from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { calculateJwkThumbprint, exportJWK, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import {
	type DelegatedAssertions,
	delegatedAssertions,
	jtiLedgers,
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
const tokenEndpoint = `${issuer}/oauth/token`;
const grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const pem = (k: KeyObject) => k.export({ format: "pem", type: "spki" }).toString();
const keyOf = (k: KeyObject) => [{ alg: "EdDSA", "public-key": pem(k) }];
const idpKey = generateKeyPairSync("ed25519");
const agentsKey = generateKeyPairSync("ed25519");
const corpKey = generateKeyPairSync("ed25519");
const ceilKey = generateKeyPairSync("ed25519");
const limitedKey = generateKeyPairSync("ed25519");

const idp = "https://idp.example";
const agentsIdp = "https://agents.example";
const delegatedIss = "https://delegated.example";
const corp = "https://corp.example";
const ceil = "https://ceil.example";
const limited = "https://limited.example";
const api = "https://api.example";
const otherApi = "https://other.example";
const idJagTyp = "oauth-id-jag+jwt";
const jkt = "A".repeat(43);

/** A trusted issuer taking no profile. */
const plainEntry = {
	issuer: idp,
	subject: "as-is",
	keys: keyOf(idpKey.publicKey),
	"accept-any-subject": true,
};
/** One whose `client` takes a request naming none. */
const agentsEntry = {
	issuer: agentsIdp,
	subject: "as-is",
	keys: keyOf(agentsKey.publicKey),
	conditions: { "subject-prefix": "agents/" },
	client: "agents",
};
/** An enterprise IdP whose ID-JAGs this server takes. */
const jagEntry = {
	issuer: corp,
	subject: "as-is",
	keys: keyOf(corpKey.publicKey),
	"accept-any-subject": true,
	profile: "id-jag",
};
/** One whose tokens its own ceiling holds too. */
const ceilEntry = {
	...jagEntry,
	issuer: ceil,
	keys: keyOf(ceilKey.publicKey),
	ceiling: { scopes: ["chat.read"] },
};
/** One whose ID-JAGs one client alone may present, for its subjects alone: 0.17's allowedClients. */
const limitedEntry = {
	issuer: limited,
	subject: "as-is",
	keys: keyOf(limitedKey.publicKey),
	conditions: { "subject-prefix": "corp|", claims: { client_id: ["agent"] } },
	profile: "id-jag",
};

const jwtOnly = allowancesFor({
	grants: [grantType],
	scopes: ["read"],
	"default-scopes": ["read"],
});
/** Wide defaults: an issuance the ID-JAG does not hold would take them all. */
const wide = allowancesFor({
	grants: [grantType],
	scopes: ["chat.read", "chat.history", "admin"],
	"default-scopes": ["chat.read", "chat.history", "admin"],
	audiences: [api, otherApi],
});

/** What the fakes were asked: a delegate's checks, the store's saves, the corp ledger's spends. */
interface Asked {
	checks: string[];
	saved: string[];
	spent: string[];
}

/** What a test may change of the fakes: a target that ignores the allowance, the corp ledger, a shared store. */
interface Fakes {
	/** A target rule taking any `resource` asked, the allowance unasked: so only a later check holds it. */
	readonly lax?: boolean;
	/** Whether the corp issuer's jtis go to its own ledger (true, by default) or to the store. */
	readonly corpLedger?: boolean;
	/** The spent assertions' records, shared with another assembly where given. */
	readonly spentRecords?: ReturnType<typeof memoryRecords<true>>;
}

function fakes(asked: Asked, withCorpLedger: boolean, given: Fakes) {
	return [
		defineModule({ name: "delegate", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(delegatedAssertions).by(
				(): DelegatedAssertions => ({
					declaredBy: "delegate",
					issuers: [delegatedIss],
					check: async (a) => {
						asked.checks.push(a);
						return { kind: "invalid" };
					},
					spend: async () => "spent",
				}),
			),
		]),
		defineModule({ name: "spent-assertions", replicaSafe: false, takes: [] }, (m) => [
			m.provide(spentAssertions).by(() => {
				const stand =
					given.spentRecords ?? memoryRecords<true>(() => now, { shards: 1, perShard: 1 });
				return {
					save: (name: string, lifetimeMs: number) => {
						asked.saved.push(name);
						return stand.records.create(name, true, lifetimeMs);
					},
				};
			}),
		]),
		// The corp issuer's own ledger, where it is named.
		defineModule({ name: "corp-ledger", replicaSafe: false, takes: [] }, (m) =>
			withCorpLedger && given.corpLedger !== false
				? [
						m.contribute(jtiLedgers).by(() => {
							const ledger = memoryJtiLedger(corp, () => now);
							return {
								issuer: corp,
								spend: (a) => {
									asked.spent.push(a.jti);
									return ledger.spend(a);
								},
							};
						}),
					]
				: [],
		),
		// The audience asked by `resource`, as resource indicators narrow it.
		defineModule({ name: "narrowing", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(targetRules).by(() => ({
				target: ({ param, audience, within }) => {
					const asked = param("resource");
					if (!asked) return { kind: "audience", audience };
					if (given.lax) return { kind: "audience", audience: [asked] };
					return within(asked)
						? { kind: "audience", audience: [asked] }
						: { kind: "error", error: "invalid_target", description: `not ${asked}` };
				},
			})),
		]),
	];
}

/** Sender binding as the endpoint composes it: with a DPoP kind writing `jkt`, or with none. */
const bindingKinds = (dpop: boolean) =>
	defineModule({ name: "sender-binding", replicaSafe: false, takes: [] }, (m) => [
		m.provide(senderBinding).by(
			() =>
				({
					tokenTypeOf: (member: string) => (dpop && member === "jkt" ? "DPoP" : undefined),
				}) as unknown as SenderBindings,
		),
		...(dpop
			? [
					m.contribute(senderBindings).by(
						(): SenderBinding => ({
							member: "jkt",
							name: "dpop",
							tokenType: "DPoP",
							explicit: true,
							read: async () => ({ kind: "absent" }),
						}),
					),
				]
			: []),
	]);

/** The metadata items every module contributes, as the discovery document is made of them. */
const published = contract<readonly MetadataItem[]>("test.id-jag-metadata");
const reader = defineModule(
	{ name: "test-metadata", replicaSafe: true, takes: [metadata] },
	(m) => [m.provide(published).by((c) => c.collect(metadata))],
);

const grantOf = contract<Grant>("test.id-jag-grant");
const exposing = defineModule({ name: "test-grant", replicaSafe: true, takes: [grants] }, (m) => [
	m.provide(grantOf).by(async (c) => {
		const found = (await c.collect(grants)).find((g) => g.grantType === grantType);
		if (!found) throw new Error("no jwt-bearer grant");
		return found;
	}),
]);

async function serve(
	issuers: readonly Record<string, unknown>[] = [
		plainEntry,
		agentsEntry,
		jagEntry,
		ceilEntry,
		limitedEntry,
	],
	options: { readonly dpop?: boolean; readonly extra?: readonly Module[] } & Fakes = {},
) {
	const asked: Asked = { checks: [], saved: [], spent: [] };
	const location = defineModule(
		{ name: "token-endpoint-location", replicaSafe: true, takes: [] },
		(m) => [m.provide(tokenEndpointLocation).by(() => ({ url: tokenEndpoint }))],
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
			externalJwtModule,
			simulatedStore().module,
			subjectRevocationStandIn,
			jwtBearer,
			exposing,
			reader,
			bindingKinds(options.dpop ?? true),
			...fakes(
				asked,
				issuers.some((i) => i.issuer === corp),
				options,
			),
			...(options.extra ?? []),
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": new URL(issuer).origin }),
			...issuerConfig({ url: issuer }),
			...clientsConfig([
				publicClient({ id: "agents", sections: jwtOnly }),
				confidentialClient({ id: "agent", sections: wide }),
				confidentialClient({ id: "other", sections: wide }),
				confidentialClient({ id: "excluded", sections: wide }),
				publicClient({ id: "pub", sections: wide }),
			]),
			"jwt-bearer": { issuers, "delegated-issuers": [delegatedIss] },
		},
		runtime,
	});
	const grant = app.get(grantOf);
	const anyClient = await (await app.get(clients)).find("agents");
	/** The grant's `identify`, asked as the endpoint asks it of a request naming no client. */
	const identify = async (assertion: string) => {
		if (!anyClient) throw new Error("no client");
		const input = grantInput(app.get(tokens), grant, anyClient, {
			grant_type: grantType,
			assertion,
		});
		return grant.identify?.({ request: input.request, param: input.param, value: input.value });
	};
	/** The grant's `handle` for a client that named itself, with the request's parameters and binding. */
	const handle = (
		assertion: string,
		client = "agent",
		more: Record<string, string> = {},
		binding?: GrantInput["binding"],
	) =>
		app
			.get(grantCalls)
			.call(
				grantType,
				client,
				{ grant_type: grantType, assertion, ...more },
				binding ? { binding } : {},
			);
	/** The value the discovery document gives a metadata item; none where it is left out. */
	const published_ = (name: string) => app.get(published).find((i) => i.name === name)?.value;
	return { identify, handle, asked, metadataOf: published_ };
}

/** Why boot is refused, by place. */
const refusedAt = async (issuers: readonly Record<string, unknown>[], dpop = true) => {
	const failure = await serve(issuers, { dpop }).then(
		() => undefined,
		(e: { refusals?: readonly { where: string; reason: string }[]; message?: string }) => {
			return e.refusals ?? [];
		},
	);
	return failure ?? "booted";
};

const sign = (
	claims: Record<string, unknown>,
	key: KeyObject,
	typ: string | null = idJagTyp,
	kid?: string,
) =>
	new SignJWT({
		jti: `j-${Math.random()}`,
		aud: issuer,
		sub: "alice",
		iat: now / 1000,
		exp: now / 1000 + 120,
		client_id: "agent",
		...claims,
	})
		.setProtectedHeader({ alg: "EdDSA", ...(typ !== null ? { typ } : {}), ...(kid ? { kid } : {}) })
		.sign(key);
/** An assembly of `issuers` whose spent assertions go to `records`, the corp issuer's too. */
const s0 = (
	records: ReturnType<typeof memoryRecords<true>>,
	issuers: readonly Record<string, unknown>[],
) => serve(issuers, { spentRecords: records, corpLedger: false });
/** An ID-JAG of the corp IdP, for the client `agent`, narrow in scope and resource. */
const ofCorp = (claims: Record<string, unknown> = {}) =>
	sign(
		{ iss: corp, scope: "chat.read chat.history", resource: api, ...claims },
		corpKey.privateKey,
	);

type Outcome =
	| {
			readonly kind: string;
			readonly error?: string;
			readonly description?: string;
			readonly body?: Readonly<Record<string, unknown>>;
	  }
	| undefined;
const said = (outcome: Outcome) =>
	outcome === undefined
		? "no identify"
		: outcome.kind === "error"
			? `${outcome.error}: ${outcome.description}`
			: outcome.kind;
const bodyOf = (outcome: Outcome) => {
	if (outcome?.kind !== "issued" || !outcome.body) throw new Error(said(outcome));
	return outcome.body;
};
const untrusted = "invalid_grant: untrusted signer";
const dpop = (confirmation: string): GrantInput["binding"] => ({
	member: "jkt",
	confirmation,
	tokenType: "DPoP",
});

describe("an ID-JAG where no issuer takes the profile", () => {
	it("is refused on every way an assertion goes, before anything is verified or used up", async () => {
		const s = await serve([plainEntry, agentsEntry]);
		const ways = {
			"a trusted issuer": await sign({ iss: idp }, idpKey.privateKey),
			"its type as external-jwt reads one": await sign(
				{ iss: idp },
				idpKey.privateKey,
				"application/OAuth-ID-JAG+JWT",
			),
			"a delegated issuer": await sign({ iss: delegatedIss }, idpKey.privateKey),
			"an issuer no entry names": await sign({ iss: "https://unknown.example" }, idpKey.privateKey),
		};
		for (const [way, assertion] of Object.entries(ways))
			expect(said(await s.handle(assertion)), way).toBe(untrusted);
		expect(s.asked.checks).toEqual([]);
		expect(s.asked.saved).toEqual([]);
	});

	it("is refused for a self-issued signer, before its keys are asked for", async () => {
		const device = generateKeyPairSync("ed25519");
		const thumb = await calculateJwkThumbprint(await exportJWK(device.publicKey), "sha256");
		const keysAsked: unknown[] = [];
		const deviceKeys = defineModule({ name: "device-keys", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(signerKeys).by(
				(): SignerKeys => ({
					issuer: "https://devices.example",
					perSigner: true,
					keysOf: async (signer) => {
						keysAsked.push(signer);
						return {
							kind: "keys",
							keys: [{ ...(await exportJWK(device.publicKey)), alg: "EdDSA", kid: thumb }],
							algorithms: ["EdDSA"],
						};
					},
				}),
			),
		]);
		const devices = {
			issuer: "https://devices.example",
			subject: "as-is",
			"subject-is-key-thumbprint": true,
			"self-issued-prefix": "device:",
		};
		const s = await serve([plainEntry, devices], { extra: [deviceKeys] });
		const name = `device:${thumb}`;
		const asJag = await sign({ iss: name, sub: name }, device.privateKey, idJagTyp, thumb);
		expect(said(await s.handle(asJag))).toBe(untrusted);
		expect(keysAsked).toEqual([]);
		// The same signer's assertion of no profile goes its way.
		const plain = await sign({ iss: name, sub: name }, device.privateKey, "JWT", thumb);
		expect(said(await s.handle(plain))).toBe("issued");
	});

	it("is refused for a request naming no client, by an entry whose client would take one", async () => {
		const s = await serve();
		const assertion = await sign({ iss: agentsIdp, sub: "agents/ci" }, agentsKey.privateKey);
		expect(said(await s.identify(assertion))).toBe(untrusted);
		expect(said(await s.handle(assertion, "agents"))).toBe(untrusted);
		expect(s.asked.saved).toEqual([]);
	});

	it("leaves an assertion of any other type as it was, its answer naming no resource", async () => {
		const s = await serve();
		const plain = await s.handle(await sign({ iss: idp }, idpKey.privateKey, null));
		expect(bodyOf(plain)).not.toHaveProperty("resource");
		expect(said(await s.handle(await sign({ iss: idp }, idpKey.privateKey, "JWT")))).toBe("issued");
		// The token endpoint's URL is still an audience such an assertion may name.
		const toEndpoint = await sign({ iss: idp, aud: tokenEndpoint }, idpKey.privateKey, "JWT");
		expect(said(await s.handle(toEndpoint))).toBe("issued");
		expect(
			said(
				await s.identify(
					await sign({ iss: agentsIdp, sub: "agents/ci" }, agentsKey.privateKey, "JWT"),
				),
			),
		).toBe("client");
	});
});

describe("an issuer taking the ID-JAG profile", () => {
	it("issues within the ID-JAG, answering the scope and resource issued and no refresh token", async () => {
		const s = await serve();
		const body = bodyOf(await s.handle(await ofCorp()));
		expect(body.scope).toBe("chat.read chat.history");
		expect(body.resource).toBe(api);
		expect(body).not.toHaveProperty("refresh_token");
		expect(body).not.toHaveProperty("authorization_details");
		expect(s.asked.spent).toHaveLength(1);
	});

	it("never lets an empty request take the client's wider defaults past the ID-JAG's scope", async () => {
		const s = await serve();
		const narrow = { scope: "chat.read" };
		expect(bodyOf(await s.handle(await ofCorp(narrow))).scope).toBe("chat.read");
		expect(bodyOf(await s.handle(await ofCorp(narrow), "agent", { scope: "" })).scope).toBe(
			"chat.read",
		);
		expect(said(await s.handle(await ofCorp(narrow), "agent", { scope: "admin" }))).toBe(
			"invalid_scope: undefined",
		);
		expect(said(await s.handle(await ofCorp({ scope: "" })))).toBe(
			"invalid_grant: missing or malformed claims",
		);
		// With no scope, the client's defaults stand, within its issuer's ceiling.
		const unscoped = await sign({ iss: ceil }, ceilKey.privateKey);
		expect(bodyOf(await s.handle(unscoped)).scope).toBe("chat.read");
	});

	it("answers the resource issued, asked or not, and refuses one the ID-JAG does not name", async () => {
		const s = await serve();
		const both = { resource: [api, otherApi] };
		expect(
			bodyOf(await s.handle(await ofCorp(both), "agent", { resource: otherApi })).resource,
		).toBe(otherApi);
		expect(bodyOf(await s.handle(await ofCorp(both))).resource).toBe(api);
		expect(said(await s.handle(await ofCorp(), "agent", { resource: otherApi }))).toBe(
			`invalid_target: not ${otherApi}`,
		);
	});

	it("drops authorization details beside a scope, and refuses them with none", async () => {
		const s = await serve();
		const details = { authorization_details: [{ type: "chat_export", limit: 3 }] };
		expect(bodyOf(await s.handle(await ofCorp(details)))).not.toHaveProperty(
			"authorization_details",
		);
		const noScope = await sign({ iss: corp, ...details }, corpKey.privateKey);
		expect(said(await s.handle(noScope))).toBe(
			"invalid_grant: authorization details are not served",
		);
	});

	it("takes this server's issuer alone as its audience, never the token endpoint", async () => {
		const s = await serve();
		expect(said(await s.handle(await ofCorp({ aud: tokenEndpoint })))).toBe(
			"invalid_grant: wrong audience",
		);
		expect(said(await s.handle(await ofCorp({ aud: [issuer, tokenEndpoint] })))).toBe(
			"invalid_grant: wrong audience",
		);
		expect(said(await s.handle(await ofCorp({ aud: [issuer] })))).toBe("issued");
	});

	it("takes its own type alone, and none by a request naming no client", async () => {
		const s = await serve();
		for (const typ of [null, "JWT"])
			expect(
				said(
					await s.handle(await sign({ iss: corp, scope: "chat.read" }, corpKey.privateKey, typ)),
				),
				String(typ),
			).toBe(untrusted);
		expect(said(await s.identify(await ofCorp()))).toBe(untrusted);
		expect(s.asked.spent).toEqual([]);
	});

	it("is bound to the key its cnf names, proved by DPoP alone", async () => {
		const s = await serve();
		const bound = { cnf: { jkt } };
		const issued = bodyOf(await s.handle(await ofCorp(bound), "agent", {}, dpop(jkt)));
		expect(issued.token_type).toBe("DPoP");
		const unproved = "invalid_grant: the request does not prove the key the assertion names";
		expect(said(await s.handle(await ofCorp(bound)))).toBe(unproved);
		expect(said(await s.handle(await ofCorp(bound), "agent", {}, dpop("B".repeat(43))))).toBe(
			unproved,
		);
		const mtls = { member: "x5t#S256", confirmation: jkt, tokenType: "Bearer" };
		expect(said(await s.handle(await ofCorp(bound), "agent", {}, mtls))).toBe(unproved);
		// One naming no key is bound as the request proves, or not at all.
		expect(bodyOf(await s.handle(await ofCorp(), "agent", {}, dpop(jkt))).token_type).toBe("DPoP");
		expect(String(bodyOf(await s.handle(await ofCorp())).token_type).toLowerCase()).toBe("bearer");
	});

	it("uses nothing up on a refusal before its jti is spent, so the request put right is taken", async () => {
		const s = await serve();
		const cases: [string, () => Promise<Outcome>, () => Promise<Outcome>, string][] = [];
		const forAgent = await ofCorp();
		cases.push([
			"another client",
			() => s.handle(forAgent, "other"),
			() => s.handle(forAgent),
			"invalid_grant: assertion is for another client",
		]);
		const forPub = await ofCorp({ client_id: "pub" });
		cases.push([
			"a public client",
			() => s.handle(forPub, "pub"),
			async () => undefined,
			"invalid_grant: the profile needs a confidential client",
		]);
		const keyed = await ofCorp({ cnf: { jkt } });
		cases.push([
			"no proof of its key",
			() => s.handle(keyed),
			() => s.handle(keyed, "agent", {}, dpop(jkt)),
			"invalid_grant: the request does not prove the key the assertion names",
		]);
		const scoped = await ofCorp();
		cases.push([
			"a scope past it",
			() => s.handle(scoped, "agent", { scope: "admin" }),
			() => s.handle(scoped),
			"invalid_scope: undefined",
		]);
		const aimed = await ofCorp();
		cases.push([
			"a resource past it",
			() => s.handle(aimed, "agent", { resource: otherApi }),
			() => s.handle(aimed),
			`invalid_target: not ${otherApi}`,
		]);
		for (const [what, refused, putRight, answer] of cases) {
			expect(said(await refused()), what).toBe(answer);
			expect(s.asked.spent, what).toEqual([]);
			const taken = await putRight();
			if (taken !== undefined) {
				expect(said(taken), what).toBe("issued");
				s.asked.spent.length = 0;
			}
		}
		const unmet = await sign({ iss: limited, scope: "chat.read" }, limitedKey.privateKey);
		expect(said(await s.handle(unmet))).toBe(
			"invalid_grant: assertion does not meet its issuer's conditions",
		);
		const past = await sign({ iss: ceil, scope: "chat.read chat.history" }, ceilKey.privateKey);
		expect(said(await s.handle(past))).toBe("invalid_scope: undefined");
		expect(s.asked.saved).toEqual([]);
	});

	it("checks again what is chosen, refusing an audience the ID-JAG does not name that a target let by", async () => {
		let judged = 0;
		const counting = defineModule({ name: "counting", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(issuancePolicies).by(() => ({
				name: "counting",
				judge: async () => {
					judged += 1;
					return { kind: "allowed" };
				},
			})),
		]);
		// The target takes what is asked, unheld by the allowance: only the ID-JAG's own check stands.
		const s = await serve(undefined, { lax: true, extra: [counting] });
		const asked = await ofCorp();
		expect(said(await s.handle(asked, "agent", { resource: otherApi }))).toBe(
			"invalid_target: undefined",
		);
		expect([s.asked.spent, judged]).toEqual([[], 0]);
		expect(said(await s.handle(asked))).toBe("issued");
	});

	it("shares its record of spent assertions with its issuer's assertions of no profile", async () => {
		// One store, as an instance keeps it across a change of the entry's profile.
		const records = memoryRecords<true>(() => now, { shards: 1, perShard: 1 });
		const plainCorp = { ...jagEntry, profile: "rfc7523" };
		const jti = `shared-${Math.random()}`;
		const asJag = await s0(records, [jagEntry]).then((s) => s.handle);
		expect(said(await asJag(await ofCorp({ jti })))).toBe("issued");
		const asPlain = await s0(records, [plainCorp]).then((s) => s.handle);
		expect(said(await asPlain(await sign({ iss: corp, jti }, corpKey.privateKey, "JWT")))).toBe(
			"invalid_grant: assertion replayed",
		);
		// And the other way: one spent with no profile, presented as an ID-JAG once it takes it.
		const other = `shared-${Math.random()}`;
		expect(
			said(await asPlain(await sign({ iss: corp, jti: other }, corpKey.privateKey, "JWT"))),
		).toBe("issued");
		expect(said(await asJag(await ofCorp({ jti: other })))).toBe(
			"invalid_grant: assertion replayed",
		);
	});

	it("gives back no jti spent before a refusal when the token is issued", async () => {
		let asked = 0;
		const secondRefuses = defineModule(
			{ name: "second-refuses", replicaSafe: false, takes: [] },
			(m) => [
				m.contribute(issuancePolicies).by(() => ({
					name: "second-refuses",
					judge: async () => {
						asked += 1;
						return asked === 2
							? { kind: "refused", reason: "test", description: "refused when issuing" }
							: { kind: "allowed" };
					},
				})),
			],
		);
		const s = await serve(undefined, { extra: [secondRefuses] });
		const assertion = await ofCorp();
		expect(said(await s.handle(assertion)).startsWith("issued")).toBe(false);
		expect(said(await s.handle(assertion))).toBe("invalid_grant: assertion replayed");
	});

	it("is held to its issuer's client and subject conditions, the client named first", async () => {
		const s = await serve();
		const forExcluded = await sign(
			{ iss: limited, sub: "corp|bob", client_id: "excluded", scope: "chat.read" },
			limitedKey.privateKey,
		);
		expect(said(await s.handle(forExcluded, "excluded"))).toBe(
			"invalid_grant: assertion does not meet its issuer's conditions",
		);
		const taken = await sign(
			{ iss: limited, sub: "corp|bob", scope: "chat.read" },
			limitedKey.privateKey,
		);
		expect(said(await s.handle(taken))).toBe("issued");
		const otherSubject = await sign(
			{ iss: limited, sub: "bob", scope: "chat.read" },
			limitedKey.privateKey,
		);
		expect(said(await s.handle(otherSubject))).toBe(
			"invalid_grant: assertion does not meet its issuer's conditions",
		);
		// For another client, and outside the conditions too: the client is told first.
		expect(said(await s.handle(forExcluded, "agent"))).toBe(
			"invalid_grant: assertion is for another client",
		);
		expect(s.asked.saved).toHaveLength(1);
	});
});

describe("the ID-JAG profile in the metadata", () => {
	const item = "authorization_grant_profiles_supported";

	it("is named where an issuer takes it, its issuers never", async () => {
		const s = await serve();
		expect(s.metadataOf(item)).toEqual(["urn:ietf:params:oauth:grant-profile:id-jag"]);
		expect(JSON.stringify(s.metadataOf(item))).not.toContain("example");
		expect((await serve([plainEntry, agentsEntry])).metadataOf(item)).toBeUndefined();
	});
});

describe("the ID-JAG profile at boot", () => {
	const at = "jwt-bearer.issuers.0.profile";

	it("is refused where no binding kind proves a DPoP key, and needs none without a profile", async () => {
		expect(await refusedAt([jagEntry], false)).toEqual([
			{ where: at, reason: "the ID-JAG profile needs DPoP composed" },
		]);
		expect(await refusedAt([plainEntry], false)).toBe("booted");
	});

	it("is refused beside a thumbprint subject, a self-issued prefix and a client", async () => {
		for (const [what, entry] of [
			[
				"a thumbprint subject",
				{ ...jagEntry, "accept-any-subject": undefined, "subject-is-key-thumbprint": true },
			],
			[
				"a client",
				{
					...jagEntry,
					"accept-any-subject": undefined,
					conditions: { "subject-prefix": "corp|" },
					client: "agents",
				},
			],
		] as const) {
			const refusals = await refusedAt([JSON.parse(JSON.stringify(entry))]);
			expect(refusals, what).toEqual(
				expect.arrayContaining([expect.objectContaining({ where: at })]),
			);
		}
		const { keys: _, ...contributed } = jagEntry;
		const prefixed = {
			...contributed,
			"accept-any-subject": undefined,
			"subject-is-key-thumbprint": true,
			"self-issued-prefix": "corp.devices",
		};
		expect(await refusedAt([JSON.parse(JSON.stringify(prefixed))])).toEqual(
			expect.arrayContaining([expect.objectContaining({ where: at })]),
		);
	});

	it("needs a subject condition or accept-any-subject as any as-is issuer does", async () => {
		const { "accept-any-subject": _, ...bare } = jagEntry;
		expect(await refusedAt([bare])).not.toBe("booted");
	});

	it("refuses an empty list of clients, which 0.17 read as none allowed: such an issuer is left out", async () => {
		const empty = { ...limitedEntry, conditions: { claims: { client_id: [] } } };
		expect(await refusedAt([empty])).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					// Refused as no entry at all, at its place: never read as "none allowed".
					where: expect.stringContaining("jwt-bearer.issuers.0"),
				}),
			]),
		);
		// Left out, its ID-JAGs are an unknown signer's, whichever client presents them.
		const s = await serve([plainEntry]);
		const fromLeftOut = await sign(
			{ iss: limited, sub: "corp|bob", scope: "chat.read" },
			limitedKey.privateKey,
		);
		expect(said(await s.handle(fromLeftOut))).toBe(untrusted);
		expect(s.asked.saved).toEqual([]);
	});
});
