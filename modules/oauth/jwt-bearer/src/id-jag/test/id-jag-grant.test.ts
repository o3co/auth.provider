import { generateKeyPairSync, type KeyObject } from "node:crypto";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import { clients } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import { clientsConfig, confidentialClient, publicClient } from "@mod/clients/testing";
import externalJwtModule from "@mod/external-jwt/module";
import { type Grant, grants } from "@mod/grants";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import outboundModule from "@mod/outbound/module";
import { memoryRecords } from "@mod/records/testing";
import secretHashModule from "@mod/secret-hash/module";
import { simulatedStore } from "@mod/store/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { tokenEndpointLocation } from "@mod/token-endpoint";
import { grantCaller, grantCalls, grantInput } from "@mod/token-endpoint/testing";
import { tokens } from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { type DelegatedAssertions, delegatedAssertions, spentAssertions } from "../../contract.ts";
import jwtBearer from "../../module.ts";

const now = 1_800_000_000_000;
const runtime = quietRuntime({
	clock: { now: () => now },
	random: { bytes: (n) => new Uint8Array(n).fill(3) },
});
const issuer = "https://as.example";
const grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const pem = (k: KeyObject) => k.export({ format: "pem", type: "spki" }).toString();
const idpKey = generateKeyPairSync("ed25519");
const agentsKey = generateKeyPairSync("ed25519");

const idp = "https://idp.example";
const agentsIdp = "https://agents.example";
const delegatedIss = "https://delegated.example";
const idJagTyp = "oauth-id-jag+jwt";

/** A trusted issuer taking no profile. */
const plainEntry = {
	issuer: idp,
	subject: "as-is",
	keys: [{ alg: "EdDSA", "public-key": pem(idpKey.publicKey) }],
	"accept-any-subject": true,
};
/** One whose `client` takes a request naming none. */
const agentsEntry = {
	issuer: agentsIdp,
	subject: "as-is",
	keys: [{ alg: "EdDSA", "public-key": pem(agentsKey.publicKey) }],
	conditions: { "subject-prefix": "agents/" },
	client: "agents",
};

const jwtOnly = allowancesFor({
	grants: [grantType],
	scopes: ["read"],
	"default-scopes": ["read"],
});

/** What the fakes were asked: a delegate's checks, the store's saves. */
interface Asked {
	checks: string[];
	saved: string[];
}

function fakes(asked: Asked) {
	return [
		defineModule({ name: "delegate", takes: [] }, (m) => [
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
		defineModule({ name: "spent-assertions", takes: [] }, (m) => [
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

const grantOf = contract<Grant>("test.id-jag-grant");
const exposing = defineModule({ name: "test-grant", takes: [grants] }, (m) => [
	m.provide(grantOf).by(async (c) => {
		const found = (await c.collect(grants)).find((g) => g.grantType === grantType);
		if (!found) throw new Error("no jwt-bearer grant");
		return found;
	}),
]);

async function serve(issuers: readonly Record<string, unknown>[] = [plainEntry, agentsEntry]) {
	const asked: Asked = { checks: [], saved: [] };
	const location = defineModule({ name: "token-endpoint-location", takes: [] }, (m) => [
		m.provide(tokenEndpointLocation).by(() => ({ url: `${issuer}/oauth/token` })),
	]);
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
			...fakes(asked),
		],
		config: {
			...kernelConfig(),
			...httpConfig(),
			...issuerConfig({ url: issuer }),
			...clientsConfig([
				publicClient({ id: "agents", sections: jwtOnly }),
				confidentialClient({ id: "agent", sections: jwtOnly }),
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
	/** The grant's `handle` for a client that named itself. */
	const handle = (assertion: string, client = "agent") =>
		app.get(grantCalls).call(grantType, client, { grant_type: grantType, assertion });
	return { identify, handle, asked };
}

const sign = (claims: Record<string, unknown>, key: KeyObject, typ: string | null = idJagTyp) =>
	new SignJWT({
		jti: `j-${Math.random()}`,
		aud: issuer,
		sub: "alice",
		iat: now / 1000,
		exp: now / 1000 + 120,
		client_id: "agent",
		...claims,
	})
		.setProtectedHeader({ alg: "EdDSA", ...(typ !== null ? { typ } : {}) })
		.sign(key);

const said = (
	outcome:
		| { readonly kind: string; readonly error?: string; readonly description?: string }
		| undefined,
) =>
	outcome === undefined
		? "no identify"
		: outcome.kind === "error"
			? `${outcome.error}: ${outcome.description}`
			: outcome.kind;
const untrusted = "invalid_grant: untrusted signer";

describe("an ID-JAG where no issuer takes the profile", () => {
	it("is refused on every way an assertion goes, before anything is verified or used up", async () => {
		const s = await serve();
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

	it("is refused for a request naming no client, by an entry whose client would take one", async () => {
		const s = await serve();
		const assertion = await sign({ iss: agentsIdp, sub: "agents/ci" }, agentsKey.privateKey);
		expect(said(await s.identify(assertion))).toBe(untrusted);
		expect(said(await s.handle(assertion, "agents"))).toBe(untrusted);
		expect(s.asked.saved).toEqual([]);
	});

	it("leaves an assertion of any other type as it was", async () => {
		const s = await serve();
		expect(said(await s.handle(await sign({ iss: idp }, idpKey.privateKey, null)))).toBe("issued");
		expect(said(await s.handle(await sign({ iss: idp }, idpKey.privateKey, "JWT")))).toBe("issued");
		expect(
			said(
				await s.identify(
					await sign({ iss: agentsIdp, sub: "agents/ci" }, agentsKey.privateKey, "JWT"),
				),
			),
		).toBe("client");
	});
});
