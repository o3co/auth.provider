import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientsModule from "@mod/clients/module";
import { clientsConfig, confidentialClient, publicClient } from "@mod/clients/testing";
import externalJwtModule from "@mod/external-jwt/module";
import { testSigner } from "@mod/external-jwt/testing";
import type { GrantOutcome } from "@mod/grants";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import outboundModule from "@mod/outbound/module";
import secretHashModule from "@mod/secret-hash/module";
import { type Binding, senderBindings } from "@mod/sender-binding";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { tlsOptionsForTests } from "@mod/tls-options/testing";
import { grantCaller, grantCalls } from "@mod/token-endpoint/testing";
import tokenExchange from "@mod/token-exchange/module";
import { tokensStandIn } from "@mod/tokens/testing";
import usersModule from "@mod/users/module";
import { memoryUsersStores, testUser } from "@mod/users/testing";
import { type UsedIdTokens, usedIdTokens } from "../src/contract.ts";
import { exchangeIdTokensOver, type Issuers } from "../src/testing.ts";
import { memoryUsedIdTokens } from "./stores.ts";

export const now = 1_800_000_000_000;
export const clock = { at: now };
export const runtime = quietRuntime({
	clock: { now: () => clock.at },
	random: { bytes: (n) => new Uint8Array(n).map(() => Math.floor(Math.random() * 256)) },
});
export const grantType = "urn:ietf:params:oauth:grant-type:token-exchange";
export const idTokenType = "urn:ietf:params:oauth:token-type:id_token";
export const api = "https://api.example";

export const apple = await testSigner("RS256", "apple-1");
export const google = await testSigner("RS256", "google-1");
export const stranger = await testSigner("RS256", "google-1");
/** A key the issuer's set holds, for an algorithm never taken. */
export const elliptic = await testSigner("ES256", "google-es");
export const issuers: Issuers = {
	apple: { iss: ["https://appleid.apple.com"], keys: { inline: [apple.jwk] } },
	google: {
		iss: ["https://accounts.google.com", "accounts.google.com"],
		keys: { inline: [google.jwk, elliptic.jwk] },
	},
};

export const allowed = allowancesFor({ grants: [grantType], scopes: ["read"], audiences: [api] });
export const settings = {
	apple: {
		clients: {
			"ios-app": { audiences: ["com.example.ios"] },
			device: { audiences: ["com.example.device"] },
		},
	},
	google: {
		clients: {
			"android-app": { audiences: ["srv"], "authorized-parties": ["android"] },
			"web-backend": { audiences: ["srv"] },
		},
	},
};

export const dpopKind = defineModule({ name: "dpop-kind", replicaSafe: true, takes: [] }, (m) => [
	m
		.contribute(senderBindings)
		.by(() => ({ member: "jkt", tokenType: "DPoP", read: async () => ({ kind: "absent" }) })),
]);
/** The id_tokens taken, in memory, fresh for each composition. */
/** The id_tokens taken in this store, so compositions can share one. */
export const usedIn = (used: UsedIdTokens) =>
	defineModule({ name: "used-id-tokens", replicaSafe: true, takes: [] }, (m) => [
		m.provide(usedIdTokens).by(() => used),
	]);
export const usedStandIn = defineModule(
	{ name: "used-id-tokens", replicaSafe: false, takes: [] },
	(m) => [m.provide(usedIdTokens).by(() => memoryUsedIdTokens().used)],
);

/** Alice's links, one through each kind the section takes, under the name it gives users: a link no module names refuses boot. */
export const linksFor = (section: unknown) =>
	(["apple", "google"] as const).flatMap((kind) => {
		const taken = (section as Record<string, { upstream?: string } | undefined>)[kind];
		return taken ? [{ idp: taken.upstream ?? kind, subject: `${kind}-sub` }] : [];
	});

/** The grant's assembly, with this section. */
export const assembly = (
	section: unknown,
	extra: readonly Module[] = [],
	used: Module = usedStandIn,
) => ({
	modules: [
		http,
		tokensStandIn(),
		issuerModule,
		clientsModule,
		secretHashModule,
		grantCaller,
		clientAllowanceModule,
		dpopKind,
		outboundModule,
		tlsOptionsForTests,
		externalJwtModule,
		used,
		subjectRevocationStandIn,
		usersModule,
		memoryUsersStores().module,
		tokenExchange,
		exchangeIdTokensOver(issuers),
		...extra,
	],
	config: {
		...kernelConfig(),
		...httpConfig(),
		...issuerConfig(),
		...clientsConfig([
			...["ios-app", "android-app", "web-backend"].map((id) =>
				confidentialClient({ id, sections: allowed }),
			),
			publicClient({
				id: "device",
				sections: { ...allowed, "token-exchange": { "public-exchange": true } },
			}),
		]),
		users: {
			registered: [testUser("alice", "pw", { subject: "acct-1", upstream: linksFor(section) })],
		},
		"exchange-id-tokens": section,
	},
	runtime,
});

export const boot = (section: unknown, extra: readonly Module[] = [], used?: Module) =>
	assemble(assembly(section, extra, used));

export async function serve(section: unknown = settings, used?: Module) {
	const app = await boot(section, [], used);
	const exchange = (client: string, idToken: string, binding?: Binding) =>
		app.get(grantCalls).call(
			grantType,
			client,
			{
				grant_type: grantType,
				subject_token: idToken,
				subject_token_type: idTokenType,
				scope: "read",
			},
			binding ? { binding } : {},
		);
	return { app, exchange };
}

export const appleClaims = (more: Record<string, unknown> = {}) => ({
	iss: "https://appleid.apple.com",
	sub: "apple-sub",
	aud: "com.example.ios",
	iat: now / 1000 - 10,
	exp: now / 1000 + 600,
	...more,
});
export const googleClaims = (more: Record<string, unknown> = {}) => ({
	iss: "https://accounts.google.com",
	sub: "google-sub",
	aud: "srv",
	azp: "android",
	iat: now / 1000 - 10,
	exp: now / 1000 + 600,
	...more,
});
export const said = (outcome: GrantOutcome) =>
	outcome.kind === "error" ? [outcome.error, outcome.description] : ["issued"];
export const failed = ["invalid_request", "subject_token validation failed"];
