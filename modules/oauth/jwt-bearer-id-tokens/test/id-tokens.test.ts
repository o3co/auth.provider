import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientsModule from "@mod/clients/module";
import { clientsConfig, confidentialClient } from "@mod/clients/testing";
import { usedIdTokens } from "@mod/exchange-id-tokens";
import { exchangeIdTokensOver, type Issuers } from "@mod/exchange-id-tokens/testing";
import externalJwtModule from "@mod/external-jwt/module";
import { testSigner } from "@mod/external-jwt/testing";
import type { GrantOutcome } from "@mod/grants";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { spentAssertions } from "@mod/jwt-bearer";
import jwtBearer from "@mod/jwt-bearer/module";
import { assemble, BootRefused, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import outboundModule from "@mod/outbound/module";
import secretHashModule from "@mod/secret-hash/module";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { tokenEndpointLocation } from "@mod/token-endpoint";
import { grantCaller, grantCalls } from "@mod/token-endpoint/testing";
import tokenExchange from "@mod/token-exchange/module";
import { tokens } from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import usersModule from "@mod/users/module";
import { memoryUsersStores, testUser } from "@mod/users/testing";
import { describe, expect, it } from "vitest";
import bridge from "../src/module.ts";

const now = 1_800_000_000_000;
const runtime = quietRuntime({
	clock: { now: () => now },
	random: { bytes: (n) => new Uint8Array(n).map(() => Math.floor(Math.random() * 256)) },
});
const issuer = "https://as.example";
const bearer = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const exchange = "urn:ietf:params:oauth:grant-type:token-exchange";
const idTokenType = "urn:ietf:params:oauth:token-type:id_token";
const appleIss = "https://appleid.apple.com";
const googleIss = ["https://accounts.google.com", "accounts.google.com"];

const apple = await testSigner("RS256", "apple-1");
const google = await testSigner("RS256", "google-1");
const issuers: Issuers = {
	apple: { iss: [appleIss], keys: { inline: [apple.jwk] } },
	google: {
		iss: ["https://accounts.google.com", "accounts.google.com"],
		keys: { inline: [google.jwk] },
	},
};
const settings = {
	apple: { clients: { "ios-app": { audiences: ["com.example.ios"] } } },
	google: { clients: { "android-app": { audiences: ["srv"], "authorized-parties": ["android"] } } },
};
const allowed = allowancesFor({
	grants: [bearer, exchange],
	scopes: ["read"],
	"default-scopes": ["read"],
});

/** Both records in memory, fresh for each composition. */
const records = defineModule({ name: "records-in-memory", replicaSafe: false, takes: [] }, (m) => {
	const held =
		(kept = new Set<string>()) =>
		async (name: string): Promise<"created" | "exists"> => {
			if (kept.has(name)) return "exists";
			kept.add(name);
			return "created";
		};
	return [
		m.provide(spentAssertions).by(() => ({ save: held() })),
		m.provide(usedIdTokens).by(() => {
			const save = held();
			return { save: (kind: string, name: string) => save(`${kind}/${name}`) };
		}),
		m.provide(tokenEndpointLocation).by(() => ({ url: `${issuer}/oauth/token` })),
	];
});

function assembly(
	section: Partial<typeof settings> = settings,
	delegated: readonly string[] = [appleIss, ...googleIss],
) {
	return {
		modules: [
			http,
			tokensStandIn(),
			issuerModule,
			clientsModule,
			secretHashModule,
			grantCaller,
			clientAllowanceModule,
			outboundModule,
			externalJwtModule,
			subjectRevocationStandIn,
			usersModule,
			memoryUsersStores().module,
			records,
			tokenExchange,
			exchangeIdTokensOver(issuers),
			jwtBearer,
			bridge,
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": new URL(issuer).origin }),
			...issuerConfig({ url: issuer }),
			...clientsConfig(
				["ios-app", "android-app"].map((id) => confidentialClient({ id, sections: allowed })),
			),
			users: {
				registered: [
					testUser("alice", "pw", {
						subject: "acct-1",
						// A link no module names refuses boot: one through each kind the section takes.
						upstream: (["apple", "google"] as const)
							.filter((kind) => kind in section)
							.map((kind) => ({ idp: kind, subject: `${kind}-sub` })),
					}),
				],
			},
			"exchange-id-tokens": section,
			"jwt-bearer": { issuers: [], "delegated-issuers": delegated },
		},
		runtime,
	};
}

async function serve() {
	const app = await assemble(assembly());
	const calls = app.get(grantCalls);
	return {
		app,
		bearer: (client: string, idToken: string) =>
			calls.call(bearer, client, { grant_type: bearer, assertion: idToken }),
		exchange: (client: string, idToken: string) =>
			calls.call(exchange, client, {
				grant_type: exchange,
				subject_token: idToken,
				subject_token_type: idTokenType,
				scope: "read",
			}),
	};
}

const appleToken = (more: Record<string, unknown> = {}) =>
	apple.sign({
		iss: appleIss,
		sub: "apple-sub",
		aud: "com.example.ios",
		iat: now / 1000 - 10,
		exp: now / 1000 + 600,
		n: Math.random(),
		...more,
	});
const googleToken = (more: Record<string, unknown> = {}) =>
	google.sign({
		iss: "https://accounts.google.com",
		sub: "google-sub",
		aud: "srv",
		azp: "android",
		iat: now / 1000 - 10,
		exp: now / 1000 + 600,
		n: Math.random(),
		...more,
	});
const said = (outcome: GrantOutcome) =>
	outcome.kind === "error" ? `${outcome.error}: ${outcome.description}` : "issued";

describe("jwt-bearer-id-tokens", () => {
	it("takes Apple's and Google's id_tokens as assertions, for the account and the one client each is for", async () => {
		const s = await serve();
		for (const [client, token] of [
			["ios-app", await appleToken()],
			["android-app", await googleToken()],
			["android-app", await googleToken({ iss: "accounts.google.com" })],
		] as const) {
			const outcome = await s.bearer(client, token);
			if (outcome.kind !== "issued") throw new Error(`${client}: ${said(outcome)}`);
			expect(await s.app.get(tokens).verifyAccess(String(outcome.body.access_token))).toMatchObject(
				{ kind: "valid", grant: { subject: "acct-1", issuedTo: client } },
			);
			expect(said(await s.bearer(client, token))).toBe("invalid_grant: assertion replayed");
		}
	});

	it("takes an id_token once across both grants, each answering in its own words", async () => {
		const s = await serve();
		const first = await appleToken();
		expect(said(await s.exchange("ios-app", first))).toBe("issued");
		expect(said(await s.bearer("ios-app", first))).toBe("invalid_grant: assertion replayed");
		const second = await appleToken();
		expect(said(await s.bearer("ios-app", second))).toBe("issued");
		expect(said(await s.exchange("ios-app", second))).toBe(
			"invalid_request: subject_token has been used",
		);
	});

	it("refuses an id_token for another client, and one exchange-id-tokens does not take, leaving it usable", async () => {
		const s = await serve();
		const token = await appleToken();
		expect(said(await s.bearer("android-app", token))).toBe(
			"invalid_grant: assertion is for another client",
		);
		expect(said(await s.bearer("ios-app", await appleToken({ aud: "com.example.other" })))).toBe(
			"invalid_grant: untrusted signer",
		);
		expect(said(await s.bearer("ios-app", token))).toBe("issued");
	});

	it("delegates each issuer of the kinds taken, and refuses boot on one not named or named and not taken", async () => {
		const refusalsOf = (...given: Parameters<typeof assembly>) =>
			assemble(assembly(...given)).then(
				() => [],
				(error: unknown) => (error instanceof BootRefused ? error.refusals : Promise.reject(error)),
			);
		expect(await refusalsOf(settings, [appleIss])).toEqual([
			expect.objectContaining({ where: "jwt-bearer.delegated-issuers" }),
		]);
		expect(await refusalsOf({ apple: settings.apple }, [appleIss, ...googleIss])).toEqual([
			{
				where: "jwt-bearer.delegated-issuers.1",
				reason: "no module checks this issuer's assertions",
			},
			{
				where: "jwt-bearer.delegated-issuers.2",
				reason: "no module checks this issuer's assertions",
			},
		]);
		expect(await refusalsOf({ apple: settings.apple }, [appleIss])).toEqual([]);
	});

	it("takes all it names", async () => {
		expect((await takesUnused(assembly()))["jwt-bearer-id-tokens"]).toBeUndefined();
	});
});
