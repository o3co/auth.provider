import { createHash } from "node:crypto";
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
import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	kernelConfig,
	type Module,
} from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import outboundModule from "@mod/outbound/module";
import { lineage } from "@mod/refresh";
import { type Binding, senderBindings } from "@mod/sender-binding";
import { sessions } from "@mod/session";
import { stubSessions } from "@mod/session/testing";
import { sessionTokens } from "@mod/session-tokens";
import { type Space, spaces } from "@mod/store";
import storeModule from "@mod/store/module";
import { storeConfig } from "@mod/store/testing";
import { revocations } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { grantCaller, grantCalls } from "@mod/token-endpoint/testing";
import tokenExchange from "@mod/token-exchange/module";
import { tokens } from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { upstreamNames } from "@mod/users";
import usersModule from "@mod/users/module";
import { memoryUsersStores, testUser } from "@mod/users/testing";
import { describe, expect, it } from "vitest";
import { exchangeIdTokensOver, type Issuers } from "../src/testing.ts";

const now = 1_800_000_000_000;
const clock = { at: now };
const runtime = quietRuntime({
	clock: { now: () => clock.at },
	random: { bytes: (n) => new Uint8Array(n).map(() => Math.floor(Math.random() * 256)) },
});
const grantType = "urn:ietf:params:oauth:grant-type:token-exchange";
const idTokenType = "urn:ietf:params:oauth:token-type:id_token";
const api = "https://api.example";

const apple = await testSigner("RS256", "apple-1");
const google = await testSigner("RS256", "google-1");
const stranger = await testSigner("RS256", "google-1");
/** A key the issuer's set holds, for an algorithm never taken. */
const elliptic = await testSigner("ES256", "google-es");
const issuers: Issuers = {
	apple: { iss: ["https://appleid.apple.com"], keys: { inline: [apple.jwk] } },
	google: {
		iss: ["https://accounts.google.com", "accounts.google.com"],
		keys: { inline: [google.jwk, elliptic.jwk] },
	},
};

const allowed = allowancesFor({ grants: [grantType], scopes: ["read"], audiences: [api] });
const settings = {
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

/** No family and no session for any token: an id_token has neither. */
const untied = defineModule({ name: "untied" }, (m) => [
	m.provide(lineage).by(() => ({
		of: async () => ({ kind: "none" }),
		adopt: async () => "adopted",
		start: async () => undefined,
	})),
	m.provide(sessions).by(() => stubSessions({ stillOpen: async () => true })),
	m.provide(sessionTokens).by(() => ({ sessionOf: async () => ({ kind: "unbound" }) })),
]);
const dpopKind = defineModule({ name: "dpop-kind" }, (m) => [
	m
		.contribute(senderBindings)
		.by(() => ({ member: "jkt", tokenType: "DPoP", read: async () => ({ kind: "absent" }) })),
]);
const collectedSpaces = contract<readonly Space[]>("test.spaces");
const spaceCollector = defineModule({ name: "space-collector" }, (m) => [
	m.provide(collectedSpaces).by((c) => c.collect(spaces)),
]);

/** Alice's links, one through each kind the section takes, under the name it gives users: a link no module names refuses boot. */
const linksFor = (section: unknown) =>
	(["apple", "google"] as const).flatMap((kind) => {
		const taken = (section as Record<string, { upstream?: string } | undefined>)[kind];
		return taken ? [{ idp: taken.upstream ?? kind, subject: `${kind}-sub` }] : [];
	});

const boot = (section: unknown, extra: readonly Module[] = []) =>
	assemble({
		modules: [
			http,
			tokensStandIn(),
			issuerModule,
			clientsModule,
			grantCaller,
			clientAllowanceModule,
			untied,
			dpopKind,
			outboundModule,
			externalJwtModule,
			storeModule,
			subjectRevocationStandIn,
			usersModule,
			memoryUsersStores().module,
			tokenExchange,
			exchangeIdTokensOver(issuers),
			spaceCollector,
			...extra,
		],
		config: {
			...kernelConfig(),
			...httpConfig(),
			...issuerConfig(),
			...storeConfig(),
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

async function serve(section: unknown = settings) {
	const app = await boot(section);
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

const appleClaims = (more: Record<string, unknown> = {}) => ({
	iss: "https://appleid.apple.com",
	sub: "apple-sub",
	aud: "com.example.ios",
	iat: now / 1000 - 10,
	exp: now / 1000 + 600,
	...more,
});
const googleClaims = (more: Record<string, unknown> = {}) => ({
	iss: "https://accounts.google.com",
	sub: "google-sub",
	aud: "srv",
	azp: "android",
	iat: now / 1000 - 10,
	exp: now / 1000 + 600,
	...more,
});
const said = (outcome: GrantOutcome) =>
	outcome.kind === "error" ? [outcome.error, outcome.description] : ["issued"];
const failed = ["invalid_request", "subject_token validation failed"];

describe("exchange-id-tokens", () => {
	it("exchanges Apple's and Google's id_tokens for a token of the account users links them to", async () => {
		const s = await serve();
		for (const [client, token] of [
			["ios-app", await apple.sign(appleClaims())],
			["android-app", await google.sign(googleClaims())],
			["android-app", await google.sign(googleClaims({ iss: "accounts.google.com" }))],
			["web-backend", await google.sign(googleClaims({ azp: undefined }))],
			["web-backend", await google.sign(googleClaims({ azp: "srv" }))],
		] as const) {
			const outcome = await s.exchange(client, token);
			if (outcome.kind !== "issued") throw new Error(`${client}: ${said(outcome).join(": ")}`);
			const checked = await s.app.get(tokens).verifyAccess(String(outcome.body.access_token));
			expect(checked).toMatchObject({
				kind: "valid",
				grant: { subject: "acct-1", issuedTo: client, scope: ["read"], audience: [api] },
			});
			if (checked.kind === "valid") expect(checked.expiresAt).toBeLessThanOrEqual(now + 600_000);
		}
	});

	it("takes an id_token once", async () => {
		const s = await serve();
		const claims = appleClaims();
		expect(said(await s.exchange("ios-app", await apple.sign(claims)))).toEqual(["issued"]);
		const used = ["invalid_request", "subject_token has been used"];
		expect(said(await s.exchange("ios-app", await apple.sign(claims)))).toEqual(used);
	});

	it("leaves an id_token unused when the exchange is refused", async () => {
		const s = await serve();
		const token = await apple.sign(appleClaims());
		expect(said(await s.exchange("web-backend", token))[0]).toBe("invalid_request");
		expect(said(await s.exchange("ios-app", token))).toEqual(["issued"]);
	});

	it("lets only the client whose audience and party it names exchange it", async () => {
		const s = await serve();
		const notThisClient = ["invalid_request", "subject_token does not name this client"];
		expect(said(await s.exchange("web-backend", await apple.sign(appleClaims())))).toEqual(
			notThisClient,
		);
		for (const claims of [
			appleClaims({ aud: "com.example.other" }),
			googleClaims({ azp: "web" }),
			googleClaims({ aud: "srv", azp: "other-srv" }),
			appleClaims({ aud: ["com.example.ios", "com.example.device"] }),
		]) {
			const signer = claims.iss.includes("apple") ? apple : google;
			const client = claims.iss.includes("apple") ? "ios-app" : "android-app";
			expect(
				said(await s.exchange(client, await signer.sign(claims))),
				JSON.stringify(claims),
			).toEqual(failed);
		}
	});

	it("refuses another issuer, another algorithm, an unknown key, and an id_token without iat, too old or from the future", async () => {
		const s = await serve();
		for (const token of [
			await apple.sign(appleClaims({ iss: "https://idp.example" })),
			await elliptic.sign(googleClaims()),
			await stranger.sign(googleClaims()),
			await apple.sign(appleClaims({ iat: undefined })),
			await apple.sign(appleClaims({ iat: now / 1000 - 631 })),
			await apple.sign(appleClaims({ iat: now / 1000 + 120 })),
		]) {
			expect(said(await s.exchange("ios-app", token))).toEqual(failed);
		}
		expect(
			said(await s.exchange("ios-app", await apple.sign(appleClaims({ iat: now / 1000 - 620 })))),
		).toEqual(["issued"]);
	});

	it("refuses an upstream subject users links to no one, and an id_token from before the subject's revocation", async () => {
		const s = await serve();
		expect(
			said(await s.exchange("ios-app", await apple.sign(appleClaims({ sub: "nobody" })))),
		).toEqual(failed);
		clock.at = now + 1000;
		try {
			await s.app.get(revocations).record("acct-1");
			expect(said(await s.exchange("ios-app", await apple.sign(appleClaims())))).toEqual(failed);
			const after = await apple.sign(appleClaims({ iat: now / 1000 + 2 }));
			clock.at = now + 3000;
			expect(said(await s.exchange("ios-app", after))).toEqual(["issued"]);
		} finally {
			clock.at = now;
		}
	});

	it("lets the public client exchange only when the nonce is the digest of the key it proves by DPoP", async () => {
		const s = await serve();
		const jkt = "thumbprint-of-the-device-key";
		const nonce = createHash("sha256").update(jkt, "ascii").digest("base64url");
		const bound: Binding = { member: "jkt", confirmation: jkt, tokenType: "DPoP" };
		const claims = appleClaims({ aud: "com.example.device", nonce });
		const other = { ...bound, confirmation: "another-key" };
		expect(said(await s.exchange("device", await apple.sign(claims), other))).toEqual([
			"invalid_request",
			"the request does not prove the key the subject token names",
		]);
		const outcome = await s.exchange("device", await apple.sign(claims), bound);
		expect(outcome).toMatchObject({ kind: "issued", body: { token_type: "DPoP" } });
	});

	it("contributes its space whenever it is composed", async () => {
		const s = await serve({ google: settings.google });
		expect(s.app.get(collectedSpaces).map((space) => space.name)).toContain(
			"exchange-id-tokens.used",
		);
	});

	it("refuses to start with no upstream, two clients taking one pair, an unregistered client, or a key set or issuer of its own", async () => {
		for (const [section, where] of [
			[{}, "exchange-id-tokens"],
			[
				{
					google: {
						clients: {
							"android-app": { audiences: ["srv"] },
							"web-backend": { audiences: ["srv"] },
						},
					},
				},
				"exchange-id-tokens.google.clients.web-backend",
			],
			[
				{ apple: { clients: { unknown: { audiences: ["a"] } } } },
				"exchange-id-tokens.apple.clients.unknown",
			],
			[{ ...settings, "jwks-uri": "https://keys.example" }, "exchange-id-tokens"],
			[{ apple: { ...settings.apple, issuer: "https://idp.example" } }, "exchange-id-tokens.apple"],
		] as const) {
			const error = await boot(section).then(
				() => undefined,
				(e: unknown) => e,
			);
			expect(error, JSON.stringify(section)).toBeInstanceOf(BootRefused);
			expect(
				(error as BootRefused).refusals.map((r) => r.where),
				JSON.stringify(section),
			).toEqual([where]);
		}
	});

	it("tells users each upstream name it takes, with its issuer, so another module's same name refuses boot unless the issuer is the same", async () => {
		const naming = (issuer: string) =>
			defineModule({ name: "federation-like" }, (m) => [
				m.contribute(upstreamNames).by(() => ({
					declaredBy: "federation-like",
					names: [{ name: "google", issuer }],
				})),
			]);
		await expect(boot(settings, [naming("https://accounts.google.com")])).resolves.toBeDefined();
		const refused = await boot(settings, [naming("https://idp.example")]).then(
			() => undefined,
			(e: unknown) => e,
		);
		expect(refused).toBeInstanceOf(BootRefused);
		expect(JSON.stringify((refused as BootRefused).refusals)).toContain("google");
		await expect(
			boot({ google: { ...settings.google, upstream: "work" } }, [naming("https://idp.example")]),
		).resolves.toBeDefined();
	});
});
