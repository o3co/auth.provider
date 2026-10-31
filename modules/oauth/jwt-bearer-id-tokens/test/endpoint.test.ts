import { createHash, generateKeyPairSync, randomUUID } from "node:crypto";
import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientAssertion from "@mod/client-assertion/module";
import clientAssertionStore from "@mod/client-assertion-store/module";
import clientsModule from "@mod/clients/module";
import {
	clientSecret,
	clientsConfig,
	confidentialClient,
	publicClient,
} from "@mod/clients/testing";
import dpop from "@mod/dpop/module";
import dpopStore from "@mod/dpop-store/module";
import { type IdTokenChecks, idTokenChecks, usedIdTokens } from "@mod/exchange-id-tokens";
import { exchangeIdTokensOver, type Issuers } from "@mod/exchange-id-tokens/testing";
import exchangeIdTokensStore from "@mod/exchange-id-tokens-store/module";
import externalJwtModule from "@mod/external-jwt/module";
import { testSigner } from "@mod/external-jwt/testing";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import jwtBearer from "@mod/jwt-bearer/module";
import jwtBearerStore from "@mod/jwt-bearer-store/module";
import { assemble, type Contract, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import keysModule from "@mod/keys/module";
import { keysConfig } from "@mod/keys/testing";
import outboundModule from "@mod/outbound/module";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import secretHashModule from "@mod/secret-hash/module";
import senderBindingModule from "@mod/sender-binding/module";
import { type SimulatedStore, simulatedStore } from "@mod/store/testing";
import revocationModule from "@mod/subject-revocation/module";
import revocationStore from "@mod/subject-revocation-store/module";
import subjectTokens from "@mod/subject-tokens/module";
import { tlsOptionsForTests } from "@mod/tls-options/testing";
import tokenEndpoint from "@mod/token-endpoint/module";
import tokenExchange from "@mod/token-exchange/module";
import { type Tokens, tokens } from "@mod/tokens";
import tokensModule from "@mod/tokens/module";
import { tokensConfig } from "@mod/tokens/testing";
import tokensStore from "@mod/tokens-store/module";
import usersModule from "@mod/users/module";
import { memoryUsersStores, testUser } from "@mod/users/testing";
import { calculateJwkThumbprint, exportJWK, SignJWT } from "jose";
import { afterEach, describe, expect, it } from "vitest";
import bridge from "../src/module.ts";

/** The whole token endpoint over HTTP, with real DPoP, tokens and stores on a simulated store. */
const origin = "https://as.example";
const bearer = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const exchange = "urn:ietf:params:oauth:grant-type:token-exchange";
const appleIss = "https://appleid.apple.com";
const usedSpace = "exchange-id-tokens-store.used";
const second = 1000;
const minute = 60 * second;
const start = 1_800_000_000_000;
/** The kernel's clock, moved by hand; the simulated store's runs from it. */
const clock = { at: start };
const runtime = quietRuntime({
	clock: { now: () => clock.at },
	random: { bytes: (n) => new Uint8Array(n).map(() => Math.floor(Math.random() * 256)) },
});

const apple = await testSigner("RS256", "apple-1");
const issuers: Issuers = {
	apple: { iss: [appleIss], keys: { inline: [apple.jwk] } },
	google: { iss: ["https://accounts.google.com"], keys: { inline: [] } },
};
const allowed = allowancesFor({
	grants: [bearer, exchange],
	scopes: ["read"],
	"default-scopes": ["read"],
	audiences: ["https://api.example"],
});
const holder = generateKeyPairSync("ed25519");
const jkt = await calculateJwkThumbprint(await exportJWK(holder.publicKey));
const digest = createHash("sha256").update(jkt, "ascii").digest("base64url");

let stops: (() => Promise<void>)[] = [];
afterEach(async () => {
	await Promise.all(stops.map((stop) => stop()));
	stops = [];
	clock.at = start;
});

/** The tokens module, each access token it was asked to revoke kept, and how many it issued. */
function watchedTokens() {
	const revoked: string[] = [];
	const issued = { count: 0 };
	const module: Module = {
		...tokensModule,
		provides: (tokensModule.provides ?? []).map((part) =>
			part.contract !== tokens
				? part
				: {
						contract: part.contract,
						create: async (context: Parameters<typeof part.create>[0]) => {
							const real = (await part.create(context)) as Tokens;
							return {
								...real,
								issue: (...given: Parameters<Tokens["issue"]>) => {
									issued.count += 1;
									return real.issue(...given);
								},
								revokeAccess: (token: string) => {
									revoked.push(token);
									return real.revokeAccess(token);
								},
							};
						},
					},
		),
	};
	return { module, revoked, issued };
}

/** exchange-id-tokens, each check and each use of an id_token its contract was asked counted. */
function watchedChecks() {
	const asked = { checks: 0, consumes: 0 };
	const over = exchangeIdTokensOver(issuers);
	const module: Module = {
		...over,
		provides: (over.provides ?? []).map((part) =>
			part.contract !== idTokenChecks
				? part
				: {
						contract: part.contract,
						create: async (context: Parameters<typeof part.create>[0]) => {
							const real = (await part.create(context)) as IdTokenChecks;
							return {
								...real,
								check: (token: string) => {
									asked.checks += 1;
									return real.check(token);
								},
								consume: (token: string) => {
									asked.consumes += 1;
									return real.consume(token);
								},
							};
						},
					},
		),
	};
	return { module, asked };
}

/** A trusted issuer whose `client` is the bound phone: a request naming no client is taken for it. */
const agents = {
	issuer: "https://agents.example",
	subject: "as-is",
	keys: [
		{
			alg: "EdDSA",
			"public-key": generateKeyPairSync("ed25519")
				.publicKey.export({ format: "pem", type: "spki" })
				.toString(),
		},
	],
	conditions: { "subject-prefix": "org:acme/" },
	client: "bound-phone",
};

interface Served {
	readonly app: Awaited<ReturnType<typeof assemble>>;
	readonly store: SimulatedStore;
	/** Where the endpoint listens. */
	readonly base: string;
	readonly revoked: readonly string[];
	readonly issued: { readonly count: number };
	/** How often the id_tokens' contract was asked to check one, and to use one up. */
	readonly asked: { readonly checks: number; readonly consumes: number };
	bearer(
		client: string,
		idToken: string,
		headers?: Record<string, string>,
	): Promise<{ status: number; body: Record<string, unknown> }>;
	exchange(
		client: string,
		idToken: string,
	): Promise<{ status: number; body: Record<string, unknown> }>;
}

/** One instance of the deployment; a second on another's store shares its records. */
async function serve(
	settings: {
		maxAge?: string;
		on?: Served;
		/** Whether the bound phone, a trusted issuer's client, is registered beside the others. */
		bound?: true;
		/** Whether client assertions are composed too, with their store. */
		assertions?: true;
		/** Leaves `http`'s public origin unwritten: the issuer alone names this provider. */
		noPublicOrigin?: true;
	} = {},
): Promise<Served> {
	const store = settings.on?.store ?? simulatedStore();
	const shared = settings.on;
	// The store the simulated one provides, by its own handle: a feature names no capability.
	const provided = store.module.provides?.[0]?.contract as Contract<object>;
	const storeModule = shared
		? defineModule({ name: "store", replicaSafe: false, takes: [] }, (m) => [
				m.provide(provided).by(() => shared.app.get(provided)),
			])
		: store.module;
	const watched = watchedTokens();
	const checks = watchedChecks();
	const app = await assemble({
		modules: [
			http,
			keysModule,
			watched.module,
			tokensStore,
			issuerModule,
			senderBindingModule,
			dpop,
			dpopStore,
			clientsModule,
			secretHashModule,
			clientAllowanceModule,
			tokenEndpoint,
			rateLimitStandIn,
			auditStandIn().module,
			revocationModule,
			revocationStore,
			subjectTokens,
			storeModule,
			usersModule,
			memoryUsersStores().module,
			outboundModule,
			tlsOptionsForTests,
			externalJwtModule,
			tokenExchange,
			checks.module,
			exchangeIdTokensStore,
			jwtBearer,
			jwtBearerStore,
			bridge,
			...(settings.assertions ? [clientAssertion, clientAssertionStore] : []),
		],
		config: {
			...kernelConfig(),
			...httpConfig(settings.noPublicOrigin ? {} : { "public-origin": origin }),
			...keysConfig(),
			...issuerConfig({ url: origin }),
			...tokensConfig({ revocation: "denylist" }, { subjects: "checked" }),
			...clientsConfig([
				confidentialClient({ id: "app", sections: allowed }),
				confidentialClient({ id: "other", sections: allowed }),
				publicClient({ id: "phone", sections: allowed }),
				publicClient({
					id: "old-phone",
					sections: { ...allowed, "jwt-bearer": { "accept-unbound": true } },
				}),
				...(settings.bound
					? [
							publicClient({
								id: "bound-phone",
								sections: allowancesFor({ grants: [bearer], scopes: ["read"] }),
							}),
						]
					: []),
			]),
			users: {
				registered: [
					testUser("alice", "pw", {
						subject: "acct-1",
						upstream: [{ idp: "apple", subject: "apple-sub" }],
					}),
				],
			},
			"exchange-id-tokens": {
				"max-age": settings.maxAge ?? "10m",
				apple: {
					clients: {
						app: { audiences: ["com.example.app"] },
						phone: { audiences: ["com.example.phone"] },
						"old-phone": { audiences: ["com.example.old"] },
						...(settings.bound ? { "bound-phone": { audiences: ["com.example.bound"] } } : {}),
					},
				},
			},
			"jwt-bearer": { issuers: settings.bound ? [agents] : [], "delegated-issuers": [appleIss] },
		},
		runtime,
	});
	await app.start();
	stops.push(() => app.stop(1000));
	const base = `http://127.0.0.1:${app.get(listening).port()}`;
	const post = async (form: Record<string, string>, headers: Record<string, string> = {}) => {
		const res = await fetch(`${base}/oauth/token`, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
			body: new URLSearchParams(form),
		});
		return { status: res.status, body: (await res.json()) as Record<string, unknown> };
	};
	const credentials = (client: string) =>
		client === "app" || client === "other"
			? { client_id: client, client_secret: clientSecret(client) }
			: { client_id: client };
	return {
		app,
		store,
		base,
		revoked: watched.revoked,
		issued: watched.issued,
		asked: checks.asked,
		bearer: (client, idToken, headers = {}) =>
			post({ grant_type: bearer, assertion: idToken, ...credentials(client) }, headers),
		exchange: (client, idToken) =>
			post({
				grant_type: exchange,
				subject_token: idToken,
				subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
				scope: "read",
				...credentials(client),
			}),
	};
}

/** Seconds since the epoch on the kernel's clock. */
const nowS = () => Math.floor(clock.at / 1000);
const idToken = (aud: string, more: Record<string, unknown> = {}) =>
	apple.sign({
		iss: appleIss,
		sub: "apple-sub",
		aud,
		iat: nowS() - 10,
		exp: nowS() + 600,
		n: randomUUID(),
		...more,
	});
/** The name the record keeps an id_token under. */
const nameOf = (token: string) =>
	createHash("sha256").update(token.split(".").slice(0, 2).join(".")).digest("base64url");
/** A DPoP proof for the token endpoint, by this key. */
const proof = async (key = holder) =>
	new SignJWT({ htm: "POST", htu: `${origin}/oauth/token`, iat: nowS(), jti: randomUUID() })
		.setProtectedHeader({ alg: "EdDSA", typ: "dpop+jwt", jwk: await exportJWK(key.publicKey) })
		.sign(key.privateKey);
const said = (r: { status: number; body: Record<string, unknown> }) =>
	r.status === 200
		? `200 ${String(r.body.token_type)}`
		: `${r.status} ${String(r.body.error)}: ${String(r.body.error_description)}`;
const refusedKey = "400 invalid_grant: the request does not prove the key the assertion names";
const replayed = "400 invalid_grant: assertion replayed";
const exchangeUsed = "400 invalid_request: subject_token has been used";

it("refuses to boot without a public origin at jwt-bearer and client-assertion, though the token endpoint names its location on the issuer's origin", async () => {
	await serve({ assertions: true });
	const refused = await serve({ assertions: true, noPublicOrigin: true }).catch((error) => error);
	expect(refused.refusals).toEqual(
		expect.arrayContaining([
			{ where: "jwt-bearer", reason: "the token endpoint's location needs a public origin" },
			{ where: "client-assertion", reason: "the token endpoint's location needs a public origin" },
		]),
	);
});

describe("the JWT bearer grant over the whole token endpoint, for id_tokens", () => {
	it("binds a public app's token to the key its id_token names, proved by real DPoP; leaving out or changing the proof never gets one [rfc9449-5-b]", async () => {
		const s = await serve();
		const bound = await idToken("com.example.phone", { nonce: digest });
		expect(said(await s.bearer("phone", bound))).toBe(refusedKey);
		const other = generateKeyPairSync("ed25519");
		expect(said(await s.bearer("phone", bound, { dpop: await proof(other) }))).toBe(refusedKey);
		const taken = await s.bearer("phone", bound, { dpop: await proof() });
		expect(said(taken)).toBe("200 DPoP");
		// Bound to that key: its confirmation is the key's thumbprint.
		const checked = await s.app.get(tokens).verifyAccess(String(taken.body.access_token));
		expect(checked).toMatchObject({ kind: "valid", binding: { member: "jkt", confirmation: jkt } });
		const unbound = await idToken("com.example.phone");
		expect(said(await s.bearer("phone", unbound, { dpop: await proof() }))).toBe(refusedKey);
	});

	it("with accept-unbound, takes an app's id_token naming no key as a bearer token, and still proves one naming a key", async () => {
		const s = await serve();
		expect(said(await s.bearer("old-phone", await idToken("com.example.old")))).toBe("200 Bearer");
		const bound = await idToken("com.example.old", { nonce: digest });
		expect(said(await s.bearer("old-phone", bound))).toBe(refusedKey);
		expect(said(await s.bearer("old-phone", bound, { dpop: await proof() }))).toBe("200 DPoP");
	});

	it("refuses an id_token another client presents", async () => {
		const s = await serve();
		const token = await idToken("com.example.app");
		expect(said(await s.bearer("other", token))).toBe(
			"400 invalid_grant: assertion is for another client",
		);
		expect(said(await s.bearer("app", token))).toBe("200 Bearer");
	});

	it("refuses a trusted issuer's client an id_token its delegate names it in, asking the delegate nothing", async () => {
		const s = await serve({ bound: true });
		// Valid or expired, named by its client_id: the delegate neither checks it nor uses it up.
		for (const token of [
			await idToken("com.example.bound"),
			await idToken("com.example.bound", { exp: nowS() - 600 }),
		]) {
			expect(said(await s.bearer("bound-phone", token))).toBe(
				"400 invalid_grant: assertion is for another client",
			);
		}
		// Naming no client, a delegated issuer's id_token identifies none.
		const res = await fetch(`${s.base}/oauth/token`, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				grant_type: bearer,
				assertion: await idToken("com.example.bound"),
			}),
		});
		expect([res.status, await res.json()]).toEqual([
			400,
			{ error: "invalid_grant", error_description: "untrusted signer" },
		]);
		expect(s.asked).toEqual({ checks: 0, consumes: 0 });
		expect(said(await s.bearer("app", await idToken("com.example.app")))).toBe("200 Bearer");
		expect(s.asked).toEqual({ checks: 1, consumes: 1 });
	});

	describe("one id_token sent to both grants at once", () => {
		it("is taken by either grant alone", async () => {
			const s = await serve();
			expect(said(await s.bearer("app", await idToken("com.example.app")))).toBe("200 Bearer");
			expect(said(await s.exchange("app", await idToken("com.example.app")))).toBe("200 Bearer");
		});

		it("gives the exchange's token back when the JWT bearer grant uses it up first, between the exchange's issuing and its use", async () => {
			const s = await serve();
			const token = await idToken("com.example.app");
			let first: { status: number; body: Record<string, unknown> } | undefined;
			// Held at the exchange's write of the record, after it issued: the other grant goes first.
			s.store.beforeNext("putIfAbsent", usedSpace, async () => {
				first = await s.bearer("app", token);
			});
			const late = await s.exchange("app", token);
			expect(first && said(first)).toBe("200 Bearer");
			expect(said(late)).toBe(exchangeUsed);
			// The token the exchange issued is revoked, never handed out.
			expect(s.revoked).toHaveLength(1);
			const withdrawn = await s.app.get(tokens).verifyAccess(s.revoked[0] as string);
			expect(withdrawn.kind).toBe("invalid");
		});

		it("issues nothing for the JWT bearer grant when the exchange uses it up first", async () => {
			const s = await serve();
			const token = await idToken("com.example.app");
			let first: { status: number; body: Record<string, unknown> } | undefined;
			// Held at the JWT bearer grant's write of the record, before it issues: the exchange goes first.
			s.store.beforeNext("putIfAbsent", usedSpace, async () => {
				first = await s.exchange("app", token);
			});
			const late = await s.bearer("app", token);
			expect(first && said(first)).toBe("200 Bearer");
			expect(said(late)).toBe(replayed);
			// The exchange's token alone: the JWT bearer grant issued none and revoked none.
			expect(s.issued.count).toBe(1);
			expect(s.revoked).toEqual([]);
		});
	});

	it("keeps a record to an hour past its iat, the longest skew and a minute, whatever max-age is", async () => {
		const s = await serve();
		// Ending past the hour: kept to `iat` + 1h + 5m + 1m.
		const token = await idToken("com.example.app", { exp: nowS() + 86_400 });
		expect(said(await s.bearer("app", token))).toBe("200 Bearer");
		// The store's clock alone moves, so the id_token stays young enough here and the record decides.
		const kept = 66 * minute - 10 * second;
		s.store.shiftClock(kept - 1);
		expect(said(await s.bearer("app", token))).toBe(replayed);
		s.store.shiftClock(2);
		expect(said(await s.bearer("app", token))).toBe("200 Bearer");
	});

	it("takes an id_token up to max-age and the skew past its iat, and a second before its exp, and no later", async () => {
		const s = await serve();
		const issued = nowS() - 10;
		const young = await idToken("com.example.app", { iat: issued, exp: issued + 3600 });
		const older = await idToken("com.example.app", { iat: issued, exp: issued + 3600 });
		// Taken while `now - iat` is no more than max-age (10m) and the skew (30s).
		clock.at = issued * 1000 + 10 * minute + 30 * second;
		expect(said(await s.bearer("app", young))).toBe("200 Bearer");
		clock.at += 1;
		expect(said(await s.bearer("app", older))).toBe("400 invalid_grant: untrusted signer");
		clock.at = start;
		const ending = nowS() + 120;
		const short = await idToken("com.example.app", { exp: ending });
		const shorter = await idToken("com.example.app", { exp: ending });
		clock.at = ending * 1000 - second;
		expect(said(await s.bearer("app", short))).toBe("200 Bearer");
		clock.at += 1;
		expect(said(await s.bearer("app", shorter))).toBe("400 invalid_grant: expired");
	});

	it("hands out no token the time of its spend left without life, though two seconds were left before it", async () => {
		const s = await serve();
		const token = await idToken("com.example.app", { exp: nowS() + 2 });
		// Two seconds pass at the write of the record, after the second left was asked.
		s.store.beforeNext("putIfAbsent", usedSpace, async () => {
			clock.at += 2 * second;
		});
		expect(said(await s.bearer("app", token))).toBe("400 invalid_grant: expired");
		// Used up still: its record holds it, so writing it again finds it.
		expect(await s.app.get(usedIdTokens).save("apple", nameOf(token), minute)).toBe("exists");
	});

	it("never takes again an id_token this version kept once max-age widens to an hour, but takes one an earlier version kept", async () => {
		const narrow = await serve({ maxAge: "10m" });
		const issued = nowS() - 10;
		const kept = await idToken("com.example.app", { iat: issued, exp: issued + 3600 });
		expect(said(await narrow.bearer("app", kept))).toBe("200 Bearer");
		const earlier = await idToken("com.example.app", { iat: issued, exp: issued + 3600 });
		// As an earlier version kept it: to `iat` and max-age (10m), then the 30s skew and a minute.
		const life = (issued + 600) * 1000 + 90 * second - clock.at;
		await narrow.app.get(usedIdTokens).save("apple", nameOf(earlier), life);
		expect(said(await narrow.bearer("app", earlier))).toBe(replayed);
		// Half an hour on, another instance on the same store takes id_tokens up to an hour old.
		clock.at += 30 * minute;
		const wide = await serve({ maxAge: "1h", on: narrow });
		expect(said(await narrow.bearer("app", kept))).toBe("400 invalid_grant: untrusted signer");
		expect(said(await wide.bearer("app", kept))).toBe(replayed);
		// The earlier version's record has gone, so the widened instance takes it again: why widening waits.
		expect(said(await wide.bearer("app", earlier))).toBe("200 Bearer");
		// Its own bound: max-age (1h) and the skew past `iat`, and not a moment after.
		const fresh = await idToken("com.example.app", { iat: issued, exp: issued + 7200 });
		const later = await idToken("com.example.app", { iat: issued, exp: issued + 7200 });
		clock.at = issued * 1000 + 60 * minute + 30 * second;
		expect(said(await wide.bearer("app", fresh))).toBe("200 Bearer");
		clock.at += 1;
		expect(said(await wide.bearer("app", later))).toBe("400 invalid_grant: untrusted signer");
	});

	it("answers unavailable while the record cannot be written, leaving the id_token usable", async () => {
		const s = await serve();
		const token = await idToken("com.example.app");
		s.store.failWrites(true);
		expect((await s.bearer("app", token)).status).toBe(503);
		s.store.failWrites(false);
		expect(said(await s.bearer("app", token))).toBe("200 Bearer");
	}, 30_000);

	it("answers unavailable when the record is written but never confirmed, and replayed once the store is back", async () => {
		const s = await serve();
		const token = await idToken("com.example.app");
		// Written on the primary, then no replica takes it: every try fails until its deadline.
		s.store.beforeConfirm("putIfAbsent", usedSpace, async () => {
			s.store.stallReplicas(true);
		});
		expect((await s.bearer("app", token)).status).toBe(503);
		s.store.stallReplicas(false);
		expect(said(await s.bearer("app", token))).toBe(replayed);
		expect(said(await s.exchange("app", token))).toBe(exchangeUsed);
	}, 30_000);

	it("settles a write whose answer is lost to one token, then replayed", async () => {
		const s = await serve();
		const token = await idToken("com.example.app");
		s.store.loseNextReply();
		expect(said(await s.bearer("app", token))).toBe("200 Bearer");
		expect(said(await s.bearer("app", token))).toBe(replayed);
	});
});
