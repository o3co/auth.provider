import { createHash } from "node:crypto";
import { externalJwt } from "@mod/external-jwt";
import externalJwtModule from "@mod/external-jwt/module";
import { testSigner } from "@mod/external-jwt/testing";
import { assemble, defineModule, isUnavailable, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import {
	type Narrower,
	type Outbound,
	type OutboundRequest,
	type OutboundResponse,
	outbound,
} from "@mod/outbound";
import { outboundOver, section as outboundSection } from "@mod/outbound/module";
import type { OutboundRefusals } from "@mod/outbound-policy";
import { type AuthorizationStart, type CodeExchange, UpstreamRefused } from "@mod/upstreams";
import { beforeAll, describe, expect, it } from "vitest";
import { settingsOf } from "../src/settings.ts";
import { issuer, opened } from "../src/upstream.ts";

const base = "https://google.test";
const endpoints = {
	"authorization-endpoint": `${base}/auth`,
	// A host of its own, so that the exchange is seen narrowed to it alone.
	"token-endpoint": "https://token.google.test/token",
	"jwks-uri": `${base}/certs`,
};
const now = 1_800_000_000_000;
const seconds = Math.floor(now / 1000);
const clock = { now: () => now };
const runtime = quietRuntime({ clock, random: { bytes: (length) => new Uint8Array(length) } });

/** What the destination policy was asked at boot. */
const policyAsked: { url: string; narrower: Narrower | undefined }[] = [];
/** How outbound explains a host its allow list leaves out. */
const notAllowed = "not-allowed: name the host in outbound.allow, or set outbound.allow-any-public";
/** A destination policy refusing the `refused` hosts as not allowed. */
const policyRefusing = (refused: readonly string[] = []): OutboundRefusals => ({
	explained: (url, narrower) => {
		policyAsked.push({ url, narrower });
		return refused.includes(new URL(url).hostname) ? notAllowed : undefined;
	},
});
const settings = settingsOf(policyRefusing());

type Handler = (
	request: OutboundRequest,
) => Promise<OutboundResponse | "unreachable"> | "unreachable";
const answer = (json: unknown, status = 200, headers: [string, string][] = []) => ({
	status,
	headers: new Map(headers),
	body: new TextEncoder().encode(JSON.stringify(json)),
});

type Signer = Awaited<ReturnType<typeof testSigner>>;
let google: Signer;
let stranger: Signer;
let elliptic: Signer;
beforeAll(async () => {
	google = await testSigner("RS256", "g1");
	// Another key under the same kid, never published: its signature does not hold.
	stranger = await testSigner("RS256", "g1");
	elliptic = await testSigner("ES256", "e1");
});

/** An id_token Google would issue for the login, with `more` (undefined leaves a claim out). */
const idToken = (more: Record<string, unknown> = {}, key = google) =>
	key.sign(
		Object.fromEntries(
			Object.entries({
				iss: issuer,
				sub: "g-alice",
				aud: "client",
				nonce: "n",
				iat: seconds,
				exp: seconds + 300,
				...more,
			}).filter(([, value]) => value !== undefined),
		),
	);

async function open(world: { token?: Handler; settings?: Record<string, unknown> } = {}) {
	const token = world.token ?? (async () => answer({}));
	const asked: { url: string; request: OutboundRequest; hosts?: readonly string[] }[] = [];
	const stub: Outbound = {
		fetch: async (url, request = {}, narrower = {}) => {
			asked.push({ url, request, ...(narrower.hosts ? { hosts: narrower.hosts } : {}) });
			const found =
				url === endpoints["jwks-uri"]
					? answer({ keys: [google.jwk, elliptic.jwk] })
					: url === endpoints["token-endpoint"]
						? await token(request)
						: answer({}, 404);
			if (found === "unreachable") throw new Unavailable("stub");
			return found;
		},
	};
	const app = await assemble({
		modules: [
			defineModule({ name: "outbound", replicaSafe: false, takes: [] }, (m) => [
				m.provide(outbound).by(() => stub),
			]),
			externalJwtModule,
		],
		config: kernelConfig(),
		runtime,
	});
	const read = settings.parse({
		"client-id": "client",
		"client-secret": "s3cr:et",
		...endpoints,
		...world.settings,
	});
	return { upstream: opened(read, stub, app.get(externalJwt), { clock }), asked };
}

const start: AuthorizationStart = {
	state: "s",
	nonce: "n",
	challenge: "c",
	challengeMethod: "S256",
	redirectUri: "https://as.example/session/oauth/federation/google/callback",
};
const exchange = (more: Partial<CodeExchange> = {}): CodeExchange => ({
	code: "c",
	verifier: "v",
	redirectUri: start.redirectUri,
	nonce: "n",
	iss: issuer,
	...more,
});
const outcome = (run: Promise<unknown>) =>
	run.then(
		(value) => value,
		(error) =>
			UpstreamRefused.is(error) ? "refused" : isUnavailable(error) ? "unavailable" : error,
	);
const granted = async (more: Record<string, unknown> = {}, claims: Record<string, unknown> = {}) =>
	answer({
		access_token: "at",
		token_type: "Bearer",
		expires_in: 3599,
		refresh_token: "rt",
		id_token: await idToken(claims),
		...more,
	});
/** What exchanging the default code comes to, at a Google handing over `token` as its id_token. */
const exchangedWith = async (token: string) => {
	const { upstream } = await open({ token: async () => granted({ id_token: token }) });
	return outcome(upstream.exchange(exchange()));
};
/** What the upstream offers as `what`; the test fails where it offers none. */
const offered = <T>(value: T | undefined, what: string): T => {
	if (value === undefined) throw new Error(`${what} is not offered`);
	return value;
};

describe("idp-google", () => {
	it("says its issuer is Google's", async () => {
		expect((await open()).upstream.issuer).toBe("https://accounts.google.com");
	});

	it("asks Google for offline access, the login's nonce and the freshness the browser asked [oidc-core-3.1.2.1-y] [oidc-core-7.2.1-a] [rfc9700-2.1.1-f] [rfc9700-2.1.1-h] [rfc9700-2.1.2-a]", async () => {
		const { upstream } = await open();
		const url = new URL(upstream.authorizationUrl({ ...start, prompt: "login", maxAgeSeconds: 0 }));
		expect(`${url.origin}${url.pathname}`).toBe(endpoints["authorization-endpoint"]);
		expect(Object.fromEntries(url.searchParams)).toEqual({
			response_type: "code",
			client_id: "client",
			redirect_uri: start.redirectUri,
			scope: "openid email profile",
			state: "s",
			code_challenge: "c",
			code_challenge_method: "S256",
			nonce: "n",
			access_type: "offline",
			prompt: "login consent",
			max_age: "0",
		});
		const online = await open({ settings: { access: "online" } });
		const plain = new URL(online.upstream.authorizationUrl(start)).searchParams;
		expect([plain.get("access_type"), plain.get("prompt"), plain.get("max_age")]).toEqual([
			null,
			null,
			null,
		]);
	});

	it("refuses at boot an endpoint that is empty or no URL, never throwing on it", () => {
		const both = { "client-id": "client", "client-secret": "s3cr:et" };
		for (const name of [
			"authorization-endpoint",
			"token-endpoint",
			"jwks-uri",
			"end-session-endpoint",
		]) {
			for (const value of ["", "not a url"]) {
				const read = () => settings.safeParse({ ...both, [name]: value });
				expect(read, `${name} ${value}`).not.toThrow();
				expect(read().success, `${name} ${value}`).toBe(false);
			}
		}
	});

	it("refuses at boot a client ID or secret that is empty or not well-formed text", () => {
		const both = { "client-id": "client", "client-secret": "s3cr:et" };
		expect(settings.safeParse(both).success).toBe(true);
		for (const name of ["client-id", "client-secret"]) {
			for (const value of ["", "a\uD800"]) {
				expect(settings.safeParse({ ...both, [name]: value }).success, `${name} ${value}`).toBe(
					false,
				);
			}
		}
	});

	it("reaches Google's own endpoints unless the operator names others", () => {
		const read = settings.parse({ "client-id": "client", "client-secret": "s3cr:et" });
		expect([read["authorization-endpoint"], read["token-endpoint"], read["jwks-uri"]]).toEqual([
			"https://accounts.google.com/o/oauth2/v2/auth",
			"https://oauth2.googleapis.com/token",
			"https://www.googleapis.com/oauth2/v3/certs",
		]);
	});

	it("takes a clock skew of whole seconds from 0s to 5m, written with its unit, 30s when not given", () => {
		const both = { "client-id": "client", "client-secret": "s3cr:et" };
		expect(settings.parse(both)["clock-skew"]).toBe(30);
		const skewOf = (skew: unknown) => settings.safeParse({ ...both, "clock-skew": skew }).success;
		expect(["0s", "300s", "5m"].map(skewOf)).toEqual([true, true, true]);
		expect(["301s", "-1s", "1.5s", 30, "30"].map(skewOf)).toEqual(Array(5).fill(false));
	});

	it("gives each default as an operator writes it, read through the key's own schema", () => {
		const kindOf = (key: { _zod: { def: { type: string } } }) => key._zod.def.type;
		const byDefault = Object.entries(settings.shape).filter(([, key]) => kindOf(key) === "default");
		expect(byDefault.map(([name]) => name)).toEqual([]);
	});

	it("takes the endpoints the browser goes to over plain http only at a loopback name, refusing another at its key", () => {
		const paths = outboundOver(outboundSection.parse({ "allow-any-public": true }), async () => [
			"93.184.216.34",
		]);
		const { explained, plainInternal, browsedRefusal } = paths;
		const policy: OutboundRefusals = { explained, plainInternal, browsedRefusal };
		const keysOf = (more: Record<string, unknown>) =>
			settingsOf(policy)
				.safeParse({ ...{ "client-id": "client", "client-secret": "s3cr:et" }, ...more })
				.error?.issues.map((i) => i.path.join("."));
		expect(keysOf({})).toBeUndefined();
		expect(
			keysOf({
				"authorization-endpoint": "http://127.0.0.1:9300/auth",
				"end-session-endpoint": "http://localhost:9300/out",
			}),
		).toBeUndefined();
		expect(keysOf({ "authorization-endpoint": "http://idp.example/auth" })).toEqual([
			"authorization-endpoint",
		]);
		expect(keysOf({ "end-session-endpoint": "http://idp.example/out" })).toEqual([
			"end-session-endpoint",
		]);
	});

	it("refuses at boot, at its key, an endpoint outbound's policy refuses, Google's own included", () => {
		const both = { "client-id": "client", "client-secret": "s3cr:et" };
		const refusalsOf = (refused: readonly string[], more: Record<string, unknown> = {}) =>
			settingsOf(policyRefusing(refused))
				.safeParse({ ...both, ...more })
				.error?.issues.map((i) => [i.path, i.message]);
		const refused = (key: string) => [
			[key],
			`outbound's destination policy refuses it: ${notAllowed}`,
		];
		policyAsked.length = 0;
		const googles = ["oauth2.googleapis.com", "www.googleapis.com"];
		expect(refusalsOf(googles)).toEqual([refused("token-endpoint"), refused("jwks-uri")]);
		expect(policyAsked).toEqual([
			{
				url: "https://oauth2.googleapis.com/token",
				narrower: { hosts: ["oauth2.googleapis.com"] },
			},
			{
				url: "https://www.googleapis.com/oauth2/v3/certs",
				narrower: { hosts: ["www.googleapis.com"] },
			},
		]);
		expect(refusalsOf(googles, endpoints)).toBeUndefined();
		expect(refusalsOf(["google.test", "token.google.test"], endpoints)).toEqual([
			refused("token-endpoint"),
			refused("jwks-uri"),
		]);
	});

	it("exchanges the code with the client's secret, sent only to the token endpoint's host", async () => {
		const { upstream, asked } = await open({
			token: async () => granted({}, { auth_time: seconds - 60 }),
		});
		expect(await upstream.exchange(exchange())).toEqual({
			subject: "g-alice",
			amr: [],
			authenticatedAt: (seconds - 60) * 1000,
			tokens: {
				accessToken: "at",
				tokenType: "Bearer",
				refreshToken: "rt",
				idToken: expect.any(String),
				expiresInSeconds: 3599,
				scope: ["openid", "email", "profile"],
			},
		});
		const sent = asked.find((a) => a.url === endpoints["token-endpoint"]);
		expect(Object.fromEntries(new URLSearchParams(String(sent?.request.body)))).toEqual({
			grant_type: "authorization_code",
			code: "c",
			redirect_uri: start.redirectUri,
			code_verifier: "v",
		});
		expect(sent?.request.headers).toEqual({
			"content-type": "application/x-www-form-urlencoded",
			accept: "application/json",
		});
		// The client's secret is outbound's to send, as the request's credential.
		expect(sent?.request.credential).toBe(
			`Basic ${Buffer.from("client:s3cr%3Aet").toString("base64")}`,
		);
		expect(sent?.hosts).toEqual(["token.google.test"]);
		// Every request, the keys' too, reaches only its own host.
		for (const a of asked) expect(a.hosts, a.url).toEqual([new URL(a.url).hostname]);
	});

	it("takes, with hosted-domains, only an id_token whose own hd is one of them, exactly", async () => {
		const settings = { "hosted-domains": ["corp.example", "lab.example"] };
		const hdOf = async (claims: Record<string, unknown>) => {
			const { upstream } = await open({ settings, token: async () => granted({}, claims) });
			return outcome(upstream.exchange(exchange()));
		};
		expect(await hdOf({ hd: "corp.example" })).toMatchObject({ subject: "g-alice" });
		expect(await hdOf({ hd: "lab.example" })).toMatchObject({ subject: "g-alice" });
		for (const claims of [
			{},
			{ hd: "other.example" },
			{ hd: "Corp.example" },
			{ hd: "sub.corp.example" },
			{ hd: ["corp.example"] },
			{ email: "a@corp.example", email_verified: true },
		]) {
			expect(await hdOf(claims), JSON.stringify(claims)).toBe("refused");
		}
	});

	it("takes any account without hosted-domains, and refuses an empty list or a domain not lowercase", async () => {
		const { upstream } = await open({ token: async () => granted() });
		expect(await upstream.exchange(exchange())).toMatchObject({ subject: "g-alice" });
		const both = { "client-id": "client", "client-secret": "s3cr:et" };
		for (const domains of [[], ["Corp.example"], [""], ["corp example"]]) {
			expect(
				settings.safeParse({ ...both, "hosted-domains": domains }).success,
				String(domains),
			).toBe(false);
		}
		expect(settings.safeParse({ ...both, "hosted-domains": ["corp.example"] }).success).toBe(true);
	});

	it("takes an id_token's at_hash only as the access token's [oidc-core-3.1.3.5-a]", async () => {
		const full = createHash("sha256").update("at").digest();
		const half = full.subarray(0, 16).toString("base64url");
		const exchanged = async (claims: Record<string, unknown>) => {
			const { upstream } = await open({ token: async () => granted({}, claims) });
			return outcome(upstream.exchange(exchange()));
		};
		expect(await exchanged({ at_hash: half })).toMatchObject({ subject: "g-alice" });
		for (const at_hash of [
			half.slice(1),
			createHash("sha256").update("x").digest().subarray(0, 16).toString("base64url"),
			7,
		]) {
			expect(await exchanged({ at_hash }), String(at_hash)).toBe("refused");
		}
	});

	it("gives the profile in the checked id_token, its email verified only by a boolean true", async () => {
		const said = { email: "a@gmail.example", name: "Alice", picture: "https://p.example/a" };
		const profileOf = async (claims: Record<string, unknown>) => {
			const { upstream } = await open({ token: async () => granted({}, claims) });
			return ((await upstream.exchange(exchange())) as { profile?: unknown }).profile;
		};
		expect(await profileOf({ ...said, email_verified: true, hd: "corp.example" })).toEqual({
			...said,
			emailVerified: true,
		});
		expect(await profileOf({ ...said, email_verified: "true" })).toEqual({
			...said,
			emailVerified: false,
		});
		expect(await profileOf({ email: said.email })).toEqual({
			email: said.email,
			emailVerified: false,
		});
		expect(await profileOf({ name: 7, email_verified: true, picture: said.picture })).toEqual({
			picture: said.picture,
		});
		expect(await profileOf({})).toBeUndefined();
	});

	it("refuses a callback without Google's iss before its code is used, an empty one always, a missing one unless iss is not asked, comparing it code point by code point [rfc9700-2.1-e] [rfc9700-2.1-f] [rfc9700-4.4.2.1-a] [rfc9700-4.4.2.2-b] [oidc-discovery-5-c]", async () => {
		const { upstream, asked } = await open({ token: async () => granted() });
		for (const iss of [
			undefined,
			"",
			"accounts.google.com",
			`${issuer}/`,
			issuer.toUpperCase(),
			"https://evil.example",
		]) {
			expect(await outcome(upstream.exchange(exchange({ iss }))), String(iss)).toBe("refused");
		}
		expect(asked).toEqual([]);
		const lenient = await open({
			token: async () => granted(),
			settings: { "require-iss": false },
		});
		expect(await lenient.upstream.exchange(exchange({ iss: undefined }))).toMatchObject({
			subject: "g-alice",
		});
		for (const iss of ["https://evil.example", ""]) {
			expect(await outcome(lenient.upstream.exchange(exchange({ iss }))), iss).toBe("refused");
		}
		expect(lenient.asked.filter((a) => a.url === endpoints["token-endpoint"])).toHaveLength(1);
	});

	it("refuses an id_token that does not hold for this client and login [oidc-core-2-v] [oidc-core-3.1.3.7-b] [oidc-core-3.1.3.7-d] [oidc-core-3.1.3.7-e] [oidc-core-3.1.3.7-h] [oidc-core-3.1.3.7-i] [oidc-core-3.1.3.7-j] [oidc-core-3.1.3.7-k] [oidc-core-16.3-a] [rfc9700-2.1.1-e] [rfc9700-4.5.3.2-a]", async () => {
		const cases = {
			"an unpublished key": await idToken({}, stranger),
			"a key under a kid not in the set": await idToken({}, await testSigner("RS256", "g9")),
			"an algorithm other than RS256": await idToken({}, elliptic),
			"another nonce": await idToken({ nonce: "other" }),
			"no nonce": await idToken({ nonce: undefined }),
			"an issuer without its scheme": await idToken({ iss: "accounts.google.com" }),
			"another audience": await idToken({ aud: "other" }),
			"two audiences, the other party authorized": await idToken({
				aud: ["client", "other"],
				azp: "other",
			}),
			"another audience beside the client, the client authorized": await idToken({
				aud: ["client", "other"],
				azp: "client",
			}),
			"an empty subject": await idToken({ sub: "" }),
			"no issue time": await idToken({ iat: undefined }),
			"an unreadable login time": await idToken({ auth_time: "yesterday" }),
			"a login time ahead of the clock allowance": await idToken({ auth_time: seconds + 31 }),
		};
		for (const [named, token] of Object.entries(cases)) {
			expect(await exchangedWith(token), named).toBe("refused");
		}
	});

	it("gives Google's clock its allowance in seconds, and no more", async () => {
		const { upstream } = await open();
		expect(upstream.clockSkewMs).toBe(30_000);
		const narrow = await open({ settings: { "clock-skew": "5s" } });
		expect(narrow.upstream.clockSkewMs).toBe(5_000);
		for (const ahead of [{ iat: seconds + 29 }, { auth_time: seconds + 29 }]) {
			expect(await exchangedWith(await idToken(ahead)), JSON.stringify(ahead)).toMatchObject({
				subject: "g-alice",
			});
		}
		expect(await exchangedWith(await idToken({ iat: seconds + 31 }))).toBe("refused");
	});

	it("accepts an id_token naming another client of the project as azp, for this client alone", async () => {
		// Cross-client identity: Google names another client of the project as azp.
		const crossClient = await idToken({ azp: "android-client" });
		expect(await exchangedWith(crossClient)).toMatchObject({ subject: "g-alice" });
	});

	it("refuses an answer without an id_token and a 400 invalid_grant, and is unavailable when Google cannot be reached [oidc-core-3.1.3.5-a]", async () => {
		const bare = await open({ token: async () => granted({ id_token: undefined }) });
		expect(await outcome(bare.upstream.exchange(exchange()))).toBe("refused");
		const denied = await open({ token: async () => answer({ error: "invalid_grant" }, 400) });
		expect(await outcome(denied.upstream.exchange(exchange()))).toBe("refused");
		const down = await open({ token: () => "unreachable" });
		expect(await outcome(down.upstream.exchange(exchange()))).toBe("unavailable");
	});

	it("reads a token answer as upstream-client's reader does, a lifetime of 0 included", async () => {
		const { upstream } = await open({ token: async () => granted({ expires_in: 0 }) });
		expect((await upstream.exchange(exchange())).tokens?.expiresInSeconds).toBe(0);
		const negative = await open({ token: async () => granted({ expires_in: -1 }) });
		expect(await outcome(negative.upstream.exchange(exchange()))).toBe("refused");
	});

	it("refreshes a token, telling a refused grant, a limit and an outage apart", async () => {
		const fresh = await open({
			token: async () => answer({ access_token: "at2", token_type: "Bearer" }),
		});
		expect(await offered(fresh.upstream.refresh, "refresh")("rt", ["openid", "email"])).toEqual({
			kind: "refreshed",
			tokens: { accessToken: "at2", tokenType: "Bearer", scope: ["openid", "email"] },
		});
		expect(Object.fromEntries(new URLSearchParams(String(fresh.asked[0]?.request.body)))).toEqual({
			grant_type: "refresh_token",
			refresh_token: "rt",
			scope: "openid email",
		});
		const refused = await open({ token: async () => answer({ error: "invalid_grant" }, 400) });
		expect(await offered(refused.upstream.refresh, "refresh")("rt", [])).toEqual({
			kind: "invalid_grant",
		});
		expect(Object.fromEntries(new URLSearchParams(String(refused.asked[0]?.request.body)))).toEqual(
			{ grant_type: "refresh_token", refresh_token: "rt" },
		);
		const limited = await open({ token: async () => answer({}, 429, [["retry-after", "7"]]) });
		expect(await offered(limited.upstream.refresh, "refresh")("rt", [])).toEqual({
			kind: "limited",
			retryAfterSeconds: 7,
		});
		const unsaid = await open({ token: async () => answer({}, 429, [["retry-after", ""]]) });
		expect(await offered(unsaid.upstream.refresh, "refresh")("rt", [])).toEqual({
			kind: "limited",
		});
		const failing = await open({ token: async () => answer({}, 503) });
		expect(await outcome(offered(failing.upstream.refresh, "refresh")("rt", []))).toBe(
			"unavailable",
		);
		const odd = await open({ token: async () => answer({ error: "invalid_client" }, 401) });
		expect(await outcome(offered(odd.upstream.refresh, "refresh")("rt", []))).toBe("refused");
	});

	it("ends the upstream session at the operator's endpoint, else where the browser goes back", async () => {
		const at = {
			idTokenHint: "hint",
			postLogoutRedirectUri: "https://app.example/bye",
			state: "st",
		};
		const set = await open({ settings: { "end-session-endpoint": "https://google.test/logout" } });
		expect(offered(set.upstream.endSession, "endSession")(at)).toBe(
			"https://google.test/logout?id_token_hint=hint&post_logout_redirect_uri=https%3A%2F%2Fapp.example%2Fbye&state=st",
		);
		const { upstream } = await open();
		const endSession = offered(upstream.endSession, "endSession");
		expect(endSession(at)).toBe("https://app.example/bye?state=st");
		expect(endSession({})).toBe("https://accounts.google.com/Logout");
	});
});
