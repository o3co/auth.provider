import { createHash, generateKeyPairSync } from "node:crypto";
import { externalJwt } from "@mod/external-jwt";
import externalJwtModule from "@mod/external-jwt/module";
import { testSigner } from "@mod/external-jwt/testing";
import {
	assemble,
	contract,
	defineModule,
	isUnavailable,
	kernelConfig,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import {
	type Narrower,
	type Outbound,
	type OutboundRefusals,
	type OutboundRequest,
	type OutboundResponse,
	outbound,
	outboundRefusals,
} from "@mod/outbound";
import {
	type AuthorizationStart,
	type CodeExchange,
	type IdpType,
	idpTypes,
	UpstreamRefused,
} from "@mod/upstreams";
import { jwtVerify } from "jose";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import idpApple from "../src/module.ts";
import { settingsOf } from "../src/settings.ts";
import { issuer, opened } from "../src/upstream.ts";

const base = "https://apple.test";
const endpoints = {
	"authorization-endpoint": `${base}/auth/authorize`,
	"token-endpoint": `${base}/auth/token`,
	"jwks-uri": `${base}/auth/keys`,
};
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
const callback = "https://as.example/session/oauth/federation/apple/callback";
const startedAt = 1_800_000_000_000;
let now = startedAt;
const seconds = Math.floor(startedAt / 1000);
const clock = { now: () => now };
const runtime = quietRuntime({ clock, random: { bytes: (length) => new Uint8Array(length) } });
const team = generateKeyPairSync("ec", { namedCurve: "P-256" });
const pkcs8 = (key: { export(o: object): string | Buffer }) =>
	key.export({ format: "pem", type: "pkcs8" }).toString();
const signing = { "team-id": "TEAM", "key-id": "KEY1", "private-key": pkcs8(team.privateKey) };

type Handler = (
	request: OutboundRequest,
) => Promise<OutboundResponse | "unreachable"> | "unreachable";
const answer = (json: unknown, status = 200, headers: [string, string][] = []) => ({
	status,
	headers: new Map(headers),
	body: new TextEncoder().encode(JSON.stringify(json)),
});

type Signer = Awaited<ReturnType<typeof testSigner>>;
let apple: Signer;
let stranger: Signer;
let elliptic: Signer;
beforeAll(async () => {
	apple = await testSigner("RS256", "a1");
	// Another key under the same kid, never published: its signature does not hold.
	stranger = await testSigner("RS256", "a1");
	elliptic = await testSigner("ES256", "e1");
});

/** An id_token Apple would issue for the login, with `more` (undefined leaves a claim out). */
const idToken = (more: Record<string, unknown> = {}, key = apple) =>
	key.sign(
		Object.fromEntries(
			Object.entries({
				iss: issuer,
				sub: "001234.abcd",
				aud: "com.example.web",
				nonce: "n",
				iat: seconds,
				exp: seconds + 300,
				...more,
			}).filter(([, value]) => value !== undefined),
		),
	);

async function open(
	token: Handler = async () => answer({}),
	more: Record<string, unknown> = { "client-secret": "fixed-secret" },
	redirectUri = callback,
) {
	const asked: { url: string; request: OutboundRequest; hosts?: readonly string[] }[] = [];
	const stub: Outbound = {
		fetch: async (url, request = {}, narrower = {}) => {
			asked.push({ url, request, ...(narrower.hosts ? { hosts: narrower.hosts } : {}) });
			const found =
				url === endpoints["jwks-uri"]
					? answer({ keys: [apple.jwk, elliptic.jwk] })
					: url === endpoints["token-endpoint"]
						? await token(request)
						: answer({}, 404);
			if (found === "unreachable") throw new Unavailable("stub");
			return found;
		},
	};
	const app = await assemble({
		modules: [
			defineModule({ name: "outbound" }, (m) => [m.provide(outbound).by(() => stub)]),
			externalJwtModule,
		],
		config: kernelConfig(),
		runtime,
	});
	const read = settings.parse({ "client-id": "com.example.web", ...endpoints, ...more });
	const upstream = opened(read, stub, app.get(externalJwt), { clock, redirectUri });
	const sent = () =>
		Object.fromEntries(
			new URLSearchParams(
				String(asked.find((a) => a.url === endpoints["token-endpoint"])?.request.body),
			),
		);
	return { upstream, asked, sent };
}

const start: AuthorizationStart = {
	state: "s",
	nonce: "n",
	challenge: "c",
	challengeMethod: "S256",
	redirectUri: callback,
};
const exchange = (more: Partial<CodeExchange> = {}): CodeExchange => ({
	code: "c",
	verifier: "v",
	redirectUri: callback,
	nonce: "n",
	iss: undefined,
	...more,
});
const outcome = (run: Promise<unknown> | undefined) =>
	Promise.resolve(run).then(
		(value) => value,
		(error) =>
			error instanceof UpstreamRefused ? "refused" : isUnavailable(error) ? "unavailable" : error,
	);
const granted = async (more: Record<string, unknown> = {}, claims: Record<string, unknown> = {}) =>
	answer({
		access_token: "at",
		token_type: "Bearer",
		expires_in: 3600,
		refresh_token: "rt",
		id_token: await idToken(claims),
		...more,
	});

afterEach(() => {
	now = startedAt;
});

describe("idp-apple", () => {
	it("says its issuer is Apple's", async () => {
		expect((await open()).upstream.issuer).toBe("https://appleid.apple.com");
	});

	it("asks for an answer in a posted form, at the callback checked at boot, without freshness", async () => {
		const { upstream } = await open();
		expect(upstream.responseMode).toBe("form_post");
		const elsewhere = { ...start, redirectUri: "https://other.example/cb" };
		const url = new URL(
			upstream.authorizationUrl({ ...elsewhere, prompt: "login", maxAgeSeconds: 0 }),
		);
		expect(`${url.origin}${url.pathname}`).toBe(endpoints["authorization-endpoint"]);
		expect(Object.fromEntries(url.searchParams)).toEqual({
			response_type: "code",
			client_id: "com.example.web",
			redirect_uri: callback,
			scope: "email",
			state: "s",
			code_challenge: "c",
			code_challenge_method: "S256",
			response_mode: "form_post",
			nonce: "n",
		});
	});

	it("refuses boot for a callback Apple refuses, and a key that is no P-256 key in PKCS8", async () => {
		for (const at of [
			"http://as.example/cb",
			"https://localhost/cb",
			"https://localhost./cb",
			"https://127.0.0.5/cb",
			"https://[::1]/cb",
		]) {
			await expect(open(undefined, undefined, at), at).rejects.toThrow();
		}
		const p384 = generateKeyPairSync("ec", { namedCurve: "P-384" }).privateKey;
		const sec1 = team.privateKey.export({ format: "pem", type: "sec1" }).toString();
		for (const pem of [pkcs8(p384), sec1, "not a key"]) {
			const said = await open(undefined, { ...signing, "private-key": pem }).then(
				() => "opened",
				(error: Error) => error.message,
			);
			expect(said).not.toBe("opened");
			expect([said.includes(pem), said.includes("BEGIN")]).toEqual([false, false]);
		}
	});

	it("refuses at boot an endpoint that is empty or no URL, never throwing on it", () => {
		const fixed = { "client-id": "com.example.web", "client-secret": "x" };
		for (const name of [
			"authorization-endpoint",
			"token-endpoint",
			"jwks-uri",
			"end-session-endpoint",
		]) {
			for (const value of ["", "not a url"]) {
				const read = () => settings.safeParse({ ...fixed, [name]: value });
				expect(read, `${name} ${value}`).not.toThrow();
				expect(read().success, `${name} ${value}`).toBe(false);
			}
		}
	});

	it("takes exactly one of a fixed secret and the three that sign one", () => {
		const parsed = (more: Record<string, unknown>) =>
			settings.safeParse({ "client-id": "com.example.web", ...more });
		expect(parsed({ "client-secret": "x" }).success).toBe(true);
		expect(parsed(signing).success).toBe(true);
		const refused = [
			{},
			{ ...signing, "client-secret": "x" },
			{ "team-id": "TEAM", "key-id": "KEY1" },
			{ "private-key": signing["private-key"] },
		];
		for (const more of refused) {
			const read = parsed(more);
			expect(read.success, JSON.stringify(Object.keys(more))).toBe(false);
			expect(JSON.stringify(read.error?.issues)).not.toContain("BEGIN");
		}
		const pathsOf = (more: Record<string, unknown>) =>
			parsed(more).error?.issues.map((i) => i.path);
		expect(pathsOf({ "team-id": "TEAM", "key-id": "KEY1" })).toEqual([["private-key"]]);
		expect(pathsOf({ "private-key": signing["private-key"] })).toEqual([["team-id"], ["key-id"]]);
	});

	it("takes a signed secret's life of 1m to 15777000s, whole seconds written with their unit", () => {
		const lifeOf = (life: unknown) =>
			settings.safeParse({ "client-id": "com.example.web", ...signing, "secret-lifetime": life })
				.success;
		expect(["60s", "1m", "15777000s"].map(lifeOf)).toEqual([true, true, true]);
		expect(["59s", "15777001s", "60.5s", 300, "300"].map(lifeOf)).toEqual(Array(5).fill(false));
	});

	it("asks only for name and email as scopes", () => {
		const scopesOf = (scopes: readonly string[]) =>
			settings.safeParse({ "client-id": "com.example.web", "client-secret": "x", scopes }).success;
		expect(scopesOf(["name", "email"])).toBe(true);
		for (const scope of ["openid", "profile"]) {
			expect(scopesOf(["email", scope]), scope).toBe(false);
		}
	});

	it("reaches Apple's own endpoints unless the operator names others", () => {
		const read = settings.parse({ "client-id": "com.example.web", "client-secret": "x" });
		expect([read["authorization-endpoint"], read["token-endpoint"], read["jwks-uri"]]).toEqual([
			"https://appleid.apple.com/auth/authorize",
			"https://appleid.apple.com/auth/token",
			"https://appleid.apple.com/auth/keys",
		]);
	});

	it("takes a clock skew of whole seconds from 0s to 5m, written with its unit, 30s when not given", () => {
		const both = { "client-id": "com.example.web", "client-secret": "x" };
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

	it("refuses at boot a client ID or fixed secret that is empty or not well-formed text", () => {
		const both = { "client-id": "com.example.web", "client-secret": "x" };
		for (const name of ["client-id", "client-secret"]) {
			for (const value of ["", "a\uD800"]) {
				expect(settings.safeParse({ ...both, [name]: value }).success, `${name} ${value}`).toBe(
					false,
				);
			}
		}
	});

	it("refuses at boot a team ID, key ID or private key that is empty or not well-formed text", () => {
		const signed = { "client-id": "com.example.web", ...signing };
		expect(settings.safeParse(signed).success).toBe(true);
		for (const name of ["team-id", "key-id", "private-key"] as const) {
			for (const value of ["", `${signed[name]}\uD800`]) {
				const read = settings.safeParse({ ...signed, [name]: value });
				expect(read.success, `${name} ${value.length}`).toBe(false);
				expect(read.error?.issues.map((i) => i.path)).toContainEqual([name]);
				expect(JSON.stringify(read.error?.issues)).not.toContain("BEGIN");
			}
		}
	});

	it("refuses at boot, at its key, an endpoint outbound's policy refuses, Apple's own included", () => {
		const both = { "client-id": "com.example.web", "client-secret": "x" };
		const refusalsOf = (refused: readonly string[], more: Record<string, unknown> = {}) =>
			settingsOf(policyRefusing(refused))
				.safeParse({ ...both, ...more })
				.error?.issues.map((i) => [i.path, i.message]);
		const refused = (key: string) => [
			[key],
			`outbound's destination policy refuses it: ${notAllowed}`,
		];
		policyAsked.length = 0;
		expect(refusalsOf(["appleid.apple.com"])).toEqual([
			refused("token-endpoint"),
			refused("jwks-uri"),
		]);
		const hosts = ["appleid.apple.com"];
		expect(policyAsked).toEqual([
			{ url: "https://appleid.apple.com/auth/token", narrower: { hosts } },
			{ url: "https://appleid.apple.com/auth/keys", narrower: { hosts } },
		]);
		expect(refusalsOf(hosts, endpoints)).toBeUndefined();
		const keysElsewhere = { ...endpoints, "jwks-uri": "https://keys.apple.test/auth/keys" };
		expect(refusalsOf(["keys.apple.test"], keysElsewhere)).toEqual([refused("jwks-uri")]);
	});

	it("exchanges the code with the fixed secret in the form, sent only to the token endpoint's host", async () => {
		const { upstream, asked, sent } = await open(async () => granted());
		expect(await upstream.exchange(exchange({ redirectUri: "https://other.example/cb" }))).toEqual({
			subject: "001234.abcd",
			amr: [],
			tokens: {
				accessToken: "at",
				tokenType: "Bearer",
				refreshToken: "rt",
				idToken: expect.any(String),
				expiresInSeconds: 3600,
				scope: ["email"],
			},
		});
		expect(sent()).toEqual({
			grant_type: "authorization_code",
			code: "c",
			redirect_uri: callback,
			code_verifier: "v",
			client_id: "com.example.web",
			client_secret: "fixed-secret",
		});
		const token = asked.find((a) => a.url === endpoints["token-endpoint"]);
		expect(token?.request.headers).toEqual({
			"content-type": "application/x-www-form-urlencoded",
			accept: "application/json",
		});
		for (const a of asked) expect(a.hosts, a.url).toEqual(["apple.test"]);
	});

	it("signs the client's secret with the team's key where the operator gives it, again once half its life is spent", async () => {
		const { upstream, asked, sent } = await open(async () => granted(), signing);
		await upstream.exchange(exchange());
		const { payload } = await jwtVerify(sent().client_secret ?? "", team.publicKey, {
			currentDate: new Date(now),
			issuer: "TEAM",
			subject: "com.example.web",
			audience: issuer,
		});
		expect(Number(payload.exp) - Number(payload.iat)).toBe(300);
		now += 149_999;
		await upstream.exchange(exchange());
		now += 1;
		await upstream.exchange(exchange());
		const [first, held, renewed] = asked
			.filter((a) => a.url === endpoints["token-endpoint"])
			.map((a) => new URLSearchParams(String(a.request.body)).get("client_secret"));
		expect(held).toBe(first);
		expect(renewed).not.toBe(first);
		const later = await jwtVerify(renewed ?? "", team.publicKey, { currentDate: new Date(now) });
		expect(later.payload.iat).toBe(seconds + 150);
	});

	it("refuses a callback naming another issuer before its code is used, and takes one naming none", async () => {
		const { upstream, asked } = await open(async () => granted());
		for (const iss of ["", "appleid.apple.com", `${issuer}/`, "https://evil.example"]) {
			expect(await outcome(upstream.exchange(exchange({ iss }))), iss).toBe("refused");
		}
		expect(asked).toEqual([]);
		expect(await upstream.exchange(exchange({ iss: issuer }))).toMatchObject({
			subject: "001234.abcd",
		});
	});

	it("refuses an id_token that does not hold for this client and login", async () => {
		const refusedBy = async (token: string) => {
			const { upstream } = await open(async () => granted({ id_token: token }));
			return outcome(upstream.exchange(exchange()));
		};
		const cases = {
			"an unpublished key": await idToken({}, stranger),
			"a key under a kid not in the set": await idToken({}, await testSigner("RS256", "a9")),
			"an algorithm other than RS256": await idToken({}, elliptic),
			"another nonce": await idToken({ nonce: "other" }),
			"another issuer": await idToken({ iss: "https://evil.example" }),
			"another audience": await idToken({ aud: "other" }),
			"two audiences, the other party authorized": await idToken({
				aud: ["com.example.web", "other"],
				azp: "other",
			}),
			"one audience, another party authorized": await idToken({ azp: "other" }),
			"an empty subject": await idToken({ sub: "" }),
			"no issue time": await idToken({ iat: undefined }),
			"an unreadable login time": await idToken({ auth_time: "yesterday" }),
			"an issue time ahead of the clock allowance": await idToken({ iat: seconds + 31 }),
			"a login time ahead of the clock allowance": await idToken({ auth_time: seconds + 31 }),
		};
		for (const [named, token] of Object.entries(cases)) {
			expect(await refusedBy(token), named).toBe("refused");
		}
		const timed = await refusedBy(await idToken({ auth_time: seconds - 60 }));
		expect(timed).toMatchObject({ authenticatedAt: (seconds - 60) * 1000 });
	});

	it("takes an id_token's at_hash only as the access token's", async () => {
		const full = createHash("sha256").update("at").digest();
		const half = full.subarray(0, 16).toString("base64url");
		const exchanged = async (claims: Record<string, unknown>) => {
			const { upstream } = await open(async () => granted({}, claims));
			return outcome(upstream.exchange(exchange()));
		};
		expect(await exchanged({ at_hash: half })).toMatchObject({ subject: expect.any(String) });
		for (const at_hash of [
			half.slice(1),
			createHash("sha256").update("x").digest().subarray(0, 16).toString("base64url"),
			7,
		]) {
			expect(await exchanged({ at_hash }), String(at_hash)).toBe("refused");
		}
	});

	it("gives the profile in the checked id_token, its email verified by Apple's true, as a boolean or text", async () => {
		const profileOf = async (claims: Record<string, unknown>) => {
			const { upstream } = await open(async () => granted({ id_token: await idToken(claims) }));
			return (await upstream.exchange(exchange())).profile;
		};
		const email = "x@privaterelay.appleid.com";
		for (const verified of [true, "true"]) {
			expect(
				await profileOf({ email, email_verified: verified, is_private_email: "true" }),
			).toEqual({ email, emailVerified: true });
		}
		for (const unverified of [false, "false", "yes", "1", undefined]) {
			expect(await profileOf({ email, email_verified: unverified }), String(unverified)).toEqual({
				email,
				emailVerified: false,
			});
		}
		expect(await profileOf({ email_verified: true })).toBeUndefined();
	});

	it("gives Apple's clock its allowance in seconds", async () => {
		const taken = async (claims: Record<string, unknown>) => {
			const { upstream } = await open(async () => granted({}, claims));
			return upstream.exchange(exchange());
		};
		for (const ahead of [{ iat: seconds + 29 }, { auth_time: seconds + 29 }]) {
			expect(await taken(ahead), JSON.stringify(ahead)).toMatchObject({ subject: "001234.abcd" });
		}
		expect((await open()).upstream.clockSkewMs).toBe(30_000);
		const narrow = await open(undefined, { "client-secret": "x", "clock-skew": "5s" });
		expect(narrow.upstream.clockSkewMs).toBe(5_000);
	});

	it("refuses an answer without an id_token, and is unavailable when Apple cannot be reached", async () => {
		const bare = await open(async () => granted({ id_token: undefined }));
		expect(await outcome(bare.upstream.exchange(exchange()))).toBe("refused");
		const down = await open(() => "unreachable");
		expect(await outcome(down.upstream.exchange(exchange()))).toBe("unavailable");
	});

	it("refreshes a token, telling a refused grant, a limit and an outage apart", async () => {
		const fresh = await open(async () => answer({ access_token: "at2", token_type: "Bearer" }));
		expect(await fresh.upstream.refresh?.("rt", ["email"])).toEqual({
			kind: "refreshed",
			tokens: { accessToken: "at2", tokenType: "Bearer", scope: ["email"] },
		});
		expect(fresh.sent()).toEqual({
			grant_type: "refresh_token",
			refresh_token: "rt",
			client_id: "com.example.web",
			client_secret: "fixed-secret",
		});
		const refused = await open(async () => answer({ error: "invalid_grant" }, 400));
		expect(await refused.upstream.refresh?.("rt", [])).toEqual({ kind: "invalid_grant" });
		const limited = await open(async () => answer({}, 429));
		expect(await limited.upstream.refresh?.("rt", [])).toEqual({ kind: "limited" });
		const unsaid = await open(async () => answer({}, 429, [["retry-after", ""]]));
		expect(await unsaid.upstream.refresh?.("rt", [])).toEqual({ kind: "limited" });
		const failing = await open(async () => answer({}, 500));
		expect(await outcome(failing.upstream.refresh?.("rt", []))).toBe("unavailable");
	});

	it("ends the upstream session only at the operator's endpoint", async () => {
		const { upstream } = await open();
		expect(upstream.endSession).toBeUndefined();
		const set = await open(undefined, {
			"client-secret": "x",
			"end-session-endpoint": "https://apple.test/logout",
		});
		expect(set.upstream.endSession?.({ idTokenHint: "hint", state: "st" })).toBe(
			"https://apple.test/logout?id_token_hint=hint&state=st",
		);
	});

	it("contributes the apple type, opening it at the callback it is given", async () => {
		const types = contract<readonly IdpType[]>("types");
		const unused: Outbound = {
			fetch: async () => {
				throw new Unavailable("stub");
			},
		};
		const app = await assemble({
			modules: [
				defineModule({ name: "outbound" }, (m) => [
					m.provide(outbound).by(() => unused),
					m.provide(outboundRefusals).by(() => policyRefusing()),
				]),
				externalJwtModule,
				idpApple,
				defineModule({ name: "types" }, (m) => [m.provide(types).by((c) => c.collect(idpTypes))]),
			],
			config: kernelConfig(),
			runtime,
		});
		const apple = app.get(types).find((type) => type.type === "apple");
		if (!apple) throw new Error("the apple type is not contributed");
		const read = apple.settings.parse({ "client-id": "com.example.web", "client-secret": "x" });
		const upstream = await apple.open(read, { idp: "apple", redirectUri: callback });
		const url = new URL(upstream.authorizationUrl(start));
		expect(url.searchParams.get("redirect_uri")).toBe(callback);
	});
});
