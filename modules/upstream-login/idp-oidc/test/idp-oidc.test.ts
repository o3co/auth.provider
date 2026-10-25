import { createHash } from "node:crypto";
import { type Algorithm, externalJwt } from "@mod/external-jwt";
import externalJwtModule from "@mod/external-jwt/module";
import {
	assemble,
	contract,
	defineModule,
	isUnavailable,
	kernelConfig,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import {
	DestinationRefused,
	type Narrower,
	type Outbound,
	type OutboundRequest,
	type OutboundResponse,
	outbound,
} from "@mod/outbound";
import { outboundOver, section as outboundSection } from "@mod/outbound/module";
import { type OutboundRefusals, outboundRefusals, withinHosts } from "@mod/outbound-policy";
import {
	type AuthorizationStart,
	type CodeExchange,
	type DelegatedExchange,
	type DelegationStart,
	type IdpType,
	idpTypes,
	type Upstream,
	UpstreamMismatch,
	UpstreamRefused,
} from "@mod/upstreams";
import { CompactSign, exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import idpOidc from "../src/module.ts";
import { settingsOf } from "../src/settings.ts";
import { opened } from "../src/upstream.ts";

/** The asymmetric algorithms external-jwt knows, the defaults among them. */
const asymmetric: readonly Algorithm[] = ["RS256", "PS256", "ES256", "EdDSA"];
const issuer = "https://idp.example";
const start = 1_800_000_000_000;
let now = start;
const clock = { now: () => now };
const runtime = quietRuntime({ clock, random: { bytes: (length) => new Uint8Array(length) } });

type Handler = (request: OutboundRequest) => OutboundResponse | "unreachable" | "broken";
const ok = (json: unknown): OutboundResponse => ({
	status: 200,
	headers: new Map(),
	body: new TextEncoder().encode(JSON.stringify(json)),
});

const authorizationStart: AuthorizationStart = {
	state: "s",
	nonce: "n",
	challenge: "c",
	challengeMethod: "S256",
	redirectUri: "https://as.example/cb",
};

/** A token endpoint's answer handing over `idToken` with an access token. */
const granted = (idToken: string, more: Record<string, unknown> = {}) =>
	ok({ access_token: "at", token_type: "Bearer", id_token: idToken, ...more });

/** An outbound that answers from a table of handlers by URL, keeping what it was asked. */
function stubOutbound(handlers: Record<string, Handler>) {
	const asked: {
		url: string;
		request: OutboundRequest;
		hosts?: readonly string[];
		internal?: string;
	}[] = [];
	const outbound: Outbound = {
		fetch: async (url, request = {}, narrower = {}) => {
			asked.push({
				url,
				request,
				...(narrower.hosts ? { hosts: narrower.hosts } : {}),
				...(narrower.internal ? { internal: narrower.internal } : {}),
			});
			if (narrower.hosts && !withinHosts(url, narrower.hosts)) {
				throw new Error("outside the narrowed hosts");
			}
			const answer = handlers[url]?.(request) ?? {
				status: 404,
				headers: new Map(),
				body: new Uint8Array(),
			};
			if (answer === "unreachable") throw new Unavailable("stub");
			if (answer === "broken") throw new Error("refused by the destination policy");
			return answer;
		},
	};
	return { outbound, asked };
}

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

let rsa: { privateKey: CryptoKey; jwk: JWK };
let other: { privateKey: CryptoKey; jwk: JWK };
/** An RSA key for PSS signatures, its JWK naming no `alg`, as an IdP's set may hold one. */
let pss: { privateKey: CryptoKey; jwk: JWK };
beforeAll(async () => {
	const made = async (kid: string, alg = "RS256") => {
		const pair = await generateKeyPair(alg, { extractable: true });
		return {
			privateKey: pair.privateKey,
			jwk: { ...(await exportJWK(pair.publicKey)), kid },
		};
	};
	rsa = await made("k1");
	other = await made("k2");
	pss = await made("p1", "PS256");
});

/** An id_token issued now, unless `iat` says otherwise (`null` leaves it out). */
const idToken = async (claims: Record<string, unknown> = {}, key = rsa, alg = "RS256") => {
	const { iat = Math.floor(now / 1000), ...rest } = claims;
	const payload: Record<string, unknown> = {
		nonce: "n",
		...rest,
		...(iat === null ? {} : { iat }),
	};
	return new SignJWT(payload as never)
		.setProtectedHeader({ alg, kid: key.jwk.kid as string })
		.setIssuer((claims.iss as string | undefined) ?? issuer)
		.setSubject((claims.sub as string | undefined) ?? "u-alice")
		.setAudience((claims.aud as string | string[] | undefined) ?? "client")
		.setExpirationTime(Math.floor(now / 1000) + 300)
		.sign(key.privateKey);
};

/** An id_token holding its claims exactly as written, for claims a signing library would refuse. */
const written = (json: string) =>
	new CompactSign(new TextEncoder().encode(json))
		.setProtectedHeader({ alg: "RS256", kid: "k1" })
		.sign(rsa.privateKey);
/** The claims of an id_token issued now, with `more`. */
const claimsWith = (more: Record<string, unknown>) => {
	const t = Math.floor(now / 1000);
	return { iss: issuer, sub: "u-alice", aud: "client", nonce: "n", iat: t, exp: t + 300, ...more };
};

interface World {
	readonly description?: Record<string, unknown>;
	readonly token?: Handler;
	/** The issuer's key set cannot be reached. */
	readonly keysUnreachable?: boolean;
	/** The issuer's key set, in place of the RSA key alone. */
	readonly keys?: readonly JWK[];
	readonly settings?: Record<string, unknown>;
	readonly more?: Record<string, Handler>;
	/** Hosts outbound's destination policy refuses. */
	readonly refused?: readonly string[];
	/** How the issuer's description answers, in place of the usual one. */
	readonly describes?: Handler;
	/** A real outbound and its refusals, in place of the table of answers. */
	readonly reach?: { readonly outbound: Outbound; readonly refusals: OutboundRefusals };
	/** Refusals in place of the table's, with the table of answers kept. */
	readonly refusals?: OutboundRefusals;
}

async function open(world: World = {}) {
	const stub = stubOutbound({
		...world.more,
		[`${issuer}/.well-known/openid-configuration`]:
			world.describes ??
			(() =>
				ok({
					issuer,
					authorization_endpoint: `${issuer}/authorize`,
					token_endpoint: `${issuer}/token`,
					jwks_uri: `${issuer}/jwks`,
					...world.description,
				})),
		[`${issuer}/jwks`]: () =>
			world.keysUnreachable ? "unreachable" : ok({ keys: world.keys ?? [rsa.jwk] }),
		[`${issuer}/token`]: world.token ?? (() => ok({ id_token: "missing" })),
	});
	const app = await assemble({
		modules: [
			defineModule({ name: "outbound", takes: [] }, (m) => [
				m.provide(outbound).by(() => stub.outbound),
			]),
			externalJwtModule,
		],
		config: kernelConfig(),
		runtime,
	});
	const jwt = app.get(externalJwt);
	const refusals = world.reach?.refusals ?? world.refusals ?? policyRefusing(world.refused);
	const settings = settingsOf(jwt.algorithms, refusals);
	const read = settings.parse({
		issuer,
		"client-id": "client",
		"client-secret": "s3cr:et",
		...world.settings,
	});
	const recorded = recordingLog();
	const upstream = await opened(
		read,
		{ outbound: world.reach?.outbound ?? stub.outbound, refusals },
		jwt,
		{
			clock,
			log: recorded.log,
			idp: "corp",
		},
	);
	/** The warn lines while it opened. */
	const warned = recorded
		.lines()
		.filter((line) => line.level === "warn")
		.map(({ event, fields }) => ({ event, fields }));
	return { upstream, settings, asked: stub.asked, warned };
}

const codeExchange = (more: Partial<CodeExchange> = {}): CodeExchange => ({
	code: "c",
	verifier: "v",
	redirectUri: "https://as.example/session/oauth/federation/corp/callback",
	nonce: "n",
	iss: issuer,
	...more,
});
/** A delegation's code, asking for openid unless `more` says otherwise. */
const delegatedExchange = (more: Partial<DelegatedExchange> = {}): DelegatedExchange => ({
	...codeExchange(),
	scopes: ["openid"],
	...more,
});
/** A delegation's start asking for offline access to files at an API. */
const delegationStart: DelegationStart = {
	...authorizationStart,
	redirectUri: "https://as.example/connect",
	scopes: ["openid", "offline_access", "files.read"],
	resource: "https://api.example/",
};
/** What the upstream offers as `what`; the test fails where it offers none. */
const offered = <T>(value: T | undefined, what: string): T => {
	if (value === undefined) throw new Error(`${what} is not offered`);
	return value;
};
const outcome = (run: Promise<unknown>) =>
	run.then(
		(value) => value,
		(error) =>
			UpstreamRefused.is(error) ? "refused" : isUnavailable(error) ? "unavailable" : error,
	);
/** An upstream whose token endpoint hands over `idToken`, with what `world` changes. */
const answering = (idToken: string, world: Omit<World, "token"> = {}) =>
	open({ ...world, token: () => granted(idToken) });
/** What exchanging the default code comes to, at an upstream handing over `idToken`. */
const exchanged = async (idToken: string, world?: Omit<World, "token">) =>
	outcome((await answering(idToken, world)).upstream.exchange(codeExchange()));
/** The URL a delegation's start goes to; the test fails where there is none. */
const delegationUrl = (upstream: Upstream, start: DelegationStart) => {
	const made = offered(upstream.delegation, "delegation").authorizationUrl(start);
	if (typeof made !== "string") throw new Error("no delegation URL");
	return new URL(made);
};
/** The endpoints an operator gives without discovery. */
const givenEndpoints = {
	discovery: false,
	"authorization-endpoint": `${issuer}/a`,
	"token-endpoint": `${issuer}/token`,
	"jwks-uri": `${issuer}/jwks`,
};
/** outbound's own refusals over `settings`, every name resolving to a private address. */
const refusalsOver = (settings: Record<string, unknown>): OutboundRefusals => {
	const paths = outboundOver(outboundSection.parse(settings), async () => ["10.0.0.5"]);
	const { explained, plainInternal, browsedRefusal } = paths;
	return { explained, plainInternal, browsedRefusal };
};
/** An issuer at `at` describing itself and serving its key set, as `issuer` does. */
const servedAt = (at: string, described: Record<string, unknown> = {}) => ({
	[`${at}/.well-known/openid-configuration`]: () =>
		ok({
			issuer: at,
			authorization_endpoint: `${at}/authorize`,
			token_endpoint: `${at}/token`,
			jwks_uri: `${at}/jwks`,
			...described,
		}),
	[`${at}/jwks`]: () => ok({ keys: [rsa.jwk] }),
});
const loopbackIssuer = "http://127.0.0.1:9100";
const loopbackRefusals = () =>
	refusalsOver({ allow: ["127.0.0.1", "idp.example"], "plain-loopback": ["127.0.0.1:9100"] });
const internalIssuer = "http://idp.internal:8080";
const internalRefusals = () =>
	refusalsOver({ allow: ["idp.internal", "idp.example"], "plain-internal": ["idp.internal:8080"] });
afterEach(() => {
	now = start;
});
describe("idp-oidc", () => {
	it("says its issuer is the one its settings name", async () => {
		expect((await open()).upstream.issuer).toBe(issuer);
	});

	it("builds the authorization request at the described endpoint, with nonce, PKCE, prompt and max_age", async () => {
		const { upstream } = await open();
		const url = new URL(
			upstream.authorizationUrl({ ...authorizationStart, prompt: "login", maxAgeSeconds: 0 }),
		);
		expect(`${url.origin}${url.pathname}`).toBe(`${issuer}/authorize`);
		expect(Object.fromEntries(url.searchParams)).toEqual({
			response_type: "code",
			client_id: "client",
			redirect_uri: "https://as.example/cb",
			scope: "openid",
			state: "s",
			nonce: "n",
			code_challenge: "c",
			code_challenge_method: "S256",
			prompt: "login",
			max_age: "0",
		});
		const profiled = await open({ settings: { scopes: ["openid", "profile"] } });
		const asked = new URL(profiled.upstream.authorizationUrl(authorizationStart));
		expect(asked.searchParams.get("scope")).toBe("openid profile");
	});

	it("refuses at boot a description that names another issuer, one only starting with it included", async () => {
		for (const named of ["https://other.example", `${issuer}/`, `${issuer}/tenant`]) {
			await expect(open({ description: { issuer: named } }), named).rejects.toThrow(
				/another issuer/,
			);
		}
	});

	it("reads the description of an issuer named with a trailing slash at one slash before .well-known", async () => {
		const slashed = `${issuer}/`;
		const { asked } = await open({
			settings: { issuer: slashed },
			description: { issuer: slashed },
		});
		expect(asked.map((a) => a.url)).toEqual([`${issuer}/.well-known/openid-configuration`]);
	});

	it("sends to no host but the issuer's and the ones the operator names, refusing a description that points elsewhere", async () => {
		const elsewhere = { token_endpoint: "https://collector.example/token" };
		await expect(open({ description: elsewhere })).rejects.toThrow(
			/host the operator did not name/,
		);
		const named = await open({
			description: { token_endpoint: "https://tokens.idp-cdn.example/token" },
			settings: { "endpoint-hosts": ["tokens.idp-cdn.example"] },
		});
		expect(named.asked.every((a) => a.hosts?.includes("idp.example"))).toBe(true);
		// Hosts compare as outbound compares them: in one spelling, and `.name` for the name and the names under it.
		await expect(
			open({ description: { token_endpoint: "https://IDP.example./token" } }),
		).resolves.toBeDefined();
		const id = await idToken();
		for (const token of ["https://tokens.idp-cdn.example/token", "https://idp-cdn.example/token"]) {
			const cdn = await open({
				description: { token_endpoint: token },
				settings: { "endpoint-hosts": [".idp-cdn.example"] },
				more: { [token]: () => granted(id) },
			});
			expect(await cdn.upstream.exchange(codeExchange()), token).toMatchObject({
				subject: "u-alice",
			});
			expect(cdn.asked.find((a) => a.url === token)?.hosts).toEqual([
				"idp.example",
				".idp-cdn.example",
			]);
		}
		const { upstream, asked } = await answering(await idToken());
		await upstream.exchange(codeExchange());
		expect(asked.length).toBeGreaterThan(1);
		for (const a of asked) expect(a.hosts, a.url).toEqual(["idp.example"]);
	});

	it("refuses at boot a description whose end of session is on a host the operator did not name", async () => {
		const elsewhere = { end_session_endpoint: "https://collector.example/logout" };
		await expect(open({ description: elsewhere })).rejects.toThrow(
			/host the operator did not name/,
		);
		const named = await open({
			description: elsewhere,
			settings: { "endpoint-hosts": ["collector.example"] },
		});
		expect(offered(named.upstream.endSession, "endSession")({})).toMatch(
			/^https:\/\/collector\.example\/logout\?/,
		);
	});

	it("refuses at boot a description whose endpoints the browser would leave https for, where outbound does not take it", async () => {
		const described: Record<string, Record<string, unknown>> = {
			"an app's scheme": { authorization_endpoint: "myapp://idp.example/authorize" },
			"plain http": { authorization_endpoint: "http://idp.example/authorize" },
			"an end of session in an app's scheme": { end_session_endpoint: "myapp://idp.example/out" },
		};
		for (const [label, description] of Object.entries(described)) {
			await expect(open({ description }), label).rejects.toThrow(/the browser/);
		}
	});

	it("lets the browser go over plain http only at a loopback name, or at the issuer's origin that plain-internal names", async () => {
		const at = (issuerUrl: string, refusals: OutboundRefusals, described = {}) =>
			open({
				settings: { issuer: issuerUrl, "endpoint-hosts": ["idp.example"] },
				more: servedAt(issuerUrl, described),
				refusals,
			}).catch((e: unknown) => e);
		expect(await at(loopbackIssuer, loopbackRefusals())).toMatchObject({
			upstream: { issuer: loopbackIssuer },
		});
		expect(await at(internalIssuer, internalRefusals())).toMatchObject({
			upstream: { issuer: internalIssuer },
		});
		const refused: [string, OutboundRefusals, Record<string, unknown>][] = [
			[
				loopbackIssuer,
				loopbackRefusals(),
				{ authorization_endpoint: "http://idp.example/authorize" },
			],
			[loopbackIssuer, loopbackRefusals(), { end_session_endpoint: "http://idp.example/out" }],
			// The issuer's host, but another origin than the issuer's.
			[
				internalIssuer,
				internalRefusals(),
				{ authorization_endpoint: "http://idp.internal:9090/a" },
			],
		];
		for (const [issuerUrl, refusals, described] of refused) {
			const error = await at(issuerUrl, refusals, described);
			expect(error, JSON.stringify(described)).toBeInstanceOf(UpstreamMismatch);
			expect((error as UpstreamMismatch).at).toEqual(["issuer"]);
			expect(String(error)).toMatch(/the browser/);
			expect(String(error)).not.toMatch(/idp\.example|9090/);
		}
	});

	it("takes plain http among its given endpoints where outbound takes each, and refuses at its key one the browser would go to", async () => {
		const given = (at: string) => ({
			discovery: false,
			issuer: at,
			"authorization-endpoint": `${at}/a`,
			"token-endpoint": `${at}/token`,
			"jwks-uri": `${at}/jwks`,
		});
		await expect(
			open({ settings: given(internalIssuer), refusals: internalRefusals() }),
		).resolves.toMatchObject({ upstream: { issuer: internalIssuer } });
		const settingsFor = settingsOf(asymmetric, internalRefusals());
		const keysRefused = (more: Record<string, unknown>) => {
			const read = settingsFor.safeParse({
				...given(internalIssuer),
				"client-id": "client",
				"client-secret": "s",
				...more,
			});
			return read.success ? [] : read.error.issues.map((issue) => issue.path.join("."));
		};
		expect(keysRefused({ "authorization-endpoint": "http://idp.example/a" })).toEqual([
			"authorization-endpoint",
		]);
		expect(keysRefused({ "end-session-endpoint": "http://idp.example/out" })).toEqual([
			"end-session-endpoint",
		]);
		// A logout on another host, which plain-internal names, is taken for itself.
		const logout = "http://logout.internal:8080/logout";
		const twoHosts = refusalsOver({
			allow: ["idp.internal", "logout.internal"],
			"plain-internal": ["idp.internal:8080", "logout.internal:8080"],
		});
		const read = settingsOf(asymmetric, twoHosts).safeParse({
			...given(internalIssuer),
			"client-id": "client",
			"client-secret": "s",
			"end-session-endpoint": logout,
		});
		expect(read.error?.issues).toBeUndefined();
	});

	it("asks for a browser's URL with the issuer as the operator's URL for what it describes, and each given endpoint for itself", async () => {
		const asked: [string, string | undefined][] = [];
		const refusals: OutboundRefusals = {
			explained: () => undefined,
			browsedRefusal: (url, narrower) => {
				asked.push([url, narrower?.internal]);
				return undefined;
			},
		};
		await open({ refusals, description: { end_session_endpoint: `${issuer}/out` } });
		expect(asked).toEqual([
			[`${issuer}/authorize`, issuer],
			[`${issuer}/out`, issuer],
		]);
		asked.length = 0;
		await open({
			refusals,
			settings: { ...givenEndpoints, "end-session-endpoint": `${issuer}/out` },
		});
		expect(asked).toEqual([
			[`${issuer}/a`, `${issuer}/a`],
			[`${issuer}/out`, `${issuer}/out`],
		]);
	});

	it("logs in at an issuer named on plain http, comparing its iss as written", async () => {
		const token = await idToken({ iss: loopbackIssuer });
		const { upstream } = await open({
			settings: { issuer: loopbackIssuer },
			more: { ...servedAt(loopbackIssuer), [`${loopbackIssuer}/token`]: () => granted(token) },
			refusals: loopbackRefusals(),
		});
		expect(await outcome(upstream.exchange(codeExchange({ iss: loopbackIssuer })))).toMatchObject({
			subject: "u-alice",
		});
		const other = "https://127.0.0.1:9100";
		expect(await outcome(upstream.exchange(codeExchange({ iss: other })))).toBe("refused");
	});

	it("refuses, asking the token endpoint nothing, an iss of the issuer's origin in another form", async () => {
		const token = await idToken({ iss: loopbackIssuer });
		const { upstream, asked } = await open({
			settings: { issuer: loopbackIssuer },
			more: { ...servedAt(loopbackIssuer), [`${loopbackIssuer}/token`]: () => granted(token) },
			refusals: loopbackRefusals(),
		});
		for (const iss of [`${loopbackIssuer}/`, `${loopbackIssuer}/other`, "HTTP://127.0.0.1:9100"]) {
			expect(await outcome(upstream.exchange(codeExchange({ iss }))), iss).toBe("refused");
		}
		expect(asked.some((a) => a.url === `${loopbackIssuer}/token`)).toBe(false);
	});

	it("refuses at boot, at its key, an endpoint outbound's policy refuses, asking with the hosts it sends to", async () => {
		const settings = settingsOf(asymmetric, policyRefusing(["idp.example"]));
		const base = { issuer, "client-id": "c", "client-secret": "s" };
		const refusalsOf = (more: Record<string, unknown>) =>
			settings.safeParse({ ...base, ...more }).error?.issues.map((i) => [i.path, i.message]);
		const refused = (key: string) => [
			[key],
			`outbound's destination policy refuses it: ${notAllowed}`,
		];
		policyAsked.length = 0;
		expect(refusalsOf({ "endpoint-hosts": ["x.example"] })).toEqual([refused("issuer")]);
		expect(policyAsked).toEqual([
			{
				url: `${issuer}/.well-known/openid-configuration`,
				narrower: { hosts: ["idp.example", "x.example"], internal: issuer },
			},
		]);
		const elsewhere = "https://keys.other.example/jwks";
		policyAsked.length = 0;
		expect(refusalsOf({ ...givenEndpoints, "jwks-uri": elsewhere })).toEqual([
			refused("token-endpoint"),
		]);
		const hosts = ["idp.example", "keys.other.example"];
		expect(policyAsked).toEqual([
			{ url: `${issuer}/token`, narrower: { hosts, internal: `${issuer}/token` } },
			{ url: elsewhere, narrower: { hosts, internal: elsewhere } },
		]);
		expect(refusalsOf(givenEndpoints)).toEqual([refused("token-endpoint"), refused("jwks-uri")]);
	});

	it("refuses at boot an endpoint-hosts entry that is no host, `*` included", () => {
		const settings = settingsOf(asymmetric, policyRefusing());
		const base = { issuer, "client-id": "c", "client-secret": "s" };
		for (const entry of ["*.idp-cdn.example", "*", "idp.example:443", "https://idp.example"]) {
			const issues = settings.safeParse({ ...base, "endpoint-hosts": [entry] }).error?.issues;
			expect(
				issues?.map((i) => i.path),
				entry,
			).toEqual([["endpoint-hosts", 0]]);
		}
		const taken = ["idp-cdn.example", ".idp-cdn.example", "192.0.2.1", "[2001:db8::1]"];
		expect(settings.parse({ ...base, "endpoint-hosts": taken })["endpoint-hosts"]).toEqual(taken);
	});

	it("refuses at boot, under issuer and naming it, a description's token endpoint or key set outbound's policy refuses", async () => {
		const cdn = "https://tokens.idp-cdn.example";
		const named = { "endpoint-hosts": ["tokens.idp-cdn.example"] };
		const refused = ["tokens.idp-cdn.example"];
		for (const [name, description] of [
			["token_endpoint", { token_endpoint: `${cdn}/token` }],
			["jwks_uri", { jwks_uri: `${cdn}/jwks` }],
		] as const) {
			const thrown = await open({ description, settings: named, refused }).catch((e) => e);
			expect(thrown, name).toBeInstanceOf(UpstreamMismatch);
			expect([thrown.at, thrown.message], name).toEqual([
				["issuer"],
				`outbound's destination policy refuses the description's ${name}: ${notAllowed}`,
			]);
			await expect(open({ description, settings: named }), name).resolves.toBeDefined();
		}
	});

	it("refuses at boot, under issuer and naming outbound's reason, a description outbound refuses to fetch", async () => {
		for (const reason of ["special-address", "redirect"] as const) {
			const describes = () => {
				throw new DestinationRefused(reason);
			};
			const thrown = await open({ describes }).catch((e) => e);
			expect(thrown, reason).toBeInstanceOf(UpstreamMismatch);
			expect([thrown.at, thrown.message], reason).toEqual([
				["issuer"],
				`outbound's destination policy refuses the description: ${reason}`,
			]);
		}
		// A refusal a second bundled copy of outbound-policy throws: another class, the same mark.
		const describes = () => {
			throw Object.assign(new Error("outbound destination refused: redirect"), {
				[Symbol.for("@mod/outbound-policy.destination-refused")]: true,
				reason: "redirect",
			});
		};
		const fromAnotherCopy = await open({ describes }).catch((e) => e);
		expect(fromAnotherCopy).toBeInstanceOf(UpstreamMismatch);
		// An issuer that cannot be reached is not one that does not match.
		const unreachable = await open({ describes: () => "unreachable" }).catch((e) => e);
		expect(isUnavailable(unreachable)).toBe(true);
	});

	it("reaches as the operator's URL the issuer for all its description names, and each given endpoint for itself", async () => {
		const described = await answering(await idToken());
		await described.upstream.exchange(codeExchange());
		expect(described.asked.map((a) => [a.url, a.internal])).toEqual([
			[`${issuer}/.well-known/openid-configuration`, issuer],
			[`${issuer}/token`, issuer],
			[`${issuer}/jwks`, issuer],
		]);
		const elsewhere = "https://keys.other.example/jwks";
		const given = await answering(await idToken(), {
			settings: { ...givenEndpoints, "jwks-uri": elsewhere },
			more: { [elsewhere]: () => ok({ keys: [rsa.jwk] }) },
		});
		await given.upstream.exchange(codeExchange());
		expect(given.asked.map((a) => [a.url, a.internal])).toEqual([
			[`${issuer}/token`, `${issuer}/token`],
			[elsewhere, elsewhere],
		]);
	});

	it("reaches an issuer at a private address as the operator's URL, only where outbound.internal-hosts lists its host", async () => {
		const corp = "https://idp.corp";
		/** outbound itself, every name resolving to a private address, a request ending fast. */
		const reachOf = (internal: readonly string[]) => {
			const settings = { allow: ["idp.corp"], "internal-hosts": internal, timeout: "300ms" };
			const paths = outboundOver(outboundSection.parse(settings), async () => ["10.0.0.5"]);
			return {
				outbound: { fetch: paths.fetch } as Outbound,
				refusals: { explained: paths.explained },
			};
		};
		const settings = { issuer: corp };
		// Unlisted, the address refuses the description at the issuer, as an upstream that does not match.
		const refused = await open({ settings, reach: reachOf([]) }).catch((e) => e);
		expect([refused instanceof UpstreamMismatch, refused.at]).toEqual([true, ["issuer"]]);
		// Listed, it gets past the address to the connection, which cannot be made here.
		const reached = await open({ settings, reach: reachOf(["idp.corp"]) }).catch((e) => e);
		expect(isUnavailable(reached)).toBe(true);
	});

	it("reaches an endpoint the operator gives on another host", async () => {
		const { upstream, asked } = await answering(await idToken(), {
			settings: { ...givenEndpoints, "jwks-uri": "https://keys.other.example/jwks" },
			more: { "https://keys.other.example/jwks": () => ok({ keys: [rsa.jwk] }) },
		});
		expect(await upstream.exchange(codeExchange())).toMatchObject({ subject: "u-alice" });
		expect(asked.map((a) => a.url)).toContain("https://keys.other.example/jwks");
	});

	it("takes its endpoints as given without discovery, and only all three together", async () => {
		const { upstream, settings, asked } = await open({ settings: givenEndpoints });
		expect(upstream.authorizationUrl(authorizationStart)).toMatch(/^https:\/\/idp\.example\/a\?/);
		expect(asked).toEqual([]);
		const base = { issuer, "client-id": "c", "client-secret": "s" };
		expect(
			settings.safeParse({ ...base, discovery: false, "token-endpoint": `${issuer}/t` }).success,
		).toBe(false);
		for (const left of ["authorization-endpoint", "token-endpoint", "jwks-uri"] as const) {
			const { [left]: _, ...rest } = givenEndpoints;
			expect(settings.safeParse({ ...base, ...rest }).success, left).toBe(false);
		}
		expect(settings.safeParse({ ...base, "jwks-uri": `${issuer}/j` }).success).toBe(false);
		expect(settings.safeParse({ ...base, scopes: ["profile"] }).success).toBe(false);
		// Half a surrogate pair cannot be sent: boot refuses it, not every exchange.
		for (const name of ["client-id", "client-secret"]) {
			expect(settings.safeParse({ ...base, [name]: "a\uD800" }).success, name).toBe(false);
			expect(settings.safeParse({ ...base, [name]: "a\uD83D\uDE00" }).success, name).toBe(true);
		}
		expect(settings.safeParse({ ...base, algorithms: ["ES512", "PS384"] }).success).toBe(true);
		for (const alg of ["none", "HS256"]) {
			expect(settings.safeParse({ ...base, algorithms: [alg] }).success, alg).toBe(false);
		}
		expect(settings.safeParse({ ...base, algorithms: [] }).success).toBe(false);
		// The refusal names the algorithms taken, never the one refused.
		const refused = settings.safeParse({ ...base, algorithms: ["ES256", "HS256"] }).error?.issues;
		expect(refused).toEqual([
			expect.objectContaining({
				code: "invalid_value",
				path: ["algorithms", 1],
				values: expect.arrayContaining([...asymmetric]),
			}),
		]);
		expect(refused?.[0]?.message).not.toMatch(/HS256|none/);
	});

	it("refuses at boot an issuer or endpoint that is empty or no URL, never throwing on it", () => {
		const settings = settingsOf(asymmetric, policyRefusing());
		const client = { "client-id": "c", "client-secret": "s" };
		const given = {
			discovery: false,
			"authorization-endpoint": `${issuer}/a`,
			"token-endpoint": `${issuer}/t`,
			"jwks-uri": `${issuer}/j`,
		};
		const cases: Record<string, unknown>[] = [];
		for (const value of ["", "not a url"]) {
			cases.push({ ...client, issuer: value });
			for (const name of [
				"authorization-endpoint",
				"token-endpoint",
				"jwks-uri",
				"end-session-endpoint",
			]) {
				cases.push({ ...client, issuer, ...given, [name]: value });
			}
		}
		for (const asked of cases) {
			const read = () => settings.safeParse(asked);
			expect(read, JSON.stringify(asked)).not.toThrow();
			expect(read().success, JSON.stringify(asked)).toBe(false);
		}
	});

	it("takes a clock skew of whole seconds from 0s to 5m, written with its unit", () => {
		const settings = settingsOf(asymmetric, policyRefusing());
		const base = { issuer, "client-id": "c", "client-secret": "s" };
		const skewOf = (skew: unknown) => settings.safeParse({ ...base, "clock-skew": skew }).success;
		expect(["0s", "300s", "5m"].map(skewOf)).toEqual([true, true, true]);
		expect(["301s", "-1s", "1.5s", 30, "30"].map(skewOf)).toEqual(Array(5).fill(false));
	});

	it("gives each default as an operator writes it, read through the key's own schema", () => {
		const { shape } = settingsOf(asymmetric, policyRefusing());
		const byDefault = Object.entries(shape).filter(
			([, key]) => (key._zod.def.type as string) === "default",
		);
		expect(byDefault.map(([name]) => name)).toEqual([]);
		// A default algorithm external-jwt does not know is refused, as one the operator wrote is.
		const base = { issuer, "client-id": "c", "client-secret": "s" };
		expect(settingsOf(["RS256"], policyRefusing()).safeParse(base).success).toBe(false);
	});

	it("takes an id_token's at_hash only as the access token's, by its signature's digest", async () => {
		const half = (digest: string, token: string) => {
			const full = createHash(digest).update(token).digest();
			return full.subarray(0, full.length / 2).toString("base64url");
		};
		const exchangedAt = async (claims: Record<string, unknown>) => {
			const token = await idToken(claims);
			const { upstream } = await open({ token: () => granted(token) });
			return outcome(upstream.exchange(codeExchange()));
		};
		const taken = { subject: "u-alice" };
		expect(await exchangedAt({ at_hash: half("sha256", "at") })).toMatchObject(taken);
		expect(await exchangedAt({})).toMatchObject(taken);
		for (const claims of [
			{ at_hash: half("sha256", "another") },
			{ at_hash: half("sha384", "at") },
			{ at_hash: half("sha256", "at").slice(1) },
			{ at_hash: 7 },
			{ at_hash: "" },
		]) {
			expect(await exchangedAt(claims), JSON.stringify(claims)).toBe("refused");
		}
	});

	it("exchanges the code with its verifier and the client's secret, and answers the id_token's subject", async () => {
		const token = await idToken({ amr: ["pwd", "mfa"] });
		const { upstream, asked } = await open({ token: () => granted(token) });
		expect(await upstream.exchange(codeExchange())).toMatchObject({
			subject: "u-alice",
			amr: ["pwd", "mfa"],
		});
		const sent = asked.find((a) => a.url === `${issuer}/token`);
		expect(sent?.request.method).toBe("POST");
		expect(Object.fromEntries(new URLSearchParams(String(sent?.request.body)))).toEqual({
			grant_type: "authorization_code",
			code: "c",
			redirect_uri: codeExchange().redirectUri,
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
	});

	it("reads the profile from the checked id_token, its email verified only by a boolean true", async () => {
		const said = { email: "a@corp.example", name: "Alice", picture: "https://p.example/a" };
		const profileOf = async (claims: Record<string, unknown>) =>
			((await exchanged(await idToken(claims))) as { profile?: unknown }).profile;
		expect(await profileOf({ ...said, email_verified: true, groups: ["admin"] })).toEqual({
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

	it("says when the upstream logged the user in, and gives the upstream's clock its allowance", async () => {
		const at = Math.floor(now / 1000) - 120;
		const { upstream } = await answering(await idToken({ auth_time: at }));
		expect(await upstream.exchange(codeExchange())).toMatchObject({ authenticatedAt: at * 1000 });
		expect(upstream.clockSkewMs).toBe(30_000);
		expect(await exchanged(await idToken())).not.toHaveProperty("authenticatedAt");
		const soon = await idToken({ auth_time: Math.floor(now / 1000) + 30 });
		expect(await exchanged(soon)).toMatchObject({ subject: "u-alice" });
	});

	it("refuses an auth_time past our clock by more than the skew, before the epoch, or not a finite number", async () => {
		const refused: Record<string, () => Promise<string>> = {
			"past the skew": () => idToken({ auth_time: Math.floor(now / 1000) + 31 }),
			"not a number": () => idToken({ auth_time: "yesterday" }),
			"before the epoch": () => idToken({ auth_time: -1 }),
			// JSON reads a number past its range as infinite.
			"past the range of numbers": () =>
				written(JSON.stringify(claimsWith({ auth_time: 0 })).replace(/0}$/, "-1e400}")),
		};
		for (const [label, make] of Object.entries(refused)) {
			expect(await exchanged(await make()), label).toBe("refused");
		}
	});

	it("sends the client's secret in the form where the operator says so", async () => {
		const { upstream, asked } = await answering(await idToken(), {
			settings: { "token-auth": "client_secret_post" },
		});
		await upstream.exchange(codeExchange());
		const sent = asked.find((a) => a.url === `${issuer}/token`);
		const form = new URLSearchParams(String(sent?.request.body));
		expect([form.get("client_id"), form.get("client_secret")]).toEqual(["client", "s3cr:et"]);
		expect(sent?.request.credential).toBeUndefined();
	});

	it("refuses an answer from another issuer before using its code, and one without iss where iss is asked", async () => {
		const token = await idToken();
		const { upstream, asked } = await answering(token);
		for (const iss of ["https://evil.example", ""]) {
			expect(await outcome(upstream.exchange(codeExchange({ iss }))), iss).toBe("refused");
		}
		expect(asked.some((a) => a.url === `${issuer}/token`)).toBe(false);
		expect(await outcome(upstream.exchange(codeExchange({ iss: undefined })))).toMatchObject({
			subject: "u-alice",
		});
		const asking: Record<string, Omit<World, "token">> = {
			"the description offers iss": {
				description: { authorization_response_iss_parameter_supported: true },
			},
			"the operator requires iss": { settings: { "require-iss": true } },
		};
		for (const [label, world] of Object.entries(asking)) {
			const strict = await answering(token, world);
			expect(await outcome(strict.upstream.exchange(codeExchange({ iss: undefined }))), label).toBe(
				"refused",
			);
		}
	});

	it("warns at boot when neither the operator nor the description requires iss", async () => {
		const notRequired = [{ event: "idp-oidc.iss_not_required", fields: { idp: "corp" } }];
		expect((await open()).warned).toEqual(notRequired);
		expect((await open({ settings: givenEndpoints })).warned).toEqual(notRequired);
		const asking: Record<string, World> = {
			"the description offers iss": {
				description: { authorization_response_iss_parameter_supported: true },
			},
			"the operator requires iss": { settings: { "require-iss": true } },
		};
		for (const [label, world] of Object.entries(asking)) {
			expect((await open(world)).warned, label).toEqual([]);
		}
	});

	it("refuses an id_token that does not hold", async () => {
		const hmac = new TextEncoder().encode("a".repeat(32));
		const cases: Record<
			string,
			{ readonly token: () => Promise<string>; readonly settings?: Record<string, unknown> }
		> = {
			"another key": { token: () => idToken({}, { ...other, jwk: { ...other.jwk, kid: "k1" } }) },
			"another issuer": { token: () => idToken({ iss: "https://evil.example" }) },
			"another audience": { token: () => idToken({ aud: "someone" }) },
			"many audiences, no azp": { token: () => idToken({ aud: ["client", "x"] }) },
			"azp not the client": { token: () => idToken({ aud: "client", azp: "x" }) },
			"another nonce": { token: () => idToken({ nonce: "other" }) },
			"no subject": { token: () => idToken({ sub: "" }) },
			"an audience not a string": {
				token: () => written(JSON.stringify(claimsWith({ aud: ["client", 5], azp: "client" }))),
			},
			"amr not strings": { token: () => idToken({ amr: ["pwd", 1] }) },
			HMAC: {
				token: () =>
					new SignJWT({ nonce: "n" })
						.setProtectedHeader({ alg: "HS256", kid: "k1" })
						.setIssuer(issuer)
						.setSubject("u")
						.setAudience("client")
						.setExpirationTime(Math.floor(now / 1000) + 300)
						.sign(hmac),
			},
			"not allowed": { token: () => idToken(), settings: { algorithms: ["ES256"] } },
		};
		for (const [label, { token, settings }] of Object.entries(cases)) {
			expect(await exchanged(await token(), settings ? { settings } : {}), label).toBe("refused");
		}
		const { upstream } = await answering(await idToken());
		expect(await outcome(upstream.exchange(codeExchange({ nonce: "x" })))).toBe("refused");
		for (const aud of [["client", "x"], ["client"]]) {
			const listed = await idToken({ aud, ...(aud.length > 1 ? { azp: "client" } : {}) });
			expect(await exchanged(listed), aud.join()).toMatchObject({ subject: "u-alice" });
		}
	});

	it("takes by default one algorithm for each kind of key, PS256 only where the operator names it", async () => {
		const base = { issuer, "client-id": "c", "client-secret": "s" };
		const read = settingsOf(asymmetric, policyRefusing()).parse(base);
		expect(read.algorithms).toEqual(["RS256", "ES256", "EdDSA"]);
		const ps = await idToken({}, pss, "PS256");
		const keys = [pss.jwk];
		expect(await exchanged(ps, { keys })).toBe("refused");
		// One RSA algorithm named, so a key of the IdP's set with no `alg` is not ambiguous.
		const named = { keys, settings: { algorithms: ["PS256"] } };
		expect(await exchanged(ps, named)).toMatchObject({ subject: "u-alice" });
		expect(await exchanged(await idToken(), { settings: { algorithms: ["PS256"] } })).toBe(
			"refused",
		);
	});

	it("reads each key of the IdP's set under one algorithm, its own alg or the one taken for its kind", async () => {
		const both = { settings: { algorithms: ["RS256", "PS256"] } };
		// Two RSA algorithms taken: a key naming no alg is used under neither.
		expect(await exchanged(await idToken(), both)).toBe("refused");
		expect(await exchanged(await idToken({}, pss, "PS256"), { ...both, keys: [pss.jwk] })).toBe(
			"refused",
		);
		// A key naming its alg is read under that one alone, never under the other.
		const named = { ...both, keys: [{ ...pss.jwk, alg: "PS256" }] };
		expect(await exchanged(await idToken({}, pss, "PS256"), named)).toMatchObject({
			subject: "u-alice",
		});
		const rs = { ...both, keys: [{ ...rsa.jwk, alg: "RS256" }] };
		expect(await exchanged(await idToken(), rs)).toMatchObject({ subject: "u-alice" });
		expect(await exchanged(await idToken({}, pss, "PS256"), rs)).toBe("refused");
		// A key whose alg is not taken is used under none.
		const untaken = { keys: [{ ...rsa.jwk, alg: "RS256" }], settings: { algorithms: ["ES256"] } };
		expect(await exchanged(await idToken(), untaken)).toBe("refused");
	});

	it("refuses an id_token without a numeric issue time, or one issued past the upstream's skew", async () => {
		const answered = async (iat: unknown) => exchanged(await idToken({ iat }));
		expect(await answered(null)).toBe("refused");
		expect(await answered("yesterday")).toBe("refused");
		expect(await answered(Math.floor(now / 1000) + 3600)).toBe("refused");
		expect(await answered(Math.floor(now / 1000) + 31)).toBe("refused");
		expect(await answered(Math.floor(now / 1000) + 30)).toMatchObject({ subject: "u-alice" });
		expect(await answered(Math.floor(now / 1000) - 86_400)).toMatchObject({ subject: "u-alice" });
	});

	it("refuses an id_token not yet valid past the upstream's skew", async () => {
		expect(await exchanged(await idToken({ nbf: Math.floor(now / 1000) + 31 }))).toBe("refused");
		expect(await exchanged(await idToken({ nbf: Math.floor(now / 1000) + 29 }))).toMatchObject({
			subject: "u-alice",
		});
	});

	it("allows the upstream's clock its skew, and no more", async () => {
		const token = await idToken();
		const { upstream } = await open({ token: () => granted(token) });
		now += 300_000 + 29_000;
		expect(await outcome(upstream.exchange(codeExchange()))).toMatchObject({ subject: "u-alice" });
		now += 1000;
		expect(await outcome(upstream.exchange(codeExchange()))).toBe("refused");
	});

	it("is unavailable when external-jwt has no key set to give", async () => {
		const token = await idToken();
		const { upstream } = await open({ token: () => granted(token), keysUnreachable: true });
		expect(await outcome(upstream.exchange(codeExchange()))).toBe("unavailable");
	});

	it("is refused by a token endpoint that refuses, and unavailable where it cannot be reached", async () => {
		const token = await idToken();
		const cases: Record<string, [Handler, string]> = {
			"a 400": [() => ({ ...granted(token), status: 400 }), "refused"],
			"a destination outbound refuses": [() => "broken", "refused"],
			"no id_token": [() => ok({ access_token: "x" }), "refused"],
			unreachable: [() => "unreachable", "unavailable"],
		};
		for (const [label, [answer, expected]] of Object.entries(cases)) {
			const { upstream } = await open({ token: answer });
			expect(await outcome(upstream.exchange(codeExchange())), label).toBe(expected);
		}
	});

	it("hands over the tokens the token endpoint gave, with the id_token it checked", async () => {
		const token = await idToken();
		const answer = {
			refresh_token: "rt",
			expires_in: 0,
			scope: "openid email",
			token_type: "DPoP",
		};
		const { upstream } = await open({ token: () => granted(token, answer) });
		expect((await upstream.exchange(codeExchange())).tokens).toEqual({
			accessToken: "at",
			tokenType: "DPoP",
			refreshToken: "rt",
			idToken: token,
			expiresInSeconds: 0,
			scope: ["openid", "email"],
		});
		// A scope left out is the one asked for.
		const plain = await open({
			token: () => granted(token),
			settings: { scopes: ["openid", "profile"] },
		});
		expect((await plain.upstream.exchange(codeExchange())).tokens).toEqual({
			accessToken: "at",
			tokenType: "Bearer",
			idToken: token,
			scope: ["openid", "profile"],
		});
	});

	it("refuses a token answer without an access token and its type, or with a lifetime that is none", async () => {
		const token = await idToken();
		const answers: Record<string, unknown> = {
			"no access token": { id_token: token, token_type: "Bearer" },
			"no token type": { id_token: token, access_token: "at" },
			"an empty token type": { id_token: token, access_token: "at", token_type: "" },
			"a negative lifetime": {
				id_token: token,
				access_token: "at",
				token_type: "Bearer",
				expires_in: -1,
			},
			"a lifetime as text": {
				id_token: token,
				access_token: "at",
				token_type: "Bearer",
				expires_in: "300",
			},
			"no id_token": { access_token: "at", token_type: "Bearer" },
		};
		for (const [label, answer] of Object.entries(answers)) {
			const { upstream } = await open({ token: () => ok(answer) });
			expect(await outcome(upstream.exchange(codeExchange())), label).toBe("refused");
		}
	});

	it("refreshes tokens at the token endpoint, handing on no id_token from it", async () => {
		const { upstream, asked } = await open({
			token: () => ok({ access_token: "at-2", token_type: "Bearer", id_token: "unchecked" }),
		});
		expect(await offered(upstream.refresh, "refresh")("rt", ["openid", "email"])).toEqual({
			kind: "refreshed",
			tokens: { accessToken: "at-2", tokenType: "Bearer", scope: ["openid", "email"] },
		});
		const sent = asked.find((a) => a.url === `${issuer}/token`);
		expect(Object.fromEntries(new URLSearchParams(String(sent?.request.body)))).toEqual({
			grant_type: "refresh_token",
			refresh_token: "rt",
			scope: "openid email",
		});
		expect(sent?.request.credential).toMatch(/^Basic /);
		expect(sent?.hosts).toEqual(["idp.example"]);
		await offered(upstream.refresh, "refresh")("rt", []);
		const unscoped = asked.filter((a) => a.url === `${issuer}/token`).at(-1);
		expect(Object.fromEntries(new URLSearchParams(String(unscoped?.request.body)))).toEqual({
			grant_type: "refresh_token",
			refresh_token: "rt",
		});
	});

	it("tells a refused refresh token, a limit and an upstream down apart", async () => {
		const withStatus = (status: number, json: unknown, headers: [string, string][] = []) => ({
			...ok(json),
			status,
			headers: new Map(headers),
		});
		const cases: Record<string, [Handler, unknown]> = {
			invalid_grant: [() => withStatus(400, { error: "invalid_grant" }), { kind: "invalid_grant" }],
			"a limit": [
				() => withStatus(429, {}, [["retry-after", "7"]]),
				{ kind: "limited", retryAfterSeconds: 7 },
			],
			"a limit with a date": [
				() => withStatus(429, {}, [["retry-after", "Wed, 21 Oct 2026 07:28:00 GMT"]]),
				{ kind: "limited" },
			],
			"a limit with an empty retry-after": [
				() => withStatus(429, {}, [["retry-after", ""]]),
				{ kind: "limited" },
			],
			down: [() => withStatus(503, { error: "invalid_grant" }), "unavailable"],
			unreachable: [() => "unreachable", "unavailable"],
			"another error": [() => withStatus(400, { error: "invalid_scope" }), "refused"],
			"invalid_grant on a 401": [() => withStatus(401, { error: "invalid_grant" }), "refused"],
			"no access token": [() => ok({ token_type: "Bearer" }), "refused"],
		};
		for (const [label, [token, expected]] of Object.entries(cases)) {
			const { upstream } = await open({ token });
			expect(await outcome(offered(upstream.refresh, "refresh")("rt", [])), label).toEqual(
				expected,
			);
		}
	});

	it("ends the upstream's session where it names an end of session", async () => {
		const { upstream } = await open({
			description: { end_session_endpoint: `${issuer}/logout?ui=1` },
		});
		const endSession = offered(upstream.endSession, "endSession");
		const url = new URL(
			endSession({
				idTokenHint: "idt",
				postLogoutRedirectUri: "https://app.example/bye",
				state: "st",
			}),
		);
		expect(`${url.origin}${url.pathname}`).toBe(`${issuer}/logout`);
		expect(Object.fromEntries(url.searchParams)).toEqual({
			ui: "1",
			id_token_hint: "idt",
			post_logout_redirect_uri: "https://app.example/bye",
			state: "st",
			client_id: "client",
		});
		expect(new URL(endSession({})).search).toBe("?ui=1&client_id=client");
		expect((await open()).upstream.endSession).toBeUndefined();
		const configured = await open({
			settings: { ...givenEndpoints, "end-session-endpoint": `${issuer}/bye` },
		});
		expect(offered(configured.upstream.endSession, "endSession")({})).toBe(
			`${issuer}/bye?client_id=client`,
		);
		expect(
			configured.settings.safeParse({
				issuer,
				"client-id": "c",
				"client-secret": "s",
				"end-session-endpoint": `${issuer}/bye`,
			}).success,
		).toBe(false);
	});

	it("asks for offline access to delegate, with the delegation's scopes and resource", async () => {
		const { upstream } = await open();
		const url = delegationUrl(upstream, delegationStart);
		expect(`${url.origin}${url.pathname}`).toBe(`${issuer}/authorize`);
		expect(Object.fromEntries(url.searchParams)).toEqual({
			response_type: "code",
			client_id: "client",
			redirect_uri: "https://as.example/connect",
			scope: "openid offline_access files.read",
			state: "s",
			code_challenge: "c",
			code_challenge_method: "S256",
			nonce: "n",
			prompt: "consent",
			resource: "https://api.example/",
		});
	});

	it("passes a delegation's prompt and resource on without offline access, and refuses one without openid", async () => {
		const { upstream } = await open();
		const online = delegationUrl(upstream, {
			...delegationStart,
			scopes: ["openid"],
			prompt: "login",
		});
		expect(online.searchParams.get("prompt")).toBe("login");
		expect(online.searchParams.has("resource")).toBe(true);
		// Scopes without openid are refused as a value, never by a throw.
		const delegation = offered(upstream.delegation, "delegation");
		expect(delegation.authorizationUrl({ ...delegationStart, scopes: ["files.read"] })).toEqual({
			kind: "refused",
		});
	});

	it("exchanges a delegation's code for the checked login, its issuer and the tokens", async () => {
		const token = await idToken();
		const { upstream } = await open({
			token: () => granted(token, { refresh_token: "rt", scope: "openid files.read" }),
		});
		const scopes = ["openid", "offline_access", "files.read"];
		const delegation = offered(upstream.delegation, "delegation");
		expect(await delegation.exchange(delegatedExchange({ scopes }))).toEqual({
			subject: "u-alice",
			amr: [],
			issuer,
			tokens: {
				accessToken: "at",
				tokenType: "Bearer",
				refreshToken: "rt",
				idToken: token,
				scope: ["openid", "files.read"],
			},
		});
		// A scope left out is the one the delegation asked for (RFC 6749 §5.1).
		const silent = await open({ token: () => granted(token, { refresh_token: "rt" }) });
		const silentDelegation = offered(silent.upstream.delegation, "delegation");
		expect((await silentDelegation.exchange(delegatedExchange({ scopes }))).tokens.scope).toEqual(
			scopes,
		);
		expect(
			await outcome(
				delegation.exchange(delegatedExchange({ scopes, iss: "https://evil.example" })),
			),
		).toBe("refused");
		const forged = await idToken({ nonce: "other" });
		const unchecked = await open({ token: () => granted(forged, { scope: "openid" }) });
		const uncheckedDelegation = offered(unchecked.upstream.delegation, "delegation");
		expect(await outcome(uncheckedDelegation.exchange(delegatedExchange({ scopes })))).toBe(
			"refused",
		);
	});

	it("sends a delegation's resource with its code, and none without one", async () => {
		const token = await idToken();
		const { upstream, asked } = await open({ token: () => granted(token, { scope: "openid" }) });
		const sent = () =>
			Object.fromEntries(
				new URLSearchParams(
					String(asked.filter((a) => a.url === `${issuer}/token`).at(-1)?.request.body),
				),
			);
		const delegation = offered(upstream.delegation, "delegation");
		await delegation.exchange(delegatedExchange({ resource: "https://api.example/" }));
		expect(sent()).toEqual({
			grant_type: "authorization_code",
			code: "c",
			redirect_uri: "https://as.example/session/oauth/federation/corp/callback",
			code_verifier: "v",
			resource: "https://api.example/",
		});
		await delegation.exchange(delegatedExchange());
		expect(sent()).not.toHaveProperty("resource");
	});

	it("refreshes a delegation's tokens for its resource", async () => {
		const { upstream, asked } = await open({
			token: () => ok({ access_token: "at-2", token_type: "Bearer", scope: "openid" }),
		});
		const delegation = offered(upstream.delegation, "delegation");
		expect(await delegation.refresh("rt", ["openid"], "https://api.example/")).toEqual({
			kind: "refreshed",
			tokens: { accessToken: "at-2", tokenType: "Bearer", scope: ["openid"] },
		});
		const sent = asked.find((a) => a.url === `${issuer}/token`);
		expect(Object.fromEntries(new URLSearchParams(String(sent?.request.body)))).toEqual({
			grant_type: "refresh_token",
			refresh_token: "rt",
			scope: "openid",
			resource: "https://api.example/",
		});
	});

	it("contributes the oidc type, taking only external-jwt's algorithms and warning under the IdP's name", async () => {
		const stub = stubOutbound({
			[`${issuer}/.well-known/openid-configuration`]: () =>
				ok({
					issuer,
					authorization_endpoint: `${issuer}/authorize`,
					token_endpoint: `${issuer}/token`,
					jwks_uri: `${issuer}/jwks`,
				}),
		});
		const types = contract<readonly IdpType[]>("types");
		const recorded = recordingLog();
		const app = await assemble({
			modules: [
				defineModule({ name: "outbound", takes: [] }, (m) => [
					m.provide(outbound).by(() => stub.outbound),
					m.provide(outboundRefusals).by(() => policyRefusing()),
				]),
				externalJwtModule,
				idpOidc,
				defineModule({ name: "types", takes: [idpTypes] }, (m) => [
					m.provide(types).by((c) => c.collect(idpTypes)),
				]),
			],
			config: kernelConfig(),
			runtime: quietRuntime({ clock, log: recorded.log }),
		});
		const oidc = offered(
			app.get(types).find((type) => type.type === "oidc"),
			"the oidc type",
		);
		const base = { issuer, "client-id": "client", "client-secret": "s" };
		expect(oidc.settings.safeParse({ ...base, algorithms: ["HS256"] }).success).toBe(false);
		await oidc.open(oidc.settings.parse(base), {
			idp: "corp",
			redirectUri: "https://as.example/cb",
		});
		expect(
			recorded
				.lines()
				.filter((line) => line.event === "idp-oidc.iss_not_required")
				.map((line) => line.fields),
		).toEqual([{ idp: "corp" }]);
	});
});
