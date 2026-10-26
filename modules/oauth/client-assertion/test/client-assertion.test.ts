import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { type Client, type Clients, clientSources, clients } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import {
	clientSecret,
	clientsConfig,
	confidentialClient,
	publicClient,
} from "@mod/clients/testing";
import externalJwtModule from "@mod/external-jwt/module";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, BootRefused, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog, takesUnused, unavailableSwitch } from "@mod/kernel/testing";
import outboundModule from "@mod/outbound/module";
import { memoryRecords } from "@mod/records/testing";
import secretHashModule from "@mod/secret-hash/module";
import { tokenEndpointLocation } from "@mod/token-endpoint";
import { CompactSign, FlattenedSign, type JWTPayload, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { clientKeys, type Jwk, type SpentAssertions, spentAssertions } from "../src/contract.ts";
import { assertionMethod, assertionType } from "../src/method.ts";
import assertionModule from "../src/module.ts";
import { section } from "../src/section.ts";
import { clientAssertionConfig, clientKeysFor } from "../src/testing.ts";

const issuer = "https://issuer.example";
const tokenUrl = `${issuer}/oauth/token`;
let now = 1_800_000_000_000;
const seconds = () => Math.floor(now / 1000);
const recorded = recordingLog();
/** The newest warn line's reason. */
const lastWarned = () =>
	String(
		recorded
			.lines()
			.filter((line) => line.level === "warn")
			.at(-1)?.fields.reason,
	);
/** The ids the client sources were asked for. */
const looked: unknown[] = [];
const runtime = quietRuntime({
	clock: { now: () => now },
	random: { bytes: (n) => new Uint8Array(n) },
	log: recorded.log,
});

const ecPair = () => generateKeyPairSync("ec", { namedCurve: "P-256" });
const ec = ecPair();
const ed = generateKeyPairSync("ed25519");
const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = (key: KeyObject, extra: Record<string, unknown> = {}): Jwk => ({
	...(key.export({ format: "jwk" }) as Jwk),
	...extra,
});

async function boot({
	keys = [jwk(ec.publicKey, { kid: "ec" })] as readonly Jwk[],
	method = "private_key_jwt",
	issuerUrl = issuer,
	/** Where the token endpoint is; null for a deployment without a public origin. */
	tokenEndpoint = tokenUrl as string | null,
	/** The clients whose section accepts a loose audience. */
	loose = [] as readonly string[],
	/** The operator section's settings. */
	settings = {} as Parameters<typeof clientAssertionConfig>[0],
} = {}) {
	const stand = memoryRecords<true>(() => now, { shards: 1, perShard: 1 });
	const down = unavailableSwitch<SpentAssertions>("spent assertions");
	const location = defineModule({ name: "token-endpoint", takes: [] }, (m) => [
		m.provide(tokenEndpointLocation).by(() => ({ url: tokenEndpoint ?? undefined })),
	]);
	const source = defineModule({ name: "source", takes: [] }, (m) => [
		m.contribute(clientSources).by(() => ({
			find: async (id) => {
				looked.push(id);
				return undefined;
			},
		})),
	]);
	const spent = defineModule({ name: "spent", takes: [] }, (m) => [
		m
			.provide(spentAssertions)
			.by(() =>
				down.wrap({ save: (name, lifetimeMs) => stand.records.create(name, true, lifetimeMs) }),
			),
	]);
	// A client of a secret method also holds its secret, which clients requires at boot.
	const registeredAs = (id: string) => {
		const sections = clientKeysFor(
			keys,
			loose.includes(id) ? { "accept-loose-audience": true } : {},
		);
		return method === "private_key_jwt"
			? { id, kind: "confidential" as const, method, sections }
			: confidentialClient({ id, method, sections });
	};
	const input = {
		modules: [
			http,
			outboundModule,
			externalJwtModule,
			clientsModule,
			secretHashModule,
			issuerModule,
			assertionModule,
			spent,
			location,
			source,
		],
		config: {
			...kernelConfig(),
			outbound: {},
			...httpConfig({ "public-origin": issuer }),
			...issuerConfig({ url: issuerUrl }),
			...clientAssertionConfig(settings),
			...clientsConfig([
				registeredAs("app"),
				registeredAs("app:twin"),
				confidentialClient({ id: "post" }),
				publicClient({ id: "pub" }),
			]),
		},
		runtime,
	};
	const app = await assemble(input);
	return { app, c: app.get(clients), down, input };
}

/** The claims of a good assertion, changed as given; a claim given as undefined is left out. */
const claims = (extra: Record<string, unknown> = {}): JWTPayload =>
	Object.fromEntries(
		Object.entries({
			iss: "app",
			sub: "app",
			aud: issuer,
			exp: seconds() + 60,
			jti: `j-${Math.random()}`,
			...extra,
		}).filter(([, value]) => value !== undefined),
	);
type Header = { readonly alg: string; readonly kid?: string };
const sign = (
	payload: JWTPayload,
	key: KeyObject = ec.privateKey,
	header: Header = { alg: "ES256", kid: "ec" },
) => new SignJWT(payload).setProtectedHeader(header).sign(key);
/** An assertion signed with a shared secret, which no client key verifies. */
const signedWithSecret = () =>
	new SignJWT(claims()).setProtectedHeader({ alg: "HS256" }).sign(new Uint8Array(32));
/** A form request; a list gives a field more than once. */
const asked = (form: Record<string, string | readonly string[]>) =>
	testRequest({
		method: "POST",
		form: new Map(Object.entries(form).map(([k, v]) => [k, [v].flat()])),
	});
/** A JSON body request. */
const posted = (json: Record<string, unknown>) => testRequest({ method: "POST", json });
const presenting = (assertion: string, extra: Record<string, string> = {}) =>
	asked({ client_assertion_type: assertionType, client_assertion: assertion, ...extra });
const outcome = async (c: Clients, request: ReturnType<typeof asked>) => {
	const result = await c.authenticate(request);
	return result.kind === "authenticated" ? result.client.id : result.reason;
};
/** The outcome of an assertion with these claims, signed as given, carrying `form` beside it. */
const tried = async (
	c: Clients,
	extra: Record<string, unknown> = {},
	form: Record<string, string> = {},
	key?: KeyObject,
	header?: Header,
) => outcome(c, presenting(await sign(claims(extra), key, header), form));

describe("private_key_jwt", () => {
	it("authenticates a client by an assertion signed with its key, for the issuer as one string [rfc7523-3-i] [rfc7521-5.2-h] [oidc-core-9-j]", async () => {
		const { c } = await boot();
		expect(await tried(c)).toBe("app");
		expect(await tried(c, {}, { client_id: "app" })).toBe("app");
		expect(await tried(c, { aud: `${issuer}/other` })).toBe("bad_credentials");
	});

	it("refuses an assertion for the token endpoint, or naming its audience in a list, before spending its jti", async () => {
		const { c } = await boot();
		for (const aud of [tokenUrl, [issuer], [tokenUrl], ["x", issuer], [issuer, tokenUrl]]) {
			expect(await tried(c, { aud, jti: "kept" }), JSON.stringify(aud)).toBe("bad_credentials");
			expect(lastWarned()).toBe("audience");
		}
		expect(await tried(c, { jti: "kept" })).toBe("app");
	});

	it("names the asymmetric algorithms an assertion may be signed with: by default one for each kind of key [oidc-discovery-3-ad]", async () => {
		const { c } = await boot();
		expect(c.signingAlgorithms()).toEqual(["RS256", "ES256", "ES384", "ES512", "EdDSA"]);
		const named = await boot({ settings: { algorithms: ["RS256", "PS256", "RS256"] } });
		expect(named.c.signingAlgorithms()).toEqual(["RS256", "PS256"]);
		for (const algorithms of [[], ["HS256"], ["none"]]) {
			expect(section.safeParse({ algorithms }).success, String(algorithms)).toBe(false);
		}
	});

	it("warns at each start of every registered client accepting a loose audience, by its id", async () => {
		const warned = () =>
			recorded
				.lines()
				.filter((line) => line.event === "client-assertion.accept_loose_audience")
				.map(({ level, fields }) => ({ level, fields }));
		const before = warned().length;
		const { app } = await boot({ loose: ["app:twin"] });
		expect(warned()).toHaveLength(before);
		await app.start();
		expect(warned().slice(before)).toEqual([{ level: "warn", fields: { client: "app:twin" } }]);
		await app.stop();
		const strict = await boot();
		await strict.app.start();
		expect(warned()).toHaveLength(before + 1);
		await strict.app.stop();
	});

	it("also takes the token endpoint's location, and lists, from a client accepting a loose audience, logging each", async () => {
		const tenant = `${issuer}/tenant`;
		const { c } = await boot({ issuerUrl: tenant, loose: ["app"] });
		const loosely = () =>
			recorded.lines().filter((line) => line.event === "client-assertion.loose_audience");
		const before = loosely().length;
		expect(await tried(c, { aud: tenant })).toBe("app");
		expect(loosely()).toHaveLength(before);
		for (const aud of [tokenUrl, [tokenUrl], ["x", tenant]]) {
			expect(await tried(c, { aud }), JSON.stringify(aud)).toBe("app");
		}
		expect(loosely()).toHaveLength(before + 3);
		expect(loosely().at(-1)).toMatchObject({ level: "warn", fields: { client: "app" } });
		// The token endpoint's own location, whatever path the issuer has.
		expect(await tried(c, { aud: `${tenant}/oauth/token` })).toBe("bad_credentials");
		expect(await tried(c, { aud: ["x"] })).toBe("bad_credentials");
		// Each client's own: another is held to the issuer alone.
		const twin = { iss: "app:twin", sub: "app:twin" };
		expect(await tried(c, { ...twin, aud: tokenUrl })).toBe("bad_credentials");
		expect(await tried(c, { ...twin, aud: tenant })).toBe("app:twin");
		const nowhere = await boot({ tokenEndpoint: null }).catch((error) => error);
		expect(nowhere).toBeInstanceOf(BootRefused);
	});

	it("takes the client from client_id when given, which the assertion's issuer and subject must match [rfc7523-3-g] [rfc7521-5.2-f] [oidc-core-9-i] [rfc7521-5.2-c] [oidc-core-9-h] [rfc7521-4.2-c]", async () => {
		const { c } = await boot();
		expect(await tried(c, {}, { client_id: "other" })).toBe("unknown_client");
		expect(await tried(c, { sub: "x" })).toBe("bad_credentials");
		expect(await tried(c, { iss: "x" }, { client_id: "app" })).toBe("bad_credentials");
		expect(await outcome(c, presenting("not.a.jwt"))).toBe("unknown_client");
		// A non-string iss names no client: no lookup ever gets 7.
		expect(await tried(c, { iss: 7 })).toBe("unknown_client");
		expect(looked).not.toContain(7);
		expect(await tried(c, { iss: "x", sub: "x" }, { client_id: "app" })).toBe("bad_credentials");
	});

	it("takes an assertion once per client and jti [oidc-core-9-l]", async () => {
		const { c } = await boot();
		const once = await sign(claims({ jti: "same" }));
		expect(await outcome(c, presenting(once))).toBe("app");
		expect(await outcome(c, presenting(once))).toBe("bad_credentials");
		expect(lastWarned()).toBe("used before");
		expect(await tried(c, { jti: "same" })).toBe("bad_credentials");
		// Another client's jti is its own, however the two read side by side.
		const twin = (jti: string) => tried(c, { iss: "app:twin", sub: "app:twin", jti });
		expect(await twin("same")).toBe("app:twin");
		expect(await tried(c, { jti: "twin:next" })).toBe("app");
		expect(await twin("next")).toBe("app:twin");
		expect(await tried(c, { jti: ":twin-joined" })).toBe("app");
		expect(await twin("-joined")).toBe("app:twin");
	});

	it("spends the jti last, and remembers it past the assertion's end [oidc-core-9-l]", async () => {
		const { c } = await boot();
		expect(await tried(c, { jti: "late", aud: "elsewhere" })).toBe("bad_credentials");
		expect(await tried(c, { jti: "late" })).toBe("app");
		const kept = () => tried(c, { jti: "kept", exp: seconds() + 10 });
		expect(await kept()).toBe("app");
		// Past exp and the allowance.
		now += 10_000 + 30_000;
		expect(await kept()).toBe("bad_credentials");
		// Within the store's clock margin.
		now += 59_999;
		expect(await kept()).toBe("bad_credentials");
		// Past the margin.
		now += 1;
		expect(await kept()).toBe("app");
	});

	it("is unavailable when the store cannot tell", async () => {
		const { c, down } = await boot();
		down.failNext("save");
		await expect(c.authenticate(presenting(await sign(claims())))).rejects.toSatisfy(isUnavailable);
	});

	it("bounds the assertion's times by the lifetime cap and the clock allowance [rfc7523-3-m] [rfc7521-5.2-j] [rfc7523-3-o] [rfc7521-5.2-l] [rfc7523-3-q]", async () => {
		const { c } = await boot();
		const at = (extra: Record<string, unknown>) => tried(c, extra);
		expect(await at({ exp: seconds() - 29 })).toBe("app");
		expect(await at({ exp: seconds() - 30 })).toBe("bad_credentials");
		expect(await at({ exp: seconds() + 3630 })).toBe("app");
		expect(await at({ exp: seconds() + 3631 })).toBe("bad_credentials");
		expect(await at({ exp: undefined })).toBe("bad_credentials");
		expect(await at({ iat: seconds() + 30 })).toBe("app");
		expect(await at({ iat: seconds() + 31 })).toBe("bad_credentials");
		expect(await at({ iat: seconds() - 3630 })).toBe("app");
		expect(await at({ iat: seconds() - 3631 })).toBe("bad_credentials");
		expect(await at({ nbf: seconds() + 30 })).toBe("app");
		expect(await at({ nbf: seconds() + 31 })).toBe("bad_credentials");
		expect(await at({ jti: undefined })).toBe("bad_credentials");
		expect(await at({ jti: "j".repeat(256) })).toBe("app");
		expect(await at({ jti: "j".repeat(257) })).toBe("bad_credentials");
		expect(await at({ jti: "" })).toBe("bad_credentials");
		expect(await at({ jti: "j\ud800" })).toBe("bad_credentials");
	});

	it("verifies with the one key the header picks, by asymmetric algorithms only [rfc7523-3-u] [rfc7521-5.2-n] [rfc8414-2-i]", async () => {
		const { c } = await boot({
			keys: [jwk(ec.publicKey, { kid: "ec" }), jwk(ed.publicKey), jwk(rsa.publicKey, { kid: "r" })],
		});
		const by = (key: KeyObject, header: Header) => tried(c, {}, {}, key, header);
		expect(await by(ec.privateKey, { alg: "ES256", kid: "ec" })).toBe("app");
		expect(await by(ec.privateKey, { alg: "ES256" })).toBe("app");
		expect(await by(ed.privateKey, { alg: "EdDSA" })).toBe("app");
		expect(await by(rsa.privateKey, { alg: "RS256" })).toBe("app");
		// PS256 is not taken by default; named, a key naming it is read under it alone.
		expect(await by(rsa.privateKey, { alg: "PS256", kid: "r" })).toBe("bad_credentials");
		const withPss = await boot({
			keys: [jwk(rsa.publicKey, { kid: "r", alg: "PS256" })],
			settings: { algorithms: ["RS256", "PS256"] },
		});
		expect(await tried(withPss.c, {}, {}, rsa.privateKey, { alg: "PS256", kid: "r" })).toBe("app");
		expect(await by(rsa.privateKey, { alg: "RS256", kid: "ec" })).toBe("bad_credentials");
		const p384 = generateKeyPairSync("ec", { namedCurve: "P-384" });
		expect(await by(p384.privateKey, { alg: "ES384" })).toBe("bad_credentials");
		expect(await outcome(c, presenting(await signedWithSecret()))).toBe("bad_credentials");
		const twin = await boot({ keys: [jwk(ec.publicKey), jwk(ecPair().publicKey)] });
		expect(await tried(twin.c, {}, {}, ec.privateKey, { alg: "ES256" })).toBe("bad_credentials");
		expect(lastWarned()).toBe("more than one key fits");
		// A key's own alg, and an EC key's curve, narrow the choice.
		const pinned = await boot({ keys: [jwk(rsa.publicKey, { alg: "RS256" })] });
		const rs = (alg: string) => tried(pinned.c, {}, {}, rsa.privateKey, { alg });
		expect(await rs("RS256")).toBe("app");
		expect(await rs("PS256")).toBe("bad_credentials");
		const p521 = generateKeyPairSync("ec", { namedCurve: "P-521" });
		const curves = await boot({
			keys: [jwk(ec.publicKey), jwk(p384.publicKey), jwk(p521.publicKey)],
		});
		expect(await tried(curves.c, {}, {}, ec.privateKey, { alg: "ES256" })).toBe("app");
		// By default, keys of P-384 and P-521 naming no alg are read under their own curve's.
		expect(await tried(curves.c, {}, {}, p384.privateKey, { alg: "ES384" })).toBe("app");
		expect(await tried(curves.c, {}, {}, p521.privateKey, { alg: "ES512" })).toBe("app");
	});

	it("reads each client key under one algorithm, its own alg or the one the operator takes for its kind", async () => {
		const both = { algorithms: ["RS256" as const, "PS256" as const] };
		// RS256 and PS256 both taken: a key naming no alg is unused, for an RS256 assertion too.
		const bare = await boot({ keys: [jwk(rsa.publicKey, { kid: "r" })], settings: both });
		const bareBy = (alg: string) => tried(bare.c, {}, {}, rsa.privateKey, { alg, kid: "r" });
		expect(await bareBy("RS256")).toBe("bad_credentials");
		expect(await bareBy("PS256")).toBe("bad_credentials");
		// A key naming its alg is read under that one alone.
		const named = await boot({
			keys: [jwk(rsa.publicKey, { kid: "r", alg: "RS256" })],
			settings: both,
		});
		const namedBy = (alg: string) => tried(named.c, {}, {}, rsa.privateKey, { alg, kid: "r" });
		expect(await namedBy("RS256")).toBe("app");
		expect(await namedBy("PS256")).toBe("bad_credentials");
		// A key whose alg the operator does not take is used under none.
		const untaken = await boot({
			keys: [jwk(rsa.publicKey, { kid: "r", alg: "PS256" })],
			settings: { algorithms: ["RS256", "ES256"] },
		});
		expect(await tried(untaken.c, {}, {}, rsa.privateKey, { alg: "RS256", kid: "r" })).toBe(
			"bad_credentials",
		);
	});

	it("logs why it refused an assertion [rfc7523-3-u] [rfc7521-5.2-n]", async () => {
		const { c } = await boot({
			keys: [jwk(ec.publicKey, { kid: "ec" }), jwk(ecPair().publicKey, { kid: "ec" })],
		});
		const single = await boot();
		const reason = async (assertion: string, at = single.c) => {
			expect(await outcome(at, presenting(assertion, { client_id: "app" }))).toBe(
				"bad_credentials",
			);
			return lastWarned();
		};
		const other = ecPair();
		expect(await reason("not.a.jwt")).toBe("not a JWT");
		expect(await reason(await sign(claims({ exp: undefined })))).toBe("not a JWT");
		expect(await reason(await sign(claims({ jti: 7 })))).toBe("missing or malformed claims");
		expect(await reason(await sign(claims(), rsa.privateKey, { alg: "RS256", kid: "ec" }))).toBe(
			"no key fits",
		);
		expect(await reason(await sign(claims()), c)).toBe("more than one key fits");
		expect(await reason(await sign(claims(), other.privateKey))).toBe("signature");
		expect(await reason(await signedWithSecret())).toBe("algorithm");
		expect(await reason(await sign(claims({ exp: seconds() - 30 })))).toBe("expired");
		expect(await reason(await sign(claims({ nbf: seconds() + 31 })))).toBe("not yet valid");
		expect(await reason(await sign(claims({ iat: seconds() + 31 })))).toBe("issued in the future");
		expect(await reason(await sign(claims({ exp: seconds() + 3631 })))).toBe("lives too long");
		expect(await reason(await sign(claims({ iat: seconds() - 3631 })))).toBe("lives too long");
		expect(await reason(await sign(claims({ iss: "x" })))).toBe("issuer");
		expect(await reason(await sign(claims({ sub: "x" })))).toBe("issuer");
		expect(await reason(await sign(claims({ aud: "x" })))).toBe("audience");
		// The times are judged before the issuer and the audience.
		expect(await reason(await sign(claims({ aud: "x", exp: seconds() - 30 })))).toBe("expired");
	});

	it("takes only a JWT: no unencoded payload, and no critical header", async () => {
		const { c } = await boot();
		const payload = new TextEncoder().encode(JSON.stringify(claims()));
		const signed = (header: Record<string, unknown>) =>
			new CompactSign(payload)
				.setProtectedHeader({ alg: "ES256", kid: "ec", ...header })
				.sign(ec.privateKey);
		const flat = await new FlattenedSign(payload)
			.setProtectedHeader({ alg: "ES256", kid: "ec", b64: false, crit: ["b64"] })
			.sign(ec.privateKey);
		const unencoded = `${flat.protected}.${flat.payload}.${flat.signature}`;
		expect(await outcome(c, presenting(unencoded, { client_id: "app" }))).toBe("bad_credentials");
		const encodedButMarked = await signed({ b64: true, crit: ["b64"] });
		expect(await outcome(c, presenting(encodedButMarked))).toBe("bad_credentials");
		expect(await outcome(c, presenting(await signed({ b64: true })))).toBe("bad_credentials");
		const extended = await new CompactSign(payload)
			.setProtectedHeader({ alg: "ES256", kid: "ec", crit: ["x-ext"], "x-ext": 1 })
			.sign(ec.privateKey, { crit: { "x-ext": true } });
		expect(await outcome(c, presenting(extended))).toBe("bad_credentials");
		expect(lastWarned()).toBe("not a JWT");
		expect(await outcome(c, presenting(await signed({})))).toBe("app");
	});

	it("answers an assertion, its type or the client id given twice as malformed, before judging or spending any", async () => {
		const { c } = await boot();
		const first = await sign(claims());
		const twice = {
			"the assertion": asked({
				client_assertion_type: assertionType,
				client_assertion: [first, await sign(claims())],
			}),
			"its type": asked({
				client_assertion_type: [assertionType, assertionType],
				client_assertion: first,
			}),
			"the client id": asked({
				client_assertion_type: assertionType,
				client_assertion: first,
				client_id: ["app", "other"],
			}),
		};
		for (const [name, request] of Object.entries(twice)) {
			expect(await outcome(c, request), name).toBe("malformed_credentials");
		}
		expect(await outcome(c, presenting(first))).toBe("app");
	});

	it("answers a request with only half of an assertion as malformed, and refuses one of a type not taken here [rfc7521-4.2-a] [rfc7521-4.2-b] [oidc-core-9-q] [rfc6749-2.3-b]", async () => {
		const { c } = await boot();
		expect(await outcome(c, asked({ client_assertion_type: assertionType }))).toBe(
			"malformed_credentials",
		);
		expect(await outcome(c, asked({ client_assertion: await sign(claims()) }))).toBe(
			"malformed_credentials",
		);
		expect(await outcome(c, presenting(""))).toBe("malformed_credentials");
		expect(await outcome(c, asked({ client_assertion: "" }))).toBe("malformed_credentials");
		expect(await outcome(c, asked({ client_assertion: "", client_id: "app" }))).toBe(
			"malformed_credentials",
		);
		const other = {
			client_assertion_type: "urn:unsupported",
			client_assertion: await sign(claims()),
		};
		expect(await outcome(c, asked(other))).toBe("bad_credentials");
		expect(lastWarned()).toBe("assertion type");
		// Nor does another method take it: not a public client by its id, not a client by its secret.
		expect(await outcome(c, asked({ ...other, client_id: "pub" }))).toBe("wrong_method");
		const secret = { client_id: "post", client_secret: clientSecret("post") };
		expect(await outcome(c, asked({ ...other, ...secret }))).toBe("multiple_methods");
	});

	it("marks as the assertion's the refusal of an assertion beside another method, or of half of one", async () => {
		const { c } = await boot();
		const secret = { client_id: "post", client_secret: clientSecret("post") };
		const beside = asked({
			client_assertion_type: assertionType,
			client_assertion: await sign(claims()),
			...secret,
		});
		expect(await c.authenticate(beside)).toMatchObject({
			kind: "refused",
			reason: "multiple_methods",
			assertion: true,
		});
		expect(await c.authenticate(asked({ client_assertion_type: assertionType }))).toMatchObject({
			kind: "refused",
			reason: "malformed_credentials",
			assertion: true,
		});
	});

	it("takes an assertion from a JSON body as from a form", async () => {
		const { c } = await boot();
		const json = async (extra: Record<string, unknown> = {}) =>
			outcome(
				c,
				posted({
					client_assertion_type: assertionType,
					client_assertion: await sign(claims()),
					...extra,
				}),
			);
		expect(await json()).toBe("app");
		expect(await json({ client_id: "app" })).toBe("app");
		expect(await json({ client_id: "other" })).toBe("unknown_client");
		expect(await json({ client_assertion: "" })).toBe("malformed_credentials");
		expect(await outcome(c, posted({ client_assertion_type: assertionType }))).toBe(
			"malformed_credentials",
		);
		expect(await outcome(c, posted({ client_assertion: await sign(claims()) }))).toBe(
			"malformed_credentials",
		);
	});

	it("answers a part of a JSON body that is not a string as malformed, before judging or spending any", async () => {
		const { c } = await boot();
		const first = await sign(claims());
		const mistyped = {
			"the assertion as a list": {
				client_assertion_type: assertionType,
				client_assertion: [first],
			},
			"the assertion as a number": { client_assertion_type: assertionType, client_assertion: 7 },
			"the type as a list": { client_assertion_type: [assertionType], client_assertion: first },
			"the type alone, as a number": { client_assertion_type: 1 },
			"the client id as a number": {
				client_assertion_type: assertionType,
				client_assertion: first,
				client_id: 7,
			},
		};
		for (const [name, json] of Object.entries(mistyped)) {
			expect(await outcome(c, posted(json)), name).toBe("malformed_credentials");
		}
		expect(
			await outcome(c, posted({ client_assertion_type: assertionType, client_assertion: first })),
		).toBe("app");
	});

	it("reads the body only, never the query, where an assertion would be logged [rfc6749-2.3.1-b]", async () => {
		const { c } = await boot();
		const query = new Map([
			["client_assertion_type", [assertionType]],
			["client_assertion", [await sign(claims())]],
		]);
		expect(await outcome(c, testRequest({ method: "POST", query }))).toBe("no_credentials");
		const halves = testRequest({
			method: "POST",
			query: new Map([["client_assertion", [await sign(claims())]]]),
			json: { client_assertion_type: assertionType },
		});
		expect(await outcome(c, halves)).toBe("malformed_credentials");
	});

	it("leaves a request with no part of an assertion to the other methods, and claims one with either part [rfc6749-2.3-b]", async () => {
		const { c } = await boot();
		const secret = { client_id: "post", client_secret: clientSecret("post") };
		expect(await outcome(c, asked(secret))).toBe("post");
		expect(await outcome(c, asked({ client_id: "pub" }))).toBe("pub");
		const typed = { ...secret, client_assertion_type: assertionType };
		expect(await outcome(c, asked(typed))).toBe("multiple_methods");
		const carried = { ...secret, client_assertion: await sign(claims()) };
		expect(await outcome(c, asked(carried))).toBe("multiple_methods");
	});

	it("is unavailable, and spends nothing, when the client's keys cannot be had", async () => {
		const saved: string[] = [];
		const method = assertionMethod({
			spent: {
				save: async (name) => {
					saved.push(name);
					return "created";
				},
			},
			jwt: {
				algorithms: ["ES256"],
				verifierOf: () => ({ verify: async () => ({ kind: "unavailable" }) }),
			},
			issuer,
			tokenEndpoint: tokenUrl,
			algorithms: ["ES256"],
			maxLifetimeMs: 3_600_000,
			skewMs: 30_000,
			clock: runtime.clock,
			log: runtime.log,
		});
		const client = { id: "app", section: () => ({ keys: [] }) } as unknown as Client;
		await expect(method.verify(presenting(await sign(claims())), client)).rejects.toSatisfy(
			isUnavailable,
		);
		expect(saved).toEqual([]);
	});

	it("is used only by clients registered for it [oidc-core-3.1.3.1-a]", async () => {
		const other = await boot({ method: "client_secret_post" });
		expect(await tried(other.c)).toBe("wrong_method");
		const none = await boot({ keys: [] });
		expect(await tried(none.c)).toBe("bad_credentials");
	});

	it("takes only public keys for verifying signatures", async () => {
		const notForSigning: Record<string, Jwk> = {
			"a private key": jwk(ec.privateKey),
			"a shared secret": { kty: "oct", k: "AAAA" },
			"one for encryption": jwk(ec.publicKey, { use: "enc" }),
			"one for deriving keys": jwk(ec.publicKey, { key_ops: ["deriveKey"] }),
			"key_ops not a list": jwk(ec.publicKey, { key_ops: "verify" }),
			"a kid that is no string": jwk(ec.publicKey, { kid: 7 }),
			...Object.fromEntries(
				["p", "q", "dp", "dq", "qi", "k", "oth"].map((member) => [
					`an RSA key with ${member}`,
					jwk(rsa.publicKey, { [member]: "AAAA" }),
				]),
			),
			"a point off the curve": { kty: "EC", crv: "P-256", x: "AAAA", y: "AAAA" },
			"a key-agreement curve": jwk(generateKeyPairSync("x25519").publicKey),
		};
		for (const [name, bad] of Object.entries(notForSigning)) {
			expect(await boot({ keys: [bad] }).catch((error) => error), name).toBeInstanceOf(BootRefused);
		}
		const marked = await boot({
			keys: [jwk(ec.publicKey, { kid: "ec", use: "sig", key_ops: ["verify"] })],
		});
		expect(await tried(marked.c)).toBe("app");
		await expect(
			boot({ keys: [jwk(generateKeyPairSync("ed448").publicKey)] }),
		).resolves.toBeDefined();
		const keys = await clientKeys.schema["~standard"].validate({ keys: [], other: 1 });
		expect(keys.issues).toBeDefined();
		expect(clientKeysFor([])).toEqual({ "client-assertion": { keys: [] } });
	});

	it("holds a client to the issuer alone unless its section accepts a loose audience, a boolean", async () => {
		const validated = (value: Record<string, unknown>) =>
			clientKeys.schema["~standard"].validate({ keys: [], ...value });
		expect(await validated({})).toMatchObject({ value: { "accept-loose-audience": false } });
		expect(await validated({ "accept-loose-audience": true })).toMatchObject({
			value: { "accept-loose-audience": true },
		});
		expect((await validated({ "accept-loose-audience": "true" })).issues).toBeDefined();
	});

	it("takes the operator's lifetime cap and clock allowance within their bounds, in whole seconds written with their unit", () => {
		const takes = (settings: Record<string, unknown>) => section.safeParse(settings).success;
		for (const fits of ["1s", "1d"]) expect(takes({ "max-lifetime": fits })).toBe(true);
		for (const fits of ["0s", "5m"]) expect(takes({ "clock-skew": fits })).toBe(true);
		for (const not of ["0s", "86401s", "1500ms", 3600, "3600"]) {
			expect(takes({ "max-lifetime": not }), String(not)).toBe(false);
		}
		for (const not of ["301s", "500ms", 30])
			expect(takes({ "clock-skew": not }), String(not)).toBe(false);
		expect(section.parse({})).toEqual({
			"max-lifetime": 3600,
			"clock-skew": 30,
			algorithms: ["RS256", "ES256", "ES384", "ES512", "EdDSA"],
		});
		expect(takes({ other: 1 })).toBe(false);
	});
});

it("takes all it names", async () => {
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused((await boot()).input))["client-assertion"]).toBeUndefined();
});
