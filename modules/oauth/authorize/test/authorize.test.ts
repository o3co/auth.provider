import { createHash } from "node:crypto";
import { acrEntries } from "@mod/acr";
import acrModule from "@mod/acr/module";
import { acrConfig } from "@mod/acr/testing";
import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientsModule from "@mod/clients/module";
import { clientsConfig, confidentialClient, publicClient } from "@mod/clients/testing";
import { type IdTokenRequest, idTokens } from "@mod/code-grant";
import codeGrantModule from "@mod/code-grant/module";
import { codeGrantConfig } from "@mod/code-grant/testing";
import codeGrantStore from "@mod/code-grant-store/module";
import { consents, type StoredAsk, type StoredGrant } from "@mod/consent";
import consentModule from "@mod/consent/module";
import { consentConfig, consentStoresOn, firstPartyFor } from "@mod/consent/testing";
import cookiesModule from "@mod/cookies/module";
import { csrfStandIn } from "@mod/csrf/testing";
import { targetRules } from "@mod/grants";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { type MetadataItem, metadata } from "@mod/issuer";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import {
	assemble,
	contract,
	defineModule,
	isUnavailable,
	kernelConfig,
	type Module,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime, recordingLog, switchedModule, unavailableSwitch } from "@mod/kernel/testing";
import { amrSources } from "@mod/login-gates";
import gatesModule from "@mod/login-gates/module";
import rateLimitModule from "@mod/rate-limit/module";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import { memoryRecords } from "@mod/records/testing";
import { type Session, sessions } from "@mod/session";
import { sessionStandIn } from "@mod/session/testing";
import bridgeModule from "@mod/session-tokens/module";
import { sessionTokensInMemory } from "@mod/session-tokens/testing";
import { simulatedStore } from "@mod/store/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { grantCaller, grantCalls } from "@mod/token-endpoint/testing";
import { type IssuanceRequest, issuancePolicies, type Tokens, tokens } from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { afterEach, describe, expect, it } from "vitest";
import { redirects } from "../src/contract.ts";
import authorizeModule from "../src/module.ts";
import { section } from "../src/section.ts";
import { type ReauthStore, reauthStore, type StoredReauth } from "../src/store.ts";
import { authorizeConfig, redirectsFor } from "../src/testing.ts";

let now = 1_800_000_000_000;
const logged = recordingLog();
const runtime = quietRuntime({ clock: { now: () => now }, log: logged.log });
const warnings = () => logged.lines().filter((line) => line.event === "authorize.unavailable");
let stop = async () => {};
afterEach(() => stop());

const issuer = "https://as.example";
const callback = "https://app.example/cb";
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
const client = (id: string, extra: Record<string, unknown> = {}, grants = ["authorization_code"]) =>
	confidentialClient({
		id,
		sections: {
			...allowancesFor({
				grants,
				scopes: ["openid", "read", "write"],
				"default-scopes": ["read"],
				audiences: ["https://api"],
			}),
			...redirectsFor([callback, "http://127.0.0.1:9000/cb"]),
			...extra,
		},
	});

async function serve(
	options: {
		revocable?: boolean;
		codeGrant?: Record<string, unknown>;
		authorize?: Record<string, unknown>;
		/** The acr table, each acr and the amr sets that meet it. */
		acr?: Record<string, string[][]>;
		extra?: Module[];
		/** The amr the deployment's ways of logging in declare. */
		proves?: string[];
		/** The rate-limit module; its stand-in never fails to count. */
		rateLimit?: Module;
		/** False leaves out the consent page, so consent cannot ask. */
		asking?: boolean;
	} = {},
) {
	const proving = defineModule({ name: "proving" }, (m) => [
		m
			.contribute(amrSources)
			.by(() => ({ name: "proving", amr: options.proves ?? ["pwd", "otp", "mfa"] })),
	]);
	const simulated = simulatedStore();
	const reauths = memoryRecords<StoredReauth>(() => now, { shards: 1, perShard: 1 });
	const down = {
		reauths: unavailableSwitch<ReauthStore>("reauth store"),
		tokens: unavailableSwitch<Tokens>("tokens"),
	};
	const reauthStand = defineModule({ name: "reauth-store" }, (m) => [
		m
			.provide(reauthStore)
			.by(() =>
				down.reauths.wrap({ save: reauths.records.create, update: reauths.records.change }),
			),
	]);
	const consentStores = consentStoresOn({
		grants: memoryRecords<StoredGrant>(() => now, { shards: 1, perShard: 1 }),
		asks: memoryRecords<StoredAsk>(() => now, { shards: 1, perShard: 1 }),
	});
	const audit = auditStandIn();
	const app = await assemble({
		modules: [
			http,
			switchedModule(tokensStandIn({ revocable: options.revocable ?? true }), tokens, down.tokens),
			issuerModule,
			clientsModule,
			grantCaller,
			clientAllowanceModule,
			sessionStandIn,
			subjectRevocationStandIn,
			consentModule,
			consentStores,
			csrfStandIn,
			cookiesModule,
			simulated.module,
			bridgeModule,
			sessionTokensInMemory().module,
			codeGrantModule,
			codeGrantStore,
			authorizeModule,
			reauthStand,
			options.rateLimit ?? rateLimitModule,
			audit.module,
			acrModule,
			gatesModule,
			proving,
			...(options.extra ?? []),
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "trusted-proxies": ["127.0.0.1"], "public-origin": issuer }),
			...issuerConfig({ url: issuer }),
			...clientsConfig([
				client("app", firstPartyFor(true)),
				client("wide", {
					...firstPartyFor(true),
					...allowancesFor({
						grants: ["authorization_code"],
						scopes: ["read"],
						"default-scopes": ["read"],
						audiences: ["https://api", "https://two"],
					}),
				}),
				client("third"),
				client("nocode", firstPartyFor(true), ["client_credentials"]),
				confidentialClient({
					id: "nodefault",
					sections: {
						...allowancesFor({ grants: ["authorization_code"], scopes: ["read"] }),
						...redirectsFor([callback]),
						...firstPartyFor(true),
					},
				}),
				confidentialClient({
					id: "openid-default",
					sections: {
						...allowancesFor({
							grants: ["authorization_code"],
							scopes: ["openid", "read"],
							"default-scopes": ["openid"],
						}),
						...redirectsFor([callback]),
						...firstPartyFor(true),
					},
				}),
				confidentialClient({
					id: "empty",
					sections: {
						...allowancesFor({ grants: ["authorization_code"], scopes: [], "default-scopes": [] }),
						...redirectsFor([callback]),
					},
				}),
				publicClient({
					id: "pub",
					sections: {
						...allowancesFor({
							grants: ["authorization_code"],
							scopes: ["read"],
							"default-scopes": ["read"],
						}),
						...redirectsFor(["http://[::1]:7000/cb"]),
						...firstPartyFor(true),
					},
				}),
			]),
			...(options.asking === false ? { consent: {} } : consentConfig()),
			// Most scenes here are not about OpenID Connect, so they leave out openid.
			...authorizeConfig({ "oidc-mode": "dual", ...options.authorize }),
			...acrConfig(options.acr ?? {}),
			...codeGrantConfig({ "code-lifetime": "1m", ...options.codeGrant }),
		},
		runtime,
	});
	await app.start();
	stop = () => app.stop(1000);
	const base = `http://127.0.0.1:${app.get(listening).port()}`;
	const opened = app.get(sessions);
	const login = async (
		subject = "alice",
		amr = ["pwd"],
		authenticatedAt: number | "unknown" = runtime.clock.now(),
	) => {
		const facts = { subject, amr, authenticatedAt };
		const { cookies } = await opened.complete(testRequest(), facts);
		return cookies[0]?.split(";")[0] ?? "";
	};
	const authorize = async (params: Record<string, string> | string, cookie = "") => {
		const query = typeof params === "string" ? params : new URLSearchParams(params).toString();
		const res = await fetch(`${base}/oauth/authorize?${query}`, {
			redirect: "manual",
			headers: { "x-forwarded-proto": "https", "x-forwarded-for": "198.51.100.1", cookie },
		});
		const location = res.headers.get("location") ?? "";
		return {
			status: res.status,
			location,
			at: location ? new URL(location) : undefined,
			text: await res.text(),
		};
	};
	/** Redeems a code through the grant harness, answering as the token endpoint would. */
	const token = async (
		form: Record<string, string>,
		id = "app",
	): Promise<{ status: number; body: Record<string, unknown> }> => {
		const params = { grant_type: "authorization_code", ...form };
		const outcome = await app
			.get(grantCalls)
			.call("authorization_code", id, params)
			.catch((error: unknown) => {
				if (isUnavailable(error)) return undefined;
				throw error;
			});
		if (!outcome) return { status: 503, body: { error: "temporarily_unavailable" } };
		if (outcome.kind === "issued") return { status: 200, body: { ...outcome.body } };
		const described = outcome.description ? { error_description: outcome.description } : {};
		return { status: 400, body: { error: outcome.error, ...described } };
	};
	return { app, simulated, down, login, authorize, token, opened, base, events: audit.events };
}

const request = (extra: Record<string, string> = {}) => ({
	response_type: "code",
	client_id: "app",
	redirect_uri: callback,
	state: "s1",
	code_challenge: challenge,
	code_challenge_method: "S256",
	...extra,
});

describe("authorize: trust in the redirect URI", () => {
	it("answers locally until the client and an exactly registered redirect URI are known", async () => {
		const { authorize, login } = await serve();
		const cookie = await login();
		for (const params of [
			request({ client_id: "" }),
			request({ client_id: "nobody" }),
			request({ redirect_uri: "" }),
			request({ redirect_uri: `${callback}/` }),
			request({ redirect_uri: "https://APP.example/cb" }),
			request({ redirect_uri: `${callback}?x=1` }),
			request({ redirect_uri: "http://localhost:9000/cb" }),
			request({ redirect_uri: "http://127.0.0.1:9000/cb/" }),
		]) {
			const res = await authorize(params, cookie);
			expect([res.status, res.location]).toEqual([400, ""]);
		}
		const loopback = await authorize(request({ redirect_uri: "http://127.0.0.1:9555/cb" }), cookie);
		expect(loopback.at?.origin).toBe("http://127.0.0.1:9555");
	});

	it("sends every other refusal back with state and iss", async () => {
		const { authorize, login } = await serve();
		const cookie = await login();
		const cases: [Record<string, string> | string, string][] = [
			[request({ response_type: "token" }), "unsupported_response_type"],
			[request({ code_challenge: "" }), "invalid_request"],
			[request({ code_challenge_method: "plain" }), "invalid_request"],
			[request({ request: "eyJ" }), "request_not_supported"],
			[request({ response_mode: "fragment" }), "invalid_request"],
			[request({ scope: "admin" }), "invalid_scope"],
			[request({ acr_values: "gold" }), "unmet_authentication_requirements"],
			[request({ client_id: "nocode" }), "unauthorized_client"],
			[request({ prompt: "none login" }), "invalid_request"],
			[`${new URLSearchParams(request())}&code_challenge_method=S256`, "invalid_request"],
		];
		for (const [params, error] of cases) {
			const res = await authorize(params, cookie);
			expect(res.status).toBe(302);
			expect(`${res.at?.origin}${res.at?.pathname}`).toBe(callback);
			expect([
				res.at?.searchParams.get("error"),
				res.at?.searchParams.get("state"),
				res.at?.searchParams.get("iss"),
			]).toEqual([error, "s1", issuer]);
		}
		const twice = await authorize(`${new URLSearchParams(request())}&state=s2`, cookie);
		expect([twice.at?.searchParams.get("error"), twice.at?.searchParams.has("state")]).toEqual([
			"invalid_request",
			false,
		]);
	});
});

it("refuses a client not allowed the code grant with the token endpoint's words for it", async () => {
	const { authorize, login } = await serve();
	const res = await authorize(request({ client_id: "nocode" }), await login());
	expect([
		res.at?.searchParams.get("error"),
		res.at?.searchParams.get("error_description"),
		res.at?.searchParams.get("state"),
	]).toEqual([
		"unauthorized_client",
		"client is not authorized for grant_type 'authorization_code'",
		"s1",
	]);
});

describe("authorize: session and consent", () => {
	it("sends a request without a session to the login page, with the way back from the public origin", async () => {
		const { authorize } = await serve();
		const res = await authorize(request());
		expect(res.status).toBe(302);
		expect(`${res.at?.origin}${res.at?.pathname}`).toBe("https://as.example/login");
		const back = new URL(res.at?.searchParams.get("redirect_to") ?? "");
		expect(`${back.origin}${back.pathname}`).toBe(`${issuer}/oauth/authorize`);
		expect(back.searchParams.get("client_id")).toBe("app");
		expect((await authorize(request({ prompt: "none" }))).at?.searchParams.get("error")).toBe(
			"login_required",
		);
	});

	it("asks a third party for consent, and lets it through once granted", async () => {
		const { app, authorize, login } = await serve();
		const cookie = await login();
		expect(
			(
				await authorize(request({ client_id: "third", prompt: "none" }), cookie)
			).at?.searchParams.get("error"),
		).toBe("consent_required");
		const asked = await authorize(request({ client_id: "third" }), cookie);
		expect(`${asked.at?.origin}${asked.at?.pathname}`).toBe("https://as.example/consent");
		await app.get(consents).grant("third", "alice", ["read"]);
		expect(
			(await authorize(request({ client_id: "third" }), cookie)).at?.searchParams.has("code"),
		).toBe(true);
		expect(
			(await authorize(request({ client_id: "third", prompt: "consent" }), cookie)).at?.pathname,
		).toBe("/consent");
	});

	it("refuses a third party when consent cannot ask, after login, whatever it was granted", async () => {
		const { app, authorize, login, events } = await serve({ asking: false });
		expect((await authorize(request({ client_id: "third" }))).at?.pathname).toBe("/login");
		const cookie = await login();
		await app.get(consents).grant("third", "alice", ["read"]);
		for (const prompt of [undefined, "none", "consent"]) {
			const res = await authorize(
				request({ client_id: "third", ...(prompt ? { prompt } : {}) }),
				cookie,
			);
			expect(`${res.at?.origin}${res.at?.pathname}`).toBe(callback);
			expect([
				res.at?.searchParams.get("error"),
				res.at?.searchParams.get("error_description"),
				res.at?.searchParams.get("state"),
				res.at?.searchParams.get("iss"),
			]).toEqual([
				"unauthorized_client",
				"client is not authorized for the authorization endpoint",
				"s1",
				issuer,
			]);
		}
		expect(events.map((e) => e.attributes?.reason)).toEqual(
			Array(3).fill("client_not_first_party"),
		);
		expect((await authorize(request(), cookie)).at?.searchParams.has("code")).toBe(true);
	});

	it("asks for a newer login on prompt=login, and takes each re-authentication once", async () => {
		const { authorize, login } = await serve();
		const old = await login();
		now += 10_000;
		const asked = await authorize(request({ prompt: "login" }), old);
		expect(asked.at?.pathname).toBe("/login");
		const resume = new URL(asked.at?.searchParams.get("redirect_to") ?? "");
		expect(resume.searchParams.get("prompt")).toBe("login");
		expect((await authorize(resume.search.slice(1), old)).at?.pathname).toBe("/login");
		const again = await authorize(request({ prompt: "login" }), old);
		const resumed = new URL(again.at?.searchParams.get("redirect_to") ?? "");
		now += 1000;
		const fresh = await login();
		expect((await authorize(resumed.search.slice(1), fresh)).at?.searchParams.has("code")).toBe(
			true,
		);
		expect((await authorize(resumed.search.slice(1), fresh)).at?.pathname).toBe("/login");
	});
});

it("counts a login made at the very time a re-authentication was asked", async () => {
	const { authorize, login } = await serve();
	const old = await login();
	now += 10_000;
	const asked = await authorize(request({ prompt: "login" }), old);
	const resume = new URL(asked.at?.searchParams.get("redirect_to") ?? "");
	const fresh = await login();
	expect((await authorize(resume.search.slice(1), fresh)).at?.searchParams.has("code")).toBe(true);
});

it("counts a login reported within the second the re-authentication was asked, not one a second before", async () => {
	const { authorize, login } = await serve();
	const old = await login();
	now += 10_500;
	const resumeOf = async () => {
		const asked = await authorize(request({ prompt: "login" }), old);
		return new URL(asked.at?.searchParams.get("redirect_to") ?? "").search.slice(1);
	};
	const sameSecond = await resumeOf();
	const early = await login("alice", ["pwd"], now - 500);
	expect((await authorize(sameSecond, early)).at?.searchParams.has("code")).toBe(true);
	const secondBefore = await resumeOf();
	const earlier = await login("alice", ["pwd"], now - 1000);
	expect((await authorize(secondBefore, earlier)).at?.pathname).toBe("/login");
});

it("limits requests per source over both methods", async () => {
	const { authorize, base } = await serve({ authorize: { requests: 2, window: "1m" } });
	expect((await authorize(request())).status).toBe(302);
	const posted = await fetch(`${base}/oauth/authorize`, {
		method: "POST",
		redirect: "manual",
		headers: {
			"content-type": "application/x-www-form-urlencoded",
			"x-forwarded-proto": "https",
			"x-forwarded-for": "198.51.100.1",
		},
		body: new URLSearchParams(request()),
	});
	expect(posted.status).toBe(303);
	const limited = await authorize(request());
	expect([limited.status, JSON.parse(limited.text)]).toEqual([429, { error: "rate_limited" }]);
});

describe("authorize: the section", () => {
	const login = { "login-page": "https://as.example/login" };

	it("reads the rate limit's window as an operator writes it, with a unit", () => {
		expect(section.parse({ ...login, window: "30m" }).window).toBe(1800);
	});

	it("refuses to start with a window that names no unit, a number or digits alone", async () => {
		const unitless = [
			[60, "written with its unit, such as 30s"],
			["60", "duration must name its unit"],
		] as const;
		for (const [written, reason] of unitless) {
			await expect(
				serve({ authorize: { window: written } }),
				String(written),
			).rejects.toMatchObject({ refusals: [{ where: "authorize.window", reason }] });
		}
		expect(section.safeParse({ ...login, window: "60" }).error?.issues).toMatchObject([
			{ path: ["window"], params: { problem: "missing-unit" } },
		]);
	});

	it("reads a section that holds only the login page with the defaults it had", () => {
		expect(section.parse(login)).toEqual({
			...login,
			"oidc-mode": "oidc-required",
			requests: 60,
			window: 60,
		});
		expect(redirects.schema["~standard"].validate({})).toEqual({ value: { "redirect-uris": [] } });
	});
});

/** A rule narrowing to the `resource` asked when the issuance may have it, as resource indicators do. */
const narrowing = defineModule({ name: "narrowing" }, (m) => [
	m.contribute(targetRules).by(() => ({
		target: ({ param, audience, within }) => {
			const asked = param("resource");
			if (!asked) return { kind: "audience", audience };
			return within(asked)
				? { kind: "audience", audience: [asked] }
				: { kind: "error", error: "invalid_target", description: `not ${asked}` };
		},
	})),
]);

describe("authorize: the audience a request asks for", () => {
	/** The audience of the token a code asked with `resource` gives. */
	const audienceFor = async (s: Awaited<ReturnType<typeof serve>>, resource: string) => {
		const res = await s.authorize(request({ client_id: "wide", resource }), await s.login());
		const code = res.at?.searchParams.get("code") ?? "";
		const issued = await s.token({ code, redirect_uri: callback, code_verifier: verifier }, "wide");
		const checked = await s.app.get(tokens).verifyAccess(String(issued.body.access_token));
		return checked.kind === "valid" ? checked.grant.audience : checked;
	};

	it("issues the code for the resource asked, within what the client may be issued, after consent", async () => {
		const s = await serve({ extra: [narrowing] });
		expect(await audienceFor(s, "https://two")).toEqual(["https://two"]);
	});

	it("sends a resource the client may not have back as invalid_target, with state and iss, unrecorded", async () => {
		const s = await serve({ extra: [narrowing] });
		const res = await s.authorize(
			request({ client_id: "wide", resource: "https://elsewhere" }),
			await s.login(),
		);
		expect([
			res.at?.searchParams.get("error"),
			res.at?.searchParams.get("error_description"),
			res.at?.searchParams.get("state"),
			res.at?.searchParams.get("iss"),
			res.at?.searchParams.get("code"),
		]).toEqual(["invalid_target", "not https://elsewhere", "s1", issuer, null]);
		expect(s.events.filter((e) => e.kind === "authorize.rejected")).toEqual([]);
	});

	it("reads no resource where no rule is composed", async () => {
		const s = await serve();
		expect(await audienceFor(s, "https://two")).toEqual(["https://api"]);
	});

	it("sends a parameter the rule reads, sent twice, back as the rule says, and any other as invalid_request", async () => {
		const strict = defineModule({ name: "strict" }, (m) => [
			m.contribute(targetRules).by(() => ({
				target: ({ audience }) => ({ kind: "audience", audience }),
				repeated: (name) =>
					name === "resource"
						? { kind: "error", error: "invalid_target", description: "one resource" }
						: undefined,
			})),
		]);
		const twice = (name: string) => {
			const query = new URLSearchParams(request({ client_id: "wide" }));
			query.append(name, "https://two");
			query.append(name, "https://api");
			return query.toString();
		};
		const s = await serve({ extra: [strict] });
		const asked = await s.authorize(twice("resource"), await s.login());
		expect([asked.at?.searchParams.get("error"), asked.at?.searchParams.get("state")]).toEqual([
			"invalid_target",
			"s1",
		]);
		const other = await s.authorize(twice("prompt"), await s.login());
		expect(other.at?.searchParams.get("error")).toBe("invalid_request");
		const plain = await serve({ extra: [narrowing] });
		const unruled = await plain.authorize(twice("resource"), await plain.login());
		expect(unruled.at?.searchParams.get("error")).toBe("invalid_request");
	});

	it("asks the issuance policies for the audience asked, and gives their refusal before invalid_target", async () => {
		const asked: IssuanceRequest[] = [];
		const policy = defineModule({ name: "refusing-bob" }, (m) => [
			m.contribute(issuancePolicies).by(() => ({
				name: "refusing-bob",
				judge: async (request) => {
					asked.push(request);
					return request.grant.subject === "bob"
						? { kind: "refused", reason: "test_reason", description: "refused here" }
						: { kind: "allowed" };
				},
			})),
		]);
		const s = await serve({ extra: [narrowing, policy] });
		expect(await audienceFor(s, "https://two")).toEqual(["https://two"]);
		expect(asked[0]?.grant.audience).toEqual(["https://two"]);
		const outside = request({ client_id: "wide", resource: "https://elsewhere" });
		const res = await s.authorize(outside, await s.login("bob"));
		expect(res.at?.searchParams.get("error")).toBe("access_denied");
	});
});

describe("authorize: the code grant", () => {
	const codeOf = async (s: Awaited<ReturnType<typeof serve>>, cookie: string) =>
		(await s.authorize(request(), cookie)).at?.searchParams.get("code") ?? "";

	it("exchanges a code once, and revokes what it gave when the code comes again", async () => {
		const s = await serve();
		const code = await codeOf(s, await s.login());
		const first = await s.token({ code, redirect_uri: callback, code_verifier: verifier });
		expect(first.status).toBe(200);
		expect(first.body).toMatchObject({ token_type: "Bearer", scope: "read" });
		const t = s.app.get(tokens);
		expect((await t.verifyAccess(String(first.body.access_token))).kind).toBe("valid");
		const again = await s.token({ code, redirect_uri: callback, code_verifier: verifier });
		expect([again.status, again.body.error]).toEqual([400, "invalid_grant"]);
		expect(await t.verifyAccess(String(first.body.access_token))).toEqual({
			kind: "invalid",
			reason: "revoked",
		});
	});

	it("uses up a code on a wrong verifier, client or redirect URI, but not on a malformed request", async () => {
		const s = await serve();
		const cookie = await s.login();
		const malformed = await codeOf(s, cookie);
		expect(
			(await s.token({ code: malformed, redirect_uri: callback, code_verifier: "short" })).body
				.error,
		).toBe("invalid_request");
		expect(
			(await s.token({ code: malformed, redirect_uri: callback, code_verifier: verifier })).status,
		).toBe(200);
		for (const [form, id] of [
			[{ redirect_uri: callback, code_verifier: "w".repeat(43) }, "app"],
			[{ redirect_uri: "http://127.0.0.1:9000/cb", code_verifier: verifier }, "app"],
			[{ redirect_uri: callback, code_verifier: verifier }, "third"],
		] as const) {
			const code = await codeOf(s, cookie);
			expect((await s.token({ code, ...form }, id)).body.error).toBe("invalid_grant");
			expect(
				(await s.token({ code, redirect_uri: callback, code_verifier: verifier })).body.error,
			).toBe("invalid_grant");
		}
	});

	it("refuses a code after its time, or after its session ended", async () => {
		const s = await serve();
		const cookie = await s.login();
		const late = await codeOf(s, cookie);
		now += 61_000;
		expect(
			(await s.token({ code: late, redirect_uri: callback, code_verifier: verifier })).body.error,
		).toBe("invalid_grant");
		const code = await codeOf(s, cookie);
		const session = (await s.opened.enter(
			testRequest({ headers: new Map([["cookie", cookie]]) }),
		)) as Session;
		await s.opened.close(session.id);
		expect(
			(await s.token({ code, redirect_uri: callback, code_verifier: verifier })).body.error,
		).toBe("invalid_grant");
	});

	it("answers 503 when the store cannot be reached", async () => {
		// Counted apart, so the store's outage reaches authorize itself, whatever rate-limit does then.
		const s = await serve({ rateLimit: rateLimitStandIn });
		const cookie = await s.login();
		s.simulated.unreachable(true);
		const before = warnings().length;
		const res = await s.authorize(request(), cookie);
		expect([
			res.status,
			res.at?.searchParams.get("error"),
			res.at?.searchParams.get("iss"),
		]).toEqual([302, "temporarily_unavailable", issuer]);
		expect(warnings().slice(before)).toEqual([
			{
				level: "warn",
				event: "authorize.unavailable",
				fields: { what: expect.any(String), route: "/oauth/authorize" },
			},
		]);
	});
});

it("refuses to register redirect URIs with a fragment, userinfo, control characters or answer names", async () => {
	const { registrable } = await import("../src/contract.ts");
	expect(registrable("https://app.example/cb?x=1")).toBe(true);
	for (const bad of [
		"https://app.example/cb#f",
		"https://u:p@app.example/cb",
		"https://app.example/c\nb",
		"https://app.example/cb?code=1",
		"https://app.example/cb?state=1",
		"/relative",
		"https://app.example/c b",
	]) {
		expect(registrable(bad)).toBe(false);
	}
});

describe("authorize: what the reviews asked to pin down", () => {
	const codeFrom = (res: { at?: URL | undefined }) => res.at?.searchParams.get("code") ?? "";

	it("answers locally with OAuth codes, and treats only loopback IP literals as loopback", async () => {
		const { authorize, login } = await serve();
		const cookie = await login();
		const local = async (params: Record<string, string> | string) => {
			const res = await authorize(params, cookie);
			return [res.status, JSON.parse(res.text).error];
		};
		expect(await local(request({ client_id: "nobody" }))).toEqual([400, "invalid_client"]);
		expect(await local(request({ redirect_uri: "https://app.example:8443/cb" }))).toEqual([
			400,
			"invalid_request",
		]);
		expect(await local(`${new URLSearchParams(request())}&client_id=app`)).toEqual([
			400,
			"invalid_request",
		]);
		expect(
			await local(`${new URLSearchParams(request())}&redirect_uri=${encodeURIComponent(callback)}`),
		).toEqual([400, "invalid_request"]);
		const v6 = await authorize(
			request({ client_id: "pub", redirect_uri: "http://[::1]:7111/cb" }),
			cookie,
		);
		expect(v6.at?.searchParams.has("code")).toBe(true);
	});

	it("refuses or accepts each parameter as the rules say", async () => {
		const { authorize, login } = await serve();
		const cookie = await login();
		const error = async (extra: Record<string, string>) =>
			(await authorize(request(extra), cookie)).at?.searchParams.get("error");
		expect(await error({ request_uri: "urn:x" })).toBe("request_not_supported");
		expect(await error({ response_mode: "query" })).toBeNull();
		expect(await error({ nonce: "n".repeat(257) })).toBe("invalid_request");
		expect(await error({ prompt: "maybe" })).toBe("invalid_request");
		expect(await error({ code_challenge: `${challenge}A` })).toBe("invalid_request");
		expect(await error({ max_age: "-1" })).toBe("invalid_request");
		expect(await error({ response_type: "" })).toBe("invalid_request");
		const long = await authorize(request({ state: "s".repeat(513) }), cookie);
		expect([long.at?.searchParams.get("error"), long.at?.searchParams.has("state")]).toEqual([
			"invalid_request",
			false,
		]);
		const ok = await authorize(request(), cookie);
		expect([
			ok.at?.searchParams.has("code"),
			ok.at?.searchParams.get("state"),
			ok.at?.searchParams.get("iss"),
		]).toEqual([true, "s1", issuer]);
	});

	it("sends a POST on to the same GET without reading the session", async () => {
		const { base, login } = await serve();
		const cookie = await login();
		const res = await fetch(`${base}/oauth/authorize`, {
			method: "POST",
			redirect: "manual",
			headers: {
				"content-type": "application/x-www-form-urlencoded",
				cookie,
				"x-forwarded-proto": "https",
				"x-forwarded-for": "198.51.100.1",
			},
			body: new URLSearchParams(request()),
		});
		const at = new URL(res.headers.get("location") ?? "");
		expect([res.status, `${at.origin}${at.pathname}`, at.searchParams.get("client_id")]).toEqual([
			303,
			`${issuer}/oauth/authorize`,
			"app",
		]);
	});

	it("binds a re-authentication to its request: another client's, or a stale one, does not count", async () => {
		const { authorize, login } = await serve();
		const theirs = await authorize(request({ client_id: "third", prompt: "login" }));
		const stolen =
			new URL(theirs.at?.searchParams.get("redirect_to") ?? "").searchParams.get("reauth") ?? "";
		now += 10_000;
		const victim = await login();
		expect(
			(await authorize(request({ prompt: "login", reauth: stolen }), victim)).at?.pathname,
		).toBe("/login");
		now += 1000;
		expect((await authorize(request({ max_age: "0", reauth: stolen }), victim)).at?.pathname).toBe(
			"/login",
		);
	});

	it("asks for a newer login past max_age, and lets the resumed request through after one", async () => {
		const { authorize, login } = await serve();
		const old = await login();
		now += 120_000;
		const asked = await authorize(request({ max_age: "60" }), old);
		expect(asked.at?.pathname).toBe("/login");
		const resume = new URL(asked.at?.searchParams.get("redirect_to") ?? "");
		now += 1000;
		const fresh = await login();
		expect((await authorize(resume.search.slice(1), fresh)).at?.searchParams.has("code")).toBe(
			true,
		);
	});

	it("asks a third party with an empty scope too", async () => {
		const { authorize, login } = await serve();
		const cookie = await login();
		expect(
			(
				await authorize(request({ client_id: "empty", prompt: "none" }), cookie)
			).at?.searchParams.get("error"),
		).toBe("consent_required");
	});

	it("goes through the consent page and back, both ways", async () => {
		const { authorize, login, base } = await serve();
		const cookie = await login();
		const answer = async (decision: string) => {
			const asked = await authorize(request({ client_id: "third" }), cookie);
			const challenge = asked.at?.searchParams.get("challenge") ?? "";
			const res = await fetch(`${base}/oauth/consent`, {
				method: "POST",
				redirect: "manual",
				headers: {
					"content-type": "application/x-www-form-urlencoded",
					cookie,
					origin: issuer,
					"x-forwarded-proto": "https",
					"x-forwarded-for": "198.51.100.1",
				},
				body: new URLSearchParams({ challenge, decision }),
			});
			const next = new URL(res.headers.get("location") ?? "");
			expect(next.origin).toBe(issuer);
			return authorize(next.search.slice(1), cookie);
		};
		expect((await answer("deny")).at?.searchParams.get("error")).toBe("access_denied");
		expect((await answer("accept")).at?.searchParams.has("code")).toBe(true);
	});

	it("refuses to start without revocable access tokens", async () => {
		await expect(serve({ revocable: false })).rejects.toThrow();
	});

	it("lets a public client redeem, and a loopback redirect redeem with its own port only", async () => {
		const s = await serve();
		const cookie = await s.login();
		const code = codeFrom(
			await s.authorize(
				request({ client_id: "pub", redirect_uri: "http://[::1]:7111/cb" }),
				cookie,
			),
		);
		expect(
			(
				await s.token(
					{ code, redirect_uri: "http://[::1]:7000/cb", code_verifier: verifier },
					"pub",
				)
			).body.error,
		).toBe("invalid_grant");
		const again = codeFrom(
			await s.authorize(
				request({ client_id: "pub", redirect_uri: "http://[::1]:7111/cb" }),
				cookie,
			),
		);
		expect(
			(
				await s.token(
					{ code: again, redirect_uri: "http://[::1]:7111/cb", code_verifier: verifier },
					"pub",
				)
			).status,
		).toBe(200);
	});

	it("does not use up a code when the request lacks it parts, and answers every refusal alike", async () => {
		const s = await serve();
		const cookie = await s.login();
		const code = codeFrom(await s.authorize(request(), cookie));
		expect((await s.token({ code, code_verifier: verifier })).body.error).toBe("invalid_request");
		const wrong = await s.token({ code, redirect_uri: callback, code_verifier: "w".repeat(43) });
		const replay = await s.token({ code, redirect_uri: callback, code_verifier: verifier });
		expect(wrong.body).toEqual(replay.body);
		expect(replay.body).toEqual({ error: "invalid_grant", error_description: "invalid code" });
	});

	it("leaves no usable token when two redeem at once, or another client presents a used code", async () => {
		const s = await serve();
		const t = s.app.get(tokens);
		const cookie = await s.login();
		const code = codeFrom(await s.authorize(request(), cookie));
		const both = await Promise.all(
			[1, 2].map(() => s.token({ code, redirect_uri: callback, code_verifier: verifier })),
		);
		for (const res of both) {
			if (res.status === 200)
				expect((await t.verifyAccess(String(res.body.access_token))).kind).toBe("invalid");
		}
		const next = codeFrom(await s.authorize(request(), cookie));
		const first = await s.token({ code: next, redirect_uri: callback, code_verifier: verifier });
		expect(
			(await s.token({ code: next, redirect_uri: callback, code_verifier: verifier }, "third")).body
				.error,
		).toBe("invalid_grant");
		expect((await t.verifyAccess(String(first.body.access_token))).kind).toBe("invalid");
	});

	it("retries a revocation that failed, until the reused code's token is revoked", async () => {
		const s = await serve({ codeGrant: { "sweep-interval": "1s" } });
		const t = s.app.get(tokens);
		const cookie = await s.login();
		const code = codeFrom(await s.authorize(request(), cookie));
		const first = await s.token({ code, redirect_uri: callback, code_verifier: verifier });
		// The revocation fails; the code stays on the list of voids for the sweep.
		s.down.tokens.unavailable("revokeAccess", "revokeReferenced");
		expect(
			(await s.token({ code, redirect_uri: callback, code_verifier: verifier })).status,
		).not.toBe(200);
		expect((await t.verifyAccess(String(first.body.access_token))).kind).not.toBe("invalid");
		s.down.tokens.restore();
		await new Promise((resolve) => setTimeout(resolve, 1300));
		expect((await t.verifyAccess(String(first.body.access_token))).kind).toBe("invalid");
	});
});

it("registers https, http to localhost or loopback literals, and reverse-domain app schemes only", async () => {
	const { registrable, matches } = await import("../src/redirect-uris/redirect-uris.ts");
	for (const ok of [
		"https://app.example/cb",
		"http://localhost:8080/cb",
		"http://127.0.0.2/cb",
		"http://[::1]:9000/cb",
		"com.example.app:/cb",
		"com.example.app://cb",
	]) {
		expect(registrable(ok)).toBe(true);
	}
	for (const bad of [
		"http://app.example/cb",
		"http://localhost.example/cb",
		"myapp:/cb",
		"javascript:alert(1)",
		"javascript.foo:/x",
		"data:text/html,x",
		"file:///x",
		"urn:ietf:wg:oauth:2.0:oob",
	]) {
		expect(registrable(bad)).toBe(false);
	}
	expect(matches("http://127.0.0.2:9000/cb", "http://127.0.0.2/cb")).toBe(true);
	expect(matches("http://127.0.0.1:9000/cb", "http://127.0.0.2:9000/cb")).toBe(false);
	expect(matches("http://localhost:8080/cb", "http://localhost:9999/cb")).toBe(false);
});

it("binds a re-authentication to the whole request", async () => {
	const { authorize, login } = await serve();
	const old = await login();
	now += 10_000;
	const asked = await authorize(request({ prompt: "login" }), old);
	const resume = new URL(asked.at?.searchParams.get("redirect_to") ?? "");
	now += 1000;
	const fresh = await login();
	resume.searchParams.set("state", "changed");
	expect((await authorize(resume.search.slice(1), fresh)).at?.pathname).toBe("/login");
});

it("revokes a code's token when its session logs out later", async () => {
	const s = await serve();
	const cookie = await s.login();
	const code = (await s.authorize(request(), cookie)).at?.searchParams.get("code") ?? "";
	const first = await s.token({ code, redirect_uri: callback, code_verifier: verifier });
	const t = s.app.get(tokens);
	expect((await t.verifyAccess(String(first.body.access_token))).kind).toBe("valid");
	const session = (await s.opened.enter(
		testRequest({ headers: new Map([["cookie", cookie]]) }),
	)) as Session;
	await s.opened.close(session.id);
	expect(await t.verifyAccess(String(first.body.access_token))).toEqual({
		kind: "invalid",
		reason: "revoked",
	});
});

it("adds an ID token through code-grant when the scope holds the maker's, with the code's facts", async () => {
	const asked: IdTokenRequest[] = [];
	const maker = defineModule({ name: "maker" }, (m) => [
		m.contribute(idTokens).by(() => ({
			scope: "openid",
			make: async (r: IdTokenRequest) => {
				asked.push(r);
				return "id.token.here";
			},
		})),
	]);
	const s = await serve({ extra: [maker] });
	const cookie = await s.login();
	const code =
		(
			await s.authorize(request({ scope: "openid read", nonce: "n1" }), cookie)
		).at?.searchParams.get("code") ?? "";
	const res = await s.token({ code, redirect_uri: callback, code_verifier: verifier });
	expect([res.status, res.body.id_token, res.body.scope]).toEqual([
		200,
		"id.token.here",
		"openid read",
	]);
	expect(asked[0]).toMatchObject({ subject: "alice", clientId: "app", nonce: "n1", amr: ["pwd"] });
	const plain =
		(await s.authorize(request({ scope: "read" }), cookie)).at?.searchParams.get("code") ?? "";
	expect(
		(await s.token({ code: plain, redirect_uri: callback, code_verifier: verifier })).body.id_token,
	).toBeUndefined();
});

it("records a re-authentication only when one is asked for", async () => {
	const { authorize } = await serve();
	const plain = await authorize(request());
	expect(new URL(plain.at?.searchParams.get("redirect_to") ?? "").searchParams.has("reauth")).toBe(
		false,
	);
	const asked = await authorize(request({ max_age: "60" }));
	expect(new URL(asked.at?.searchParams.get("redirect_to") ?? "").searchParams.has("reauth")).toBe(
		true,
	);
});

it("does not count a re-authentication made for the same client with another state or challenge", async () => {
	const { authorize, login } = await serve();
	const old = await login();
	now += 10_000;
	const reauthFor = async () => {
		const asked = await authorize(request({ prompt: "login" }), old);
		return (
			new URL(asked.at?.searchParams.get("redirect_to") ?? "").searchParams.get("reauth") ?? ""
		);
	};
	const first = await reauthFor();
	const second = await reauthFor();
	now += 1000;
	const fresh = await login();
	expect(
		(await authorize(request({ prompt: "login", reauth: first, state: "other" }), fresh)).at
			?.pathname,
	).toBe("/login");
	const otherChallenge = createHash("sha256").update("x".repeat(43)).digest("base64url");
	expect(
		(
			await authorize(
				request({ prompt: "login", reauth: second, code_challenge: otherChallenge }),
				fresh,
			)
		).at?.pathname,
	).toBe("/login");
});

it("writes nothing for a plain request without a session, even when writes would fail", async () => {
	const { authorize, down } = await serve();
	down.reauths.failNext("save");
	const res = await authorize(request());
	expect(res.at?.pathname).toBe("/login");
});

it("never counts a login whose authentication time is unknown as the newer one prompt=login asks, and refuses it back from the login", async () => {
	const { authorize, login } = await serve();
	const old = await login();
	now += 10_000;
	const asked = await authorize(request({ prompt: "login" }), old);
	const resume = new URL(asked.at?.searchParams.get("redirect_to") ?? "");
	now += 1000;
	const unknown = await login("alice", ["pwd"], "unknown");
	const back = await authorize(resume.search.slice(1), unknown);
	expect(back.at?.searchParams.get("error")).toBe("login_required");
	expect((await authorize(request({ prompt: "login" }), unknown)).at?.pathname).toBe("/login");
});

it("never counts a session whose authentication time is unknown within max_age, and refuses it back from the login", async () => {
	const { authorize, login } = await serve();
	const unknown = await login("alice", ["pwd"], "unknown");
	const asked = await authorize(request({ max_age: "60" }), unknown);
	expect(asked.at?.pathname).toBe("/login");
	const resume = new URL(asked.at?.searchParams.get("redirect_to") ?? "");
	const again = await login("alice", ["pwd"], "unknown");
	const back = await authorize(resume.search.slice(1), again);
	expect(back.at?.searchParams.get("error")).toBe("login_required");
	// Asked for no fresh login, it is a session like any other.
	expect((await authorize(request(), again)).at?.searchParams.has("code")).toBe(true);
});

it("judges max_age on the kernel's clock, the one its session's login time is on", async () => {
	const { authorize, login } = await serve();
	now += 120_000;
	const cookie = await login();
	now += 59_000;
	expect((await authorize(request({ max_age: "60" }), cookie)).at?.searchParams.has("code")).toBe(
		true,
	);
	now += 41_000;
	expect((await authorize(request({ max_age: "60" }), cookie)).at?.pathname).toBe("/login");
});

it("hashes a re-authentication the same whatever the order of parameters or prompt words", async () => {
	const { authorize, login } = await serve();
	const old = await login();
	now += 10_000;
	const asked = await authorize(request({ prompt: "login consent" }), old);
	const resume = new URL(asked.at?.searchParams.get("redirect_to") ?? "");
	now += 1000;
	const fresh = await login();
	const reordered = new URLSearchParams([...resume.searchParams].reverse());
	reordered.set("prompt", "consent login login");
	const res = await authorize(reordered.toString(), fresh);
	expect(res.at?.pathname).not.toBe("/login");
});

it("meets an acr by the amr sets its table names, and sends a session that falls short to raise it", async () => {
	const s = await serve({
		acr: { "urn:test:mfa": [["mfa"]] },
		authorize: { "step-up-page": "https://as.example/mfa" },
	});
	const asked = request({ acr_values: "urn:test:mfa" });
	const short = await s.authorize(asked, await s.login());
	expect(`${short.at?.origin}${short.at?.pathname}`).toBe("https://as.example/mfa");
	expect(short.at?.searchParams.get("acr_values")).toBe("urn:test:mfa");
	const back = new URL(short.at?.searchParams.get("redirect_to") ?? "");
	expect(`${back.origin}${back.pathname}`).toBe("https://as.example/oauth/authorize");
	const met = await s.authorize(asked, await s.login("alice", ["pwd", "otp", "mfa"]));
	expect(met.at?.searchParams.get("code")).toBeTruthy();
	const quiet = await s.authorize(
		request({ acr_values: "urn:test:mfa", prompt: "none" }),
		await s.login(),
	);
	expect(quiet.at?.searchParams.get("error")).toBe("interaction_required");
	const unknown = await s.authorize(request({ acr_values: "gold" }), await s.login());
	expect(unknown.at?.searchParams.get("error")).toBe("unmet_authentication_requirements");
});

it("binds to the code the first acr met in the order asked, past any not met", async () => {
	const asked: IdTokenRequest[] = [];
	const maker = defineModule({ name: "maker" }, (m) => [
		m.contribute(idTokens).by(() => ({
			scope: "openid",
			make: async (r: IdTokenRequest) => {
				asked.push(r);
				return "id.token.here";
			},
		})),
	]);
	const s = await serve({
		extra: [maker],
		acr: {
			"urn:test:one": [["pwd"]],
			"urn:test:either": [["pwd"], ["otp"]],
			"urn:test:two": [["pwd", "otp"]],
		},
	});
	for (const order of [
		"urn:test:either urn:test:one",
		"urn:test:one urn:test:either",
		"urn:test:two urn:test:one",
	]) {
		const res = await s.authorize(request({ scope: "openid", acr_values: order }), await s.login());
		const code = res.at?.searchParams.get("code") ?? "";
		await s.token({ code, redirect_uri: callback, code_verifier: verifier });
	}
	await s.token({
		code:
			(await s.authorize(request({ scope: "openid" }), await s.login())).at?.searchParams.get(
				"code",
			) ?? "",
		redirect_uri: callback,
		code_verifier: verifier,
	});
	expect(asked.map((r) => r.acr)).toEqual([
		"urn:test:either",
		"urn:test:one",
		"urn:test:one",
		undefined,
	]);
});

describe("authorize: one trip to raise the authentication", () => {
	const raised = async (s: Awaited<ReturnType<typeof serve>>, cookie: string) => {
		const done = await s.opened.raise(testRequest({ headers: new Map([["cookie", cookie]]) }), [
			"otp",
			"mfa",
		]);
		return done?.cookies[0]?.split(";")[0] ?? "";
	};
	const table = {
		acr: { "urn:test:mfa": [["mfa"]] },
		authorize: { "step-up-page": "https://as.example/mfa" },
	};

	it("answers unmet when the browser comes back without raising, and issues once it raised", async () => {
		const s = await serve(table);
		const cookie = await s.login();
		const sent = await s.authorize(request({ acr_values: "urn:test:mfa" }), cookie);
		const back = new URL(sent.at?.searchParams.get("redirect_to") ?? "");
		const unraised = await s.authorize(back.search.slice(1), cookie);
		expect(unraised.at?.searchParams.get("error")).toBe("unmet_authentication_requirements");
		const again = await s.authorize(request({ acr_values: "urn:test:mfa" }), cookie);
		const resume = new URL(again.at?.searchParams.get("redirect_to") ?? "");
		const done = await s.authorize(resume.search.slice(1), await raised(s, cookie));
		expect(done.at?.searchParams.has("code")).toBe(true);
	});

	it("keeps a newer login asked by prompt=login across the trip to raise it", async () => {
		const s = await serve(table);
		const old = await s.login();
		now += 10_000;
		const asked = await s.authorize(request({ acr_values: "urn:test:mfa", prompt: "login" }), old);
		const resume = new URL(asked.at?.searchParams.get("redirect_to") ?? "");
		now += 1000;
		const fresh = await s.login();
		const sent = await s.authorize(resume.search.slice(1), fresh);
		expect(`${sent.at?.origin}${sent.at?.pathname}`).toBe("https://as.example/mfa");
		const back = new URL(sent.at?.searchParams.get("redirect_to") ?? "");
		const done = await s.authorize(back.search.slice(1), await raised(s, fresh));
		expect(done.at?.searchParams.has("code")).toBe(true);
		const reused = await s.authorize(back.search.slice(1), await raised(s, await s.login()));
		expect(reused.at?.searchParams.has("code")).toBe(false);
	});
});

it("refuses a claims parameter that is no object or asks for acr, and ignores the other claims it names", async () => {
	const s = await serve({ acr: { "urn:test:pwd": [["pwd"]] } });
	const cookie = await s.login();
	const answer = async (claims: string, extra: Record<string, string> = {}) =>
		(await s.authorize(request({ claims, ...extra }), cookie)).at?.searchParams;
	const acr = JSON.stringify({ id_token: { acr: { essential: true, values: ["urn:test:pwd"] } } });
	for (const asked of [acr, JSON.stringify({ userinfo: { acr: null } }), "[]", "not json"]) {
		expect((await answer(asked))?.get("error")).toBe("invalid_request");
	}
	expect((await answer(acr, { acr_values: "urn:test:pwd" }))?.get("error")).toBe("invalid_request");
	expect((await answer(JSON.stringify({ id_token: { email: null } })))?.has("code")).toBe(true);
});

it("asks a session whose authentication time is unknown to log in again for an essential auth_time, as max_age does", async () => {
	const { authorize, login } = await serve();
	const authTime = (essential: boolean) =>
		JSON.stringify({ id_token: { auth_time: essential ? { essential: true } : null } });
	const unknown = await login("alice", ["pwd"], "unknown");
	const resumeOf = async () => {
		const asked = await authorize(request({ claims: authTime(true) }), unknown);
		expect(asked.at?.pathname).toBe("/login");
		const resume = new URL(asked.at?.searchParams.get("redirect_to") ?? "");
		expect(resume.searchParams.get("reauth")).toMatch(/^[A-Za-z0-9_-]{43}$/);
		return resume.search.slice(1);
	};
	const stillUnknown = await authorize(await resumeOf(), await login("alice", ["pwd"], "unknown"));
	expect(stillUnknown.at?.searchParams.get("error")).toBe("login_required");
	expect((await authorize(await resumeOf(), await login())).at?.searchParams.has("code")).toBe(
		true,
	);
	const quiet = await authorize(request({ claims: authTime(true), prompt: "none" }), unknown);
	expect(quiet.at?.searchParams.get("error")).toBe("login_required");
	const known = await authorize(request({ claims: authTime(true) }), await login());
	expect(known.at?.searchParams.has("code")).toBe(true);
	const loose = await authorize(request({ claims: authTime(false) }), unknown);
	expect(loose.at?.searchParams.has("code")).toBe(true);
});

it("offers a contributed acr unless the operator's table names the same acr", async () => {
	const offered = (acr: string) =>
		defineModule({ name: `offers-${acr}` }, (m) => [
			m.contribute(acrEntries).by(() => ({ acr, sets: [["mfa"]] })),
		]);
	const s = await serve({
		extra: [offered("urn:test:own"), offered("urn:test:both")],
		acr: { "urn:test:both": [["pwd"]] },
	});
	const cookie = await s.login();
	const code = async (acr: string) =>
		(await s.authorize(request({ acr_values: acr }), cookie)).at?.searchParams;
	expect((await code("urn:test:own"))?.get("error")).toBe("unmet_authentication_requirements");
	expect((await code("urn:test:both"))?.has("code")).toBe(true);
	const strong = await s.login("alice", ["pwd", "mfa"]);
	const met = await s.authorize(request({ acr_values: "urn:test:own" }), strong);
	expect(met.at?.searchParams.has("code")).toBe(true);
});

it("names among the issuer's metadata where it is, that it answers with a code, and PKCE by S256 alone", async () => {
	const published = contract<readonly MetadataItem[]>("published");
	const reader = defineModule({ name: "reader" }, (m) => [
		m.provide(published).by((c) => c.collect(metadata)),
	]);
	const { app } = await serve({ extra: [reader] });
	const items = app.get(published);
	expect(items).toContainEqual({
		name: "authorization_endpoint",
		value: `${issuer}/oauth/authorize`,
	});
	expect(items).toContainEqual({ name: "response_types_supported", value: ["code"] });
	expect(items).toContainEqual({ name: "code_challenge_methods_supported", value: ["S256"] });
});

it("takes its pages only as https URLs kept as written: no userinfo, no fragment", () => {
	const pages = (login: string, stepUp?: string) =>
		section.safeParse({ "login-page": login, ...(stepUp ? { "step-up-page": stepUp } : {}) })
			.success;
	expect(pages("https://as.example/login?ui=1", "https://as.example/raise")).toBe(true);
	for (const value of [
		"https://u@as.example/login",
		"https://as.example/#/login",
		"HTTPS://as.example/login",
	]) {
		expect(pages(value), value).toBe(false);
		expect(pages("https://as.example/login", value), value).toBe(false);
	}
});

describe("authorize: openid in the request", () => {
	const required = { authorize: { "oidc-mode": "oidc-required" } };
	const answer = (res: { at: URL | undefined }) =>
		["code", "error", "state", "iss"].map((name) =>
			name === "code" ? res.at?.searchParams.has(name) : res.at?.searchParams.get(name),
		);

	it("requires openid by default", () => {
		const parsed = section.parse({ "login-page": "https://as.example/login" });
		expect(parsed["oidc-mode"]).toBe("oidc-required");
		expect(
			section.safeParse({ "login-page": "https://as.example/login", "oidc-mode": "x" }).success,
		).toBe(false);
	});

	it("refuses a request that does not name openid itself with invalid_scope, sent back", async () => {
		const { authorize, login } = await serve(required);
		const cookie = await login();
		const refused = [false, "invalid_scope", "s1", issuer];
		expect(answer(await authorize(request(), cookie))).toEqual(refused);
		expect(answer(await authorize(request({ scope: "read" }), cookie))).toEqual(refused);
		expect(answer(await authorize(request({ client_id: "openid-default" }), cookie))).toEqual(
			refused,
		);
		expect(answer(await authorize(request({ scope: "openid read" }), cookie))).toEqual([
			true,
			null,
			"s1",
			issuer,
		]);
	});

	it("keeps the refusal of a scope left out with no default, and records it", async () => {
		const { authorize, login, events } = await serve(required);
		const res = await authorize(request({ client_id: "nodefault" }), await login());
		expect(res.at?.searchParams.get("error")).toBe("invalid_scope");
		expect(events.map((event) => event.attributes?.reason)).toEqual([
			"scope_omitted_without_default",
		]);
	});

	it("gives a request without openid the scope it asks, or the client's default, in dual mode", async () => {
		const { authorize, login } = await serve();
		const cookie = await login();
		for (const params of [request(), request({ scope: "read" })]) {
			expect(answer(await authorize(params, cookie))).toEqual([true, null, "s1", issuer]);
		}
	});
});

describe("authorize: audit events", () => {
	const rejected = (client: string, reason: string) => ({
		kind: "authorize.rejected",
		at: now,
		attributes: { client, reason, source: "198.51.100.1" },
	});

	it("records a code given with the subject and the client, never the code or the request's values", async () => {
		const { authorize, login, events } = await serve();
		const res = await authorize(request(), await login());
		const code = res.at?.searchParams.get("code") ?? "";
		expect(code).not.toBe("");
		expect(events).toEqual([
			{
				kind: "authorize.granted",
				at: now,
				subject: "alice",
				attributes: { client: "app", response_type: "code", source: "198.51.100.1" },
			},
		]);
		expect(JSON.stringify(events)).not.toMatch(new RegExp(`${code}|s1|${challenge}|app\\.example`));
	});

	it("records the refusals it decides for a client or a consent, with the reason, without the subject", async () => {
		const { authorize, login, events } = await serve();
		const cookie = await login();
		await authorize(request({ client_id: "nocode" }), cookie);
		await authorize(request({ client_id: "nodefault" }), cookie);
		await authorize(request({ client_id: "third", prompt: "none" }), cookie);
		expect(events).toEqual([
			rejected("nocode", "grant_type_not_allowed"),
			rejected("nodefault", "scope_omitted_without_default"),
			rejected("third", "consent_required"),
		]);
	});

	it("records nothing for a malformed request, an unknown client or redirect URI, or while unavailable", async () => {
		const { authorize, login, events, down } = await serve();
		const cookie = await login();
		await authorize(request({ client_id: "nobody" }), cookie);
		await authorize(request({ redirect_uri: `${callback}/` }), cookie);
		await authorize(request({ code_challenge: "" }), cookie);
		await authorize(request({ scope: "admin" }), cookie);
		await authorize(request({ prompt: "none" }));
		await authorize(request({ client_id: "third" }), cookie);
		down.reauths.failNext("save");
		await authorize(request({ prompt: "login" }), cookie);
		expect(events).toEqual([]);
	});
});

describe("authorize: the issuance policies", () => {
	/** A policy that refuses bob, as one would a user whose email is not verified, and keeps what it was asked. */
	const refusingBob = (asked: IssuanceRequest[], down = false) =>
		defineModule({ name: "refusing-bob" }, (m) => [
			m.contribute(issuancePolicies).by(() => ({
				name: "refusing-bob",
				judge: async (request) => {
					asked.push(request);
					if (down) throw new Unavailable("refusing-bob");
					return request.grant.subject === "bob"
						? {
								kind: "refused",
								reason: "email_not_verified",
								description: "email address is not verified",
							}
						: { kind: "allowed" };
				},
			})),
		]);
	const answered = (res: { at?: URL | undefined }) => [
		res.at?.searchParams.get("error"),
		res.at?.searchParams.get("error_description"),
		res.at?.searchParams.get("state"),
		res.at?.searchParams.get("iss"),
		res.at?.searchParams.has("code"),
	];
	const denied = ["access_denied", "email address is not verified", "s1", issuer, false];

	it("records a refusal with the policy's name and its reason, never the subject or the request's values", async () => {
		const { authorize, login, events } = await serve({ extra: [refusingBob([])] });
		expect(answered(await authorize(request(), await login("bob")))).toEqual(denied);
		expect(events).toEqual([
			{
				kind: "authorize.rejected",
				at: now,
				attributes: {
					client: "app",
					reason: "email_not_verified",
					policy: "refusing-bob",
					source: "198.51.100.1",
				},
			},
		]);
	});

	it("asks them after login, before consent, and sends a refusal back as access_denied with its description", async () => {
		const asked: IssuanceRequest[] = [];
		const { authorize, login, events, opened } = await serve({ extra: [refusingBob(asked)] });
		expect((await authorize(request())).at?.pathname).toBe("/login");
		expect(asked).toEqual([]);
		const bob = await login("bob");
		expect(answered(await authorize(request(), bob))).toEqual(denied);
		for (const prompt of [undefined, "none", "consent"]) {
			const third = request({ client_id: "third", ...(prompt ? { prompt } : {}) });
			expect(answered(await authorize(third, bob))).toEqual(denied);
		}
		expect(events.map((e) => [e.kind, e.attributes?.client, e.attributes?.reason])).toEqual([
			["authorize.rejected", "app", "email_not_verified"],
			...Array(3).fill(["authorize.rejected", "third", "email_not_verified"]),
		]);
		const alice = await login("alice");
		const given = await authorize(request({ scope: "read write" }), alice);
		expect(given.at?.searchParams.has("code")).toBe(true);
		const session = await opened.enter(testRequest({ headers: new Map([["cookie", alice]]) }));
		expect(asked.at(-1)).toEqual({
			grant: {
				subject: "alice",
				issuedTo: "app",
				audience: ["https://api"],
				scope: ["read", "write"],
				amr: ["pwd"],
				authenticatedAt: now,
			},
			grantType: "authorization_code",
			session: session?.id,
		});
	});

	it("asks them with the acr the session met, after a session that falls short is sent to raise it", async () => {
		const asked: IssuanceRequest[] = [];
		const { authorize, login } = await serve({
			extra: [refusingBob(asked)],
			acr: { "urn:test:mfa": [["mfa"]] },
			authorize: { "step-up-page": "https://as.example/mfa" },
		});
		const raising = request({ acr_values: "urn:test:mfa" });
		expect((await authorize(raising, await login("bob"))).at?.pathname).toBe("/mfa");
		expect(asked).toEqual([]);
		const met = await authorize(raising, await login("alice", ["pwd", "mfa"]));
		expect(met.at?.searchParams.has("code")).toBe(true);
		expect(asked.map((request) => [request.grant.acr, request.grant.amr])).toEqual([
			["urn:test:mfa", ["pwd", "mfa"]],
		]);
	});

	it("asks them with the mark that the authentication time is unknown, only for such a session", async () => {
		const asked: IssuanceRequest[] = [];
		const { authorize, login } = await serve({ extra: [refusingBob(asked)] });
		const unknown = await authorize(request(), await login("alice", ["pwd"], "unknown"));
		expect(unknown.at?.searchParams.has("code")).toBe(true);
		const known = await authorize(request(), await login("alice"));
		expect(known.at?.searchParams.has("code")).toBe(true);
		expect(asked.map((request) => request.grant.authenticatedAtUnknown)).toEqual([true, undefined]);
		expect(Object.hasOwn(asked[1]?.grant ?? {}, "authenticatedAtUnknown")).toBe(false);
	});

	it("refuses a client that is not first-party first while consent cannot ask", async () => {
		const asked: IssuanceRequest[] = [];
		const { authorize, login } = await serve({ extra: [refusingBob(asked)], asking: false });
		const res = await authorize(request({ client_id: "third" }), await login("bob"));
		expect(res.at?.searchParams.get("error")).toBe("unauthorized_client");
		expect(asked).toEqual([]);
	});

	it("answers unavailable when a policy cannot tell, and logs it", async () => {
		const { authorize, login, events } = await serve({ extra: [refusingBob([], true)] });
		const before = warnings().length;
		const res = await authorize(request(), await login());
		expect(answered(res)).toEqual(["temporarily_unavailable", null, "s1", issuer, false]);
		expect(
			warnings()
				.slice(before)
				.map((line) => line.fields),
		).toEqual([{ what: "refusing-bob", route: "/oauth/authorize" }]);
		expect(events).toEqual([]);
	});
});
