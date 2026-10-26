import { isUnavailable, Unavailable } from "@mod/kernel";
import type { Narrower, Outbound, OutboundRequest, OutboundResponse } from "@mod/outbound";
import { outboundOver, section as outboundSection } from "@mod/outbound/module";
import type { OutboundRefusals } from "@mod/outbound-policy";
import { type AuthorizationStart, type CodeExchange, UpstreamRefused } from "@mod/upstreams";
import { describe, expect, it } from "vitest";
import { settingsOf } from "../src/settings.ts";
import { opened } from "../src/upstream.ts";

type Handler = (request: OutboundRequest) => OutboundResponse | "unreachable" | "broken";
const ok = (json: unknown, status = 200): OutboundResponse => ({
	status,
	headers: new Map(),
	body: new TextEncoder().encode(JSON.stringify(json)),
});

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

function open(handlers: { token?: Handler; user?: Handler }, more: Record<string, unknown> = {}) {
	const asked: {
		url: string;
		request: OutboundRequest;
		hosts?: readonly string[];
		internal?: string;
	}[] = [];
	const table: Record<string, Handler | undefined> = {
		"https://github.com/login/oauth/access_token":
			handlers.token ?? (() => ok({ access_token: "gho_x", token_type: "bearer" })),
		"https://api.github.com/user": handlers.user ?? (() => ok({ id: 583231, login: "octocat" })),
	};
	const outbound: Outbound = {
		fetch: async (url, request = {}, narrower = {}) => {
			asked.push({
				url,
				request,
				...(narrower.hosts ? { hosts: narrower.hosts } : {}),
				...(narrower.internal ? { internal: narrower.internal } : {}),
			});
			const answer = table[url]?.(request) ?? ok({}, 404);
			if (answer === "unreachable") throw new Unavailable("stub");
			if (answer === "broken") throw new Error("refused by the destination policy");
			return answer;
		},
	};
	const read = settings.parse({ "client-id": "cid", "client-secret": "sec", ...more });
	return { upstream: opened(read, outbound), asked };
}

const start: AuthorizationStart = {
	state: "s",
	nonce: "n",
	challenge: "c",
	challengeMethod: "S256",
	redirectUri: "https://as.example/cb",
};
const exchange = (more: Partial<CodeExchange> = {}): CodeExchange => ({
	code: "c",
	verifier: "v",
	redirectUri: "https://as.example/session/oauth/federation/gh/callback",
	nonce: "n",
	iss: undefined,
	...more,
});
const outcome = (run: Promise<unknown>) =>
	run.then(
		(value) => value,
		(error) =>
			UpstreamRefused.is(error) ? "refused" : isUnavailable(error) ? "unavailable" : error,
	);

describe("idp-github", () => {
	it("says its issuer is the one its settings name, GitHub's unless told another", () => {
		expect(open({}).upstream.issuer).toBe("https://github.com/login/oauth");
		expect(open({}, { issuer: "https://ghe.example/login/oauth" }).upstream.issuer).toBe(
			"https://ghe.example/login/oauth",
		);
	});

	it("asks GitHub to authorize with PKCE, and its own endpoints unless told others [rfc9700-2.1.1-f] [rfc9700-2.1.1-h] [rfc9700-2.1.2-a]", () => {
		const { upstream } = open({});
		const url = new URL(upstream.authorizationUrl(start));
		expect(`${url.origin}${url.pathname}`).toBe("https://github.com/login/oauth/authorize");
		expect(Object.fromEntries(url.searchParams)).toEqual({
			response_type: "code",
			client_id: "cid",
			redirect_uri: "https://as.example/cb",
			scope: "read:user",
			state: "s",
			code_challenge: "c",
			code_challenge_method: "S256",
		});
		const enterprise = open(
			{},
			{ "authorization-endpoint": "https://ghe.example/login/oauth/authorize" },
		);
		expect(enterprise.upstream.authorizationUrl(start)).toMatch(/^https:\/\/ghe\.example\//);
	});

	it("exchanges the code with its verifier and the client's secret, and answers the user's numeric id [rfc6750-2.3-d] [rfc9700-4.3.2-a]", async () => {
		const { upstream, asked } = open({});
		expect(await upstream.exchange(exchange())).toEqual({ subject: "583231", amr: [] });
		const [token, user] = asked;
		expect(token?.request.method).toBe("POST");
		expect(token?.request.headers?.accept).toBe("application/json");
		expect(Object.fromEntries(new URLSearchParams(String(token?.request.body)))).toEqual({
			grant_type: "authorization_code",
			code: "c",
			redirect_uri: exchange().redirectUri,
			code_verifier: "v",
			client_id: "cid",
			client_secret: "sec",
		});
		// The User-Agent GitHub's API requires is outbound's own; this module sends none. The token is
		// outbound's to send, as the request's credential.
		expect(user?.request.headers).toEqual({
			accept: "application/vnd.github+json",
			"x-github-api-version": "2022-11-28",
		});
		expect(user?.request.credential).toBe("Bearer gho_x");
	});

	it("gives the user's public profile, its email never verified, as GitHub's user answer cannot say so", async () => {
		const profileOf = async (user: Record<string, unknown>) => {
			const { upstream } = open({ user: () => ok({ id: 583231, ...user }) });
			return ((await upstream.exchange(exchange())) as { profile?: unknown }).profile;
		};
		const said = {
			email: "octo@example.com",
			name: "Octo Cat",
			avatar_url: "https://av.example/o",
		};
		expect(await profileOf({ ...said, verified: true, email_verified: true })).toEqual({
			email: said.email,
			emailVerified: false,
			name: said.name,
			picture: said.avatar_url,
		});
		expect(await profileOf({ email: null, name: null, avatar_url: said.avatar_url })).toEqual({
			picture: said.avatar_url,
		});
		expect(await profileOf({ name: said.name, avatar_url: 7 })).toEqual({ name: said.name });
		expect(await profileOf({ login: "octocat" })).toBeUndefined();
	});

	it("sends the code and the access token only to the hosts of the endpoints the operator set [rfc6750-5.3-f]", async () => {
		const { upstream, asked } = open({});
		await upstream.exchange(exchange());
		expect(asked.map((a) => a.hosts)).toEqual([
			["github.com", "api.github.com"],
			["github.com", "api.github.com"],
		]);
		// Each sent for the endpoint the operator set, so one on an internal network is reached as theirs.
		expect(asked.map((a) => a.internal)).toEqual([
			"https://github.com/login/oauth/access_token",
			"https://api.github.com",
		]);
	});

	it("reaches a GitHub Enterprise at a private address as the operator's endpoints, only where outbound.internal-hosts lists its host", async () => {
		const enterprise = {
			"client-id": "cid",
			"client-secret": "sec",
			"authorization-endpoint": "https://ghe.corp/login/oauth/authorize",
			"token-endpoint": "https://ghe.corp/login/oauth/access_token",
			api: "https://ghe.corp/api/v3/",
		};
		/** outbound itself, every name resolving to a private address, a request ending fast. */
		const pathsOf = (internal: readonly string[]) =>
			outboundOver(
				outboundSection.parse({
					allow: ["ghe.corp"],
					"internal-hosts": internal,
					timeout: "300ms",
				}),
				async () => ["10.0.0.5"],
			);
		for (const [internal, expected] of [
			[[], "refused"],
			[["ghe.corp"], "unavailable"],
		] as const) {
			const paths = pathsOf(internal);
			// Boot asks with the same narrowing, and outbound's policy refuses no host it allows.
			const read = settingsOf({ explained: paths.explained }).parse(enterprise);
			const upstream = opened(read, { fetch: paths.fetch } as Outbound);
			// Unlisted, the address refuses the token request; listed, it gets past it to the connection.
			expect(await outcome(upstream.exchange(exchange())), JSON.stringify(internal)).toBe(expected);
		}
	});

	it("refuses at boot, at its key, an endpoint outbound's policy refuses, GitHub's own included", () => {
		const both = { "client-id": "cid", "client-secret": "sec" };
		const refusalsOf = (refused: readonly string[], more: Record<string, unknown> = {}) =>
			settingsOf(policyRefusing(refused))
				.safeParse({ ...both, ...more })
				.error?.issues.map((i) => [i.path, i.message]);
		const refused = (key: string) => [
			[key],
			`outbound's destination policy refuses it: ${notAllowed}`,
		];
		policyAsked.length = 0;
		expect(refusalsOf(["github.com"])).toEqual([refused("token-endpoint")]);
		const hosts = ["github.com", "api.github.com"];
		expect(policyAsked).toEqual([
			{
				url: "https://github.com/login/oauth/access_token",
				narrower: { hosts, internal: "https://github.com/login/oauth/access_token" },
			},
			{
				url: "https://api.github.com/user",
				narrower: { hosts, internal: "https://api.github.com" },
			},
		]);
		expect(refusalsOf(["api.github.com"])).toEqual([refused("api")]);
		const enterprise = {
			api: "https://ghe.example/api/v3/",
			"token-endpoint": "https://ghe.example/t",
		};
		policyAsked.length = 0;
		expect(refusalsOf(["github.com", "api.github.com"], enterprise)).toBeUndefined();
		// The API's trailing slash is not doubled, and a host named twice is narrowed to once.
		expect(policyAsked).toEqual([
			{
				url: "https://ghe.example/t",
				narrower: { hosts: ["ghe.example"], internal: "https://ghe.example/t" },
			},
			{
				url: "https://ghe.example/api/v3/user",
				narrower: { hosts: ["ghe.example"], internal: "https://ghe.example/api/v3/" },
			},
		]);
		expect(refusalsOf(["ghe.example"], enterprise)).toEqual([
			refused("token-endpoint"),
			refused("api"),
		]);
	});

	it("takes the authorization endpoint over plain http only where outbound's policy for the browser does, refusing it at its key", () => {
		const both = { "client-id": "cid", "client-secret": "sec" };
		const refusalsOver = (more: Record<string, unknown>): OutboundRefusals => {
			const paths = outboundOver(outboundSection.parse(more), async () => ["10.0.0.5"]);
			const { explained, plainInternal, browsedRefusal } = paths;
			return { explained, plainInternal, browsedRefusal };
		};
		const policy = refusalsOver({
			allow: ["ghe.internal", "ghe.example", "127.0.0.1"],
			"plain-internal": ["ghe.internal:8080"],
		});
		const keysOf = (refusals: OutboundRefusals, more: Record<string, unknown>) =>
			settingsOf(refusals)
				.safeParse({ ...both, ...more })
				.error?.issues.map((i) => i.path.join("."));
		const at = (authorization: string) => ({
			"authorization-endpoint": authorization,
			"token-endpoint": "https://ghe.example/t",
			api: "https://ghe.example/api/v3/",
		});
		expect(keysOf(policy, at("https://ghe.example/login/oauth/authorize"))).toBeUndefined();
		expect(keysOf(policy, at("http://127.0.0.1:9200/login/oauth/authorize"))).toBeUndefined();
		expect(keysOf(policy, at("http://ghe.internal:8080/login/oauth/authorize"))).toBeUndefined();
		for (const refused of ["http://ghe.example/login", "http://ghe.internal:9090/login"]) {
			expect(keysOf(policy, at(refused)), refused).toEqual(["authorization-endpoint"]);
		}
		// A policy that does not say takes https alone.
		expect(keysOf(policyRefusing(), at("http://127.0.0.1:9200/login"))).toEqual([
			"authorization-endpoint",
		]);
	});

	it("asks for the browser's endpoint with it as the operator's URL", () => {
		const asked: [string, string | undefined][] = [];
		const refusals: OutboundRefusals = {
			explained: () => undefined,
			browsedRefusal: (url, narrower) => {
				asked.push([url, narrower?.internal]);
				return undefined;
			},
		};
		settingsOf(refusals).parse({ "client-id": "cid", "client-secret": "sec" });
		const github = "https://github.com/login/oauth/authorize";
		expect(asked).toEqual([[github, github]]);
	});

	it("takes an id written as its canonical digits, and never one past the safe integers", async () => {
		const answered = async (id: unknown) =>
			outcome(open({ user: () => ok({ id }) }).upstream.exchange(exchange()));
		expect(await answered("42")).toEqual({ subject: "42", amr: [] });
		for (const bad of [0, -1, 1.5, 2 ** 53, "042", "9007199254740993", "", "x", null]) {
			expect(await answered(bad), String(bad)).toBe("refused");
		}
	});

	it("refuses an answer from another issuer before using its code, and takes the issuer's own [rfc9700-2.1-e] [rfc9700-2.1-f] [rfc9700-4.4.2.1-a]", async () => {
		const { upstream, asked } = open({});
		expect(await outcome(upstream.exchange(exchange({ iss: "https://evil.example" })))).toBe(
			"refused",
		);
		expect(asked).toEqual([]);
		expect(
			await outcome(upstream.exchange(exchange({ iss: "https://github.com/login/oauth" }))),
		).toEqual({
			subject: "583231",
			amr: [],
		});
	});

	it("refuses a code GitHub refused, however it answers, and is unavailable where GitHub cannot be reached", async () => {
		const answered = (handlers: { token?: Handler; user?: Handler }) =>
			outcome(open(handlers).upstream.exchange(exchange()));
		const cases: Record<string, [{ token?: Handler; user?: Handler }, string]> = {
			"a refused code answered with 200": [
				{ token: () => ok({ error: "bad_verification_code" }) },
				"refused",
			],
			"an empty access token": [
				{ token: () => ok({ access_token: "", token_type: "bearer" }) },
				"refused",
			],
			"a token not bearer": [
				{ token: () => ok({ access_token: "x", token_type: "mac" }) },
				"refused",
			],
			"a token endpoint answering 401": [{ token: () => ok({}, 401) }, "refused"],
			"a token answered with 401": [
				{ token: () => ok({ access_token: "x", token_type: "bearer" }, 401) },
				"refused",
			],
			"bad credentials at /user": [
				{ user: () => ok({ message: "Bad credentials" }, 401) },
				"refused",
			],
			"an id answered with 401": [{ user: () => ok({ id: 1 }, 401) }, "refused"],
			"a /user body not JSON": [
				{ user: () => ({ status: 200, headers: new Map(), body: new Uint8Array([1]) }) },
				"refused",
			],
			"a destination outbound refuses": [{ token: () => "broken" }, "refused"],
			"a token endpoint unreachable": [{ token: () => "unreachable" }, "unavailable"],
			"an API unreachable": [{ user: () => "unreachable" }, "unavailable"],
		};
		for (const [label, [handlers, expected]] of Object.entries(cases)) {
			expect(await answered(handlers), label).toBe(expected);
		}
	});

	it("takes a bearer token type in any case", async () => {
		const token = () => ok({ access_token: "gho_x", token_type: "Bearer" });
		expect(await open({ token }).upstream.exchange(exchange())).toEqual({
			subject: "583231",
			amr: [],
		});
	});

	it("refuses at boot an endpoint or API that is empty or no URL, never throwing on it", () => {
		const both = { "client-id": "cid", "client-secret": "sec" };
		for (const name of ["authorization-endpoint", "token-endpoint", "api"]) {
			for (const value of ["", "not a url"]) {
				const read = () => settings.safeParse({ ...both, [name]: value });
				expect(read, `${name} ${value}`).not.toThrow();
				expect(read().success, `${name} ${value}`).toBe(false);
			}
		}
	});

	it("refuses at boot an empty issuer", () => {
		const both = { "client-id": "cid", "client-secret": "sec" };
		expect(settings.safeParse({ ...both, issuer: "" }).success).toBe(false);
	});

	it("refuses at boot a client ID or secret that is empty or not well-formed text", () => {
		const both = { "client-id": "cid", "client-secret": "sec" };
		for (const name of ["client-id", "client-secret"]) {
			for (const value of ["", "a\uD800"]) {
				expect(settings.safeParse({ ...both, [name]: value }).success, `${name} ${value}`).toBe(
					false,
				);
			}
		}
	});

	it("carries no login time", async () => {
		expect(await open({}).upstream.exchange(exchange())).not.toHaveProperty("authenticatedAt");
	});
});

describe("github's settings", () => {
	it("gives each default as an operator writes it, read through the key's own schema", () => {
		const kindOf = (key: { _zod: { def: { type: string } } }) => key._zod.def.type;
		const byDefault = Object.entries(settings.shape).filter(([, key]) => kindOf(key) === "default");
		expect(byDefault.map(([name]) => name)).toEqual([]);
	});
});
