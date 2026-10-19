import { isUnavailable, Unavailable } from "@mod/kernel";
import type {
	Narrower,
	Outbound,
	OutboundPolicy,
	OutboundRequest,
	OutboundResponse,
} from "@mod/outbound";
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
/** A destination policy refusing the `refused` hosts as not allowed. */
const policyRefusing = (refused: readonly string[] = []): OutboundPolicy => ({
	refusalOf: (url, narrower) => {
		policyAsked.push({ url, narrower });
		return refused.includes(new URL(url).hostname) ? "not-allowed" : undefined;
	},
});
const settings = settingsOf(policyRefusing());

function open(handlers: { token?: Handler; user?: Handler }, more: Record<string, unknown> = {}) {
	const asked: { url: string; request: OutboundRequest; hosts?: readonly string[] }[] = [];
	const table: Record<string, Handler | undefined> = {
		"https://github.com/login/oauth/access_token":
			handlers.token ?? (() => ok({ access_token: "gho_x", token_type: "bearer" })),
		"https://api.github.com/user": handlers.user ?? (() => ok({ id: 583231, login: "octocat" })),
	};
	const outbound: Outbound = {
		fetch: async (url, request = {}, narrower = {}) => {
			asked.push({ url, request, ...(narrower.hosts ? { hosts: narrower.hosts } : {}) });
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
			error instanceof UpstreamRefused ? "refused" : isUnavailable(error) ? "unavailable" : error,
	);

describe("idp-github", () => {
	it("says its issuer is the one its settings name, GitHub's unless told another", () => {
		expect(open({}).upstream.issuer).toBe("https://github.com/login/oauth");
		expect(open({}, { issuer: "https://ghe.example/login/oauth" }).upstream.issuer).toBe(
			"https://ghe.example/login/oauth",
		);
	});

	it("asks GitHub to authorize with PKCE, and its own endpoints unless told others", () => {
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

	it("exchanges the code with its verifier and the client's secret, and answers the user's numeric id", async () => {
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

	it("sends the code and the access token only to the hosts of the endpoints the operator set", async () => {
		const { upstream, asked } = open({});
		await upstream.exchange(exchange());
		expect(asked.map((a) => a.hosts)).toEqual([
			["github.com", "api.github.com"],
			["github.com", "api.github.com"],
		]);
	});

	it("refuses at boot, at its key, an endpoint outbound's policy refuses, GitHub's own included", () => {
		const both = { "client-id": "cid", "client-secret": "sec" };
		const refusalsOf = (refused: readonly string[], more: Record<string, unknown> = {}) =>
			settingsOf(policyRefusing(refused))
				.safeParse({ ...both, ...more })
				.error?.issues.map((i) => [i.path, i.message]);
		const refused = (key: string) => [
			[key],
			"outbound's destination policy refuses it: not-allowed",
		];
		policyAsked.length = 0;
		expect(refusalsOf(["github.com"])).toEqual([refused("token-endpoint")]);
		const hosts = ["github.com", "api.github.com"];
		expect(policyAsked).toEqual([
			{ url: "https://github.com/login/oauth/access_token", narrower: { hosts } },
			{ url: "https://api.github.com/user", narrower: { hosts } },
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
			{ url: "https://ghe.example/t", narrower: { hosts: ["ghe.example"] } },
			{ url: "https://ghe.example/api/v3/user", narrower: { hosts: ["ghe.example"] } },
		]);
		expect(refusalsOf(["ghe.example"], enterprise)).toEqual([
			refused("token-endpoint"),
			refused("api"),
		]);
	});

	it("takes an id written as its canonical digits, and never one past the safe integers", async () => {
		const answered = async (id: unknown) =>
			outcome(open({ user: () => ok({ id }) }).upstream.exchange(exchange()));
		expect(await answered("42")).toEqual({ subject: "42", amr: [] });
		for (const bad of [0, -1, 1.5, 2 ** 53, "042", "9007199254740993", "", "x", null]) {
			expect(await answered(bad), String(bad)).toBe("refused");
		}
	});

	it("refuses an answer from another issuer before using its code, and takes the issuer's own", async () => {
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
