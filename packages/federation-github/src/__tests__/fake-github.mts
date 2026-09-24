/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * A fake GitHub behind a `fetch` implementation.
 *
 * The adapter configures openid-client with no `customFetch`, so every request
 * the library makes — the token exchange, `/user`, `/user/emails` — goes
 * through the global `fetch`. A test installs `github.fetch` there
 * (`vi.stubGlobal("fetch", github.fetch)`) and the real library runs against
 * it: nothing touches the network, and every request is recorded for the test
 * to inspect.
 *
 * The bodies are GitHub's, not an OpenID Provider's: the token response is
 * `token_type: "bearer"` with a comma-delimited `scope` and no id_token, and
 * `/user` answers a numeric `id` and no `sub`. The knobs below let a test make
 * one endpoint answer differently at a time.
 *
 * It is no laxer than GitHub where a client could come to depend on the
 * difference: the token endpoint answers form-encoded unless the request's
 * `Accept` asks for JSON, and the REST API (`api.github.com`) refuses a
 * request without a `User-Agent` with `403`. `fake-github.test.mts` holds it
 * to both.
 */

export const GITHUB = {
	authorizationEndpoint: "https://github.com/login/oauth/authorize",
	tokenEndpoint: "https://github.com/login/oauth/access_token",
	user: "https://api.github.com/user",
	emails: "https://api.github.com/user/emails",
} as const;

export interface RecordedRequest {
	readonly url: URL;
	readonly method: string;
	readonly headers: Headers;
	readonly body: URLSearchParams | undefined;
	/** What the fake answered — a test can ask whether the client read or released its body. */
	readonly response: Response;
}

/** What one endpoint answers: a JSON value, or `raw` text sent as it is. */
export interface FakeAnswer {
	status: number;
	/** Serialized as JSON unless `raw` is set. */
	body: unknown;
	/** A body sent verbatim — for an answer that is not JSON. */
	raw?: string;
	contentType: string;
}

export interface FakeGithub {
	readonly requests: RecordedRequest[];
	readonly fetch: typeof fetch;
	/** The token endpoint's answer. */
	token: FakeAnswer;
	/** `GET /user`'s answer. */
	user: FakeAnswer;
	/** `GET /user/emails`'s answer. */
	emails: FakeAnswer;
	/** Requests to an endpoint, compared on origin and path (a query string is ignored). */
	requestsTo(endpoint: string): RecordedRequest[];
}

export const ACCESS_TOKEN = "gho_16C7e42F292c6912E7710c838347Ae178B4a";

/** GitHub's token response for an OAuth App: no id_token, no expiry, comma-delimited scope. */
export const githubTokenResponse = (): Record<string, unknown> => ({
	access_token: ACCESS_TOKEN,
	token_type: "bearer",
	scope: "read:user,user:email",
});

/** `GET /user` as GitHub answers it for the authenticated user: `id` is a number, there is no `sub`. */
export const githubUser = (): Record<string, unknown> => ({
	login: "octocat",
	id: 12345,
	node_id: "MDQ6VXNlcjEyMzQ1",
	avatar_url: "https://avatars.githubusercontent.com/u/12345?v=4",
	gravatar_id: "",
	url: "https://api.github.com/users/octocat",
	html_url: "https://github.com/octocat",
	type: "User",
	site_admin: false,
	name: "The Octocat",
	company: "@github",
	blog: "https://github.blog",
	location: "San Francisco",
	email: null,
	hireable: null,
	bio: null,
	twitter_username: null,
	public_repos: 8,
	followers: 1000,
	following: 9,
	created_at: "2011-01-25T18:44:36Z",
	updated_at: "2026-09-01T00:00:00Z",
});

/** `GET /user/emails`: every address on the account, with `primary` and `verified`. */
export const githubEmails = (): unknown[] => [
	{ email: "octocat@github.com", primary: true, verified: true, visibility: "public" },
	{ email: "octocat@users.noreply.github.com", primary: false, verified: true, visibility: null },
];

const JSON_TYPE = "application/json; charset=utf-8";
const FORM_TYPE = "application/x-www-form-urlencoded; charset=utf-8";
const answer = (body: unknown): FakeAnswer => ({ status: 200, body, contentType: JSON_TYPE });

const originAndPath = (url: URL): string => `${url.origin}${url.pathname}`;

/** GitHub's own answer to a REST request without a `User-Agent`. */
const NO_USER_AGENT =
	"Request forbidden by administrative rules. Please make sure your request has a User-Agent header (https://docs.github.com/en/rest/overview/resources-in-the-rest-api#user-agent-required). Check https://developer.github.com for other possible causes.";

export function createFakeGithub(): FakeGithub {
	const requests: RecordedRequest[] = [];

	const respond = (a: FakeAnswer): Response =>
		new Response(a.raw ?? JSON.stringify(a.body), {
			status: a.status,
			headers: { "content-type": a.contentType },
		});

	/**
	 * The token endpoint answers `application/x-www-form-urlencoded` by default,
	 * and JSON only when `Accept` asks for it.
	 */
	const respondToken = (headers: Headers): Response => {
		const a = github.token;
		if (a.raw !== undefined || (headers.get("accept") ?? "").includes("application/json")) {
			return respond(a);
		}
		const form = new URLSearchParams();
		for (const [k, v] of Object.entries(a.body as Record<string, unknown>)) form.set(k, String(v));
		return new Response(form.toString(), {
			status: a.status,
			headers: { "content-type": FORM_TYPE },
		});
	};

	const github: FakeGithub = {
		requests,
		fetch: undefined as unknown as typeof fetch,
		token: answer(githubTokenResponse()),
		user: answer(githubUser()),
		emails: answer(githubEmails()),
		requestsTo: (endpoint) => {
			const wanted = originAndPath(new URL(endpoint));
			return requests.filter((r) => originAndPath(r.url) === wanted);
		},
	};

	const route = (url: URL, method: string, headers: Headers): Response => {
		const where = originAndPath(url);
		if (url.hostname === "api.github.com" && !headers.has("user-agent")) {
			return new Response(NO_USER_AGENT, {
				status: 403,
				headers: { "content-type": "text/plain; charset=utf-8" },
			});
		}
		if (where === GITHUB.tokenEndpoint && method === "POST") return respondToken(headers);
		if (where === GITHUB.user && method === "GET") return respond(github.user);
		if (where === GITHUB.emails && method === "GET") return respond(github.emails);
		return new Response(JSON.stringify({ message: "Not Found" }), {
			status: 404,
			headers: { "content-type": JSON_TYPE },
		});
	};

	const fetchImpl = async (
		input: string | URL | Request,
		init?: RequestInit,
	): Promise<Response> => {
		const url = new URL(
			typeof input === "string" ? input : input instanceof URL ? input.href : input.url,
		);
		const method = (
			init?.method ?? (input instanceof Request ? input.method : "GET")
		).toUpperCase();
		const headers = new Headers(
			(init?.headers ??
				(input instanceof Request ? input.headers : undefined)) as ConstructorParameters<
				typeof Headers
			>[0],
		);
		const raw = init?.body;
		const body =
			raw === undefined || raw === null
				? undefined
				: new URLSearchParams(raw instanceof URLSearchParams ? raw : String(raw));
		const response = route(url, method, headers);
		requests.push({ url, method, headers, body, response });
		return response;
	};
	(github as { fetch: typeof fetch }).fetch = fetchImpl as typeof fetch;
	return github;
}
