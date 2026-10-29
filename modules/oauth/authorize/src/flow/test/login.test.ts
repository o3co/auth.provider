import { afterEach, describe, expect, it } from "vitest";
import {
	advance,
	callback,
	eventsDeclared,
	issuer,
	request,
	serve,
	stopServed,
} from "../../../test/harness.ts";

afterEach(() => stopServed());
afterEach(() => eventsDeclared());

describe("the flow: logging in before a refusal", () => {
	/** A query's pairs in order of name, so the way back holds every value sent, repeats included. */
	const pairs = (query: string) =>
		[...new URLSearchParams(query)].sort(([a], [b]) => a.localeCompare(b));

	it("sends a browser without a session to log in before a refusal goes back, and the same request back from its login is refused [rfc9700-4.11.2-b]", async () => {
		const { authorize, login } = await serve();
		const cookie = await login();
		for (const [sent, error] of [
			[new URLSearchParams(request({ scope: "unknown" })).toString(), "invalid_scope"],
			[`${new URLSearchParams(request())}&state=s2`, "invalid_request"],
			[new URLSearchParams(request({ nonce: "n".repeat(2049) })).toString(), "invalid_request"],
			[new URLSearchParams(request({ consent_denied: "1" })).toString(), "access_denied"],
			[new URLSearchParams(request({ reauth: "unknown" })).toString(), "login_required"],
		] as const) {
			const first = await authorize(sent);
			expect(`${first.at?.origin}${first.at?.pathname}`, sent).toBe("https://as.example/login");
			const back = new URL(first.at?.searchParams.get("redirect_to") ?? "");
			expect(pairs(back.search), sent).toEqual(pairs(sent));
			const again = await authorize(back.search.slice(1), cookie);
			expect([
				`${again.at?.origin}${again.at?.pathname}`,
				again.at?.searchParams.get("error"),
			]).toEqual([callback, error]);
		}
	});

	it("answers a silent request without a session at once, its prompt repeated too: its refusal, or login_required [rfc9700-4.11.2-b]", async () => {
		const { authorize } = await serve();
		const refused = await authorize(request({ prompt: "none", scope: "unknown" }));
		const silent = await authorize(request({ prompt: "none" }));
		const twice = await authorize(
			`${new URLSearchParams(request({ prompt: "none" }))}&prompt=none`,
		);
		expect(
			[refused, silent, twice].map((res) => [
				`${res.at?.origin}${res.at?.pathname}`,
				res.at?.searchParams.get("error"),
			]),
		).toEqual([
			[callback, "invalid_scope"],
			[callback, "login_required"],
			[callback, "invalid_request"],
		]);
	});

	it("answers a request at the endpoint by 400, sending nothing back, where its login URL would pass the limit set, on either way to log in [rfc9700-4.11.2-b]", async () => {
		const { authorize } = await serve({ authorize: { "login-url-limit": "2KiB" } });
		const long = { "x-a": "x".repeat(2048) };
		const said = async (extra: Record<string, string>) => {
			const res = await authorize(request({ ...long, ...extra }));
			return [res.status, res.location, JSON.parse(res.text).error];
		};
		expect(await said({ scope: "unknown" })).toEqual([400, "", "invalid_scope"]);
		expect(await said({})).toEqual([400, "", "invalid_request"]);
		const short = await authorize(request({ scope: "unknown" }));
		expect(short.at?.pathname).toBe("/login");
		// Padded to a login URL of the limit exactly, then one byte past it.
		const padded = (n: number) => authorize(request({ scope: "unknown", "x-a": "x".repeat(n) }));
		const pad = 2048 - ((await padded(1)).location.length - 1);
		const [at, past] = [await padded(pad), await padded(pad + 1)];
		expect([at.location.length, at.at?.pathname, past.status]).toEqual([2048, "/login", 400]);
	});

	it("answers a refusal at the endpoint by 400, sending nothing back, where its login URL would pass 8 KiB by default [rfc9700-4.11.2-b]", async () => {
		const { authorize } = await serve();
		const long = Object.fromEntries(["a", "b", "c"].map((name) => [`x-${name}`, "x".repeat(2048)]));
		const res = await authorize(request({ ...long, nonce: "n".repeat(2049) }));
		expect([res.status, res.location, JSON.parse(res.text)]).toEqual([
			400,
			"",
			{ error: "invalid_request", error_description: "parameter too long" },
		]);
	});
});

describe("the flow: the way to the login page", () => {
	it("sends a request without a session to the login page, with the way back from the public origin [rfc6749-3.1-a]", async () => {
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

	it("tells the login page the prompt=login and max_age the request asked, beside redirect_to, and nothing it did not ask", async () => {
		const { authorize, login } = await serve();
		const old = await login();
		advance(120_000);
		const both = await authorize(request({ prompt: "login", max_age: "60" }), old);
		expect([
			both.at?.pathname,
			both.at?.searchParams.get("prompt"),
			both.at?.searchParams.get("max_age"),
		]).toEqual(["/login", "login", "60"]);
		const aged = await authorize(request({ max_age: "60" }), old);
		expect([aged.at?.searchParams.get("prompt"), aged.at?.searchParams.get("max_age")]).toEqual([
			null,
			"60",
		]);
		const plain = await authorize(request());
		expect([plain.at?.searchParams.has("prompt"), plain.at?.searchParams.has("max_age")]).toEqual([
			false,
			false,
		]);
	});
});
