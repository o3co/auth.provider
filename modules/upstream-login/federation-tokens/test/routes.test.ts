import { Unavailable } from "@mod/kernel";
import { type Entry, sessions } from "@mod/session";
import type { UpstreamRefresh } from "@mod/upstreams";
import { describe, expect, it, vi } from "vitest";
import { back, harness, named, type Offered, unreadable } from "./harness.ts";

const refreshed = (more: Record<string, unknown> = {}): UpstreamRefresh =>
	({
		kind: "refreshed",
		tokens: { accessToken: "up-2", tokenType: "Bearer", expiresInSeconds: 600, scope: [], ...more },
	}) as UpstreamRefresh;

/** An upstream whose refreshes answer in turn as given, keeping what each was asked. */
function refreshing(...answers: (UpstreamRefresh | Error)[]) {
	const asked: { refreshToken: string; scope: readonly string[] }[] = [];
	const offered: Offered = {
		refresh: async (refreshToken, scope) => {
			asked.push({ refreshToken, scope });
			const next = answers.shift() ?? refreshed();
			if (next instanceof Error) throw next;
			return next;
		},
	};
	return { offered, asked };
}

/** A harness with a session linked to `corp`, and a receiver's token issued in it. */
async function linked(
	options: Parameters<typeof harness>[0] = {},
	given: Parameters<Awaited<ReturnType<typeof harness>>["receive"]>[1] = {},
) {
	const h = await harness(options);
	const session = await h.login();
	await h.receive(session, given);
	const { token } = await h.issue(session);
	return { ...h, session, token };
}

describe("the token route", () => {
	it("takes requests from other sites as a client's own call, which reads no cookie, and limits them per source", async () => {
		const h = await harness();
		const route = h.routes.find((r) => r.path === "/oauth/federation/*");
		expect(route?.crossSite).toBe(
			"A client's own call, authenticated as that client; it reads no cookie.",
		);
		expect(route?.uses?.map((u) => u.policy.label)).toEqual(["rate-limit.requests-per-source"]);
	});

	it("hands a receiver the upstream access token of its session, never kept", async () => {
		const h = await linked({}, { expiresInSeconds: 300 });
		const got = await h.ask(h.token);
		expect([got.status, got.json]).toEqual([
			200,
			{ access_token: "up-1", token_type: "Bearer", expires_in: 300, scope: "read" },
		]);
		expect(got.headers["cache-control"]).toBe("no-store");
		expect(h.events.map((e) => [e.kind, e.subject, e.attributes])).toEqual([
			[
				"federation.token.succeeded",
				"alice",
				{ idp: "corp", client: "app", refreshed: "false", source: "127.0.0.1" },
			],
		]);
	});

	it("says no end and no scope where the upstream gave none", async () => {
		const h = await linked({}, { scope: [] });
		expect((await h.ask(h.token)).json).toEqual({ access_token: "up-1", token_type: "Bearer" });
	});

	it("refreshes a token near its end with the scope the login gave, and hands the new one", async () => {
		const up = refreshing(refreshed({ refreshToken: "r-2", scope: ["read"] }));
		const h = await linked(
			{ offered: up.offered },
			{ refreshToken: "r-1", expiresInSeconds: 20, scope: ["read", "write"] },
		);
		// A life shorter than refresh-before is renewed only once half spent.
		h.advance(9_000);
		expect((await h.ask(h.token)).json).toMatchObject({ access_token: "up-1", expires_in: 11 });
		h.advance(1_000);
		const got = await h.ask(h.token);
		expect([got.status, got.json]).toEqual([
			200,
			{ access_token: "up-2", token_type: "Bearer", expires_in: 600, scope: "read" },
		]);
		expect(up.asked).toEqual([{ refreshToken: "r-1", scope: ["read", "write"] }]);
		expect(h.events.map((e) => e.attributes?.refreshed)).toEqual(["false", "true"]);
		h.advance(590_000);
		await h.ask(h.token);
		expect(up.asked[1]).toEqual({ refreshToken: "r-2", scope: ["read", "write"] });
	});

	it.each([
		["closed", "absent"],
		["short of a requirement", "short"],
		["open for another subject", "bob"],
	] as const)(
		"refuses the refreshed token when the session is %s once the upstream's tokens are written [rfc6750-3-a] [rfc6750-3-b] [rfc6750-3-c] [rfc6750-3-f]",
		async (_, now) => {
			const at: { h?: Awaited<ReturnType<typeof linked>> } = {};
			const offered: Offered = {
				refresh: async () => {
					const { app, session, stores } = at.h as Awaited<ReturnType<typeof linked>>;
					const open = app.get(sessions);
					const real = open.entryOf.bind(open);
					const written = stores.given.length;
					const told: Entry =
						now === "absent"
							? { kind: "absent" }
							: now === "short"
								? { kind: "short", requirement: "test-short", answer: { error: "test_short" } }
								: {
										kind: "entered",
										session: { ...session, context: { ...session.context, subject: now } },
										endsAt: Number.MAX_SAFE_INTEGER,
									};
					// Only once the refreshed tokens are written, so the write itself still finds the session.
					vi.spyOn(open, "entryOf").mockImplementation(async (handle, level) =>
						stores.given.length > written ? told : real(handle, level),
					);
					return refreshed();
				},
			};
			at.h = await linked({ offered }, { refreshToken: "r-1", expiresInSeconds: 0 });
			const got = await at.h.ask(at.h.token);
			expect([got.status, got.json, got.headers["www-authenticate"]]).toEqual([
				401,
				{ error: "invalid_token" },
				'Bearer error="invalid_token"',
			]);
			expect(at.h.events).toEqual([]);
		},
	);

	it("refuses a request without a token, or with one not accepted", async () => {
		const h = await linked();
		expect((await h.ask(undefined)).status).toBe(401);
		expect(await h.ask("not-a-token")).toMatchObject({
			status: 401,
			json: { error: "invalid_token" },
		});
	});

	it("refuses a token of an ended family, for another audience, or whose session is open for another subject [rfc6750-3-a] [rfc6750-3-b] [rfc6750-3-c] [rfc6750-3-f] [rfc6750-3.1-b] [rfc9700-2.3-c]", async () => {
		const h = await linked();
		const ended = await h.issue(h.session, "app", { family: "ended" });
		const aside = await h.issue(h.session, "app", { audience: ["api"] });
		const stranger = await h.issue(h.session, "app", { subject: "bob" });
		// At an IdP the session is not linked to as well: refused before anything is looked up.
		for (const token of [ended.token, aside.token, stranger.token]) {
			for (const idp of ["corp", "other"]) {
				const got = await h.ask(token, idp);
				expect([got.status, got.json, got.headers["www-authenticate"]]).toEqual([
					401,
					{ error: "invalid_token" },
					'Bearer error="invalid_token"',
				]);
			}
		}
	});

	it("challenges a refused DPoP-bound token in its own scheme [rfc9449-7.1-c] [rfc9449-7.2-c]", async () => {
		const h = await linked();
		const ended = await h.issue(h.session, "app", { family: "ended", dpop: true });
		const got = await h.call("token", ended.token, { scheme: "DPoP" });
		expect([got.status, got.headers["www-authenticate"]]).toEqual([
			401,
			'DPoP error="invalid_token"',
		]);
	});

	it("refuses a token once its session closed, and forgets the session's upstream tokens", async () => {
		const h = await linked();
		await h.close(h.session);
		expect((await h.ask(h.token)).status).toBe(401);
		expect(await h.stores.records.read(h.session.id)).toBeUndefined();
	});

	it("refuses a token whose session is short of a requirement as one closed, keeping the session's upstream tokens [rfc6750-3-a] [rfc6750-3-b] [rfc6750-3-c] [rfc6750-3-f]", async () => {
		const h = await linked();
		h.shorten("alice");
		for (const idp of ["corp", "other"]) {
			const got = await h.ask(h.token, idp);
			expect([got.status, got.json, got.headers["www-authenticate"]]).toEqual([
				401,
				{ error: "invalid_token" },
				'Bearer error="invalid_token"',
			]);
		}
		expect(h.events).toEqual([]);
		expect(await h.stores.records.read(h.session.id)).toBeDefined();
	});

	it("refuses a client the operator did not make a receiver, even one whose own metadata says it receives", async () => {
		const h = await linked();
		for (const client of ["plain", named]) {
			const { token } = await h.issue(h.session, client);
			expect(await h.ask(token)).toMatchObject({ status: 403, json: { error: "forbidden" } });
		}
		expect(h.events.map((e) => [e.kind, e.attributes?.reason])).toEqual([
			["federation.token.failed", "forbidden"],
			["federation.token.failed", "forbidden"],
		]);
	});

	it("answers not linked for an IdP the session has no tokens from, and for unknown paths not found", async () => {
		const h = await linked();
		expect(await h.ask(h.token, "other")).toMatchObject({
			status: 404,
			json: { error: "federation_not_linked" },
		});
		const other = await h.login("bob");
		const bobs = await h.issue(other);
		expect((await h.ask(bobs.token)).status).toBe(404);
		expect((await h.ask(h.token, "corp/token")).status).toBe(404);
		expect(await h.call("foo", h.token)).toMatchObject({
			status: 404,
			json: { error: "not_found" },
		});
		expect(h.events).toEqual([]);
	});

	it("hands no token that is not a bearer, keeping the record", async () => {
		const h = await linked({}, { tokenType: "mac" });
		for (const _ of [1, 2]) {
			const got = await h.ask(h.token);
			expect([got.status, got.json, got.headers["retry-after"]]).toEqual([
				502,
				{ error: "upstream_token_ineligible" },
				"300",
			]);
		}
		const lower = await linked({}, { tokenType: "bearer" });
		expect((await lower.ask(lower.token)).status).toBe(200);
	});

	it("removes the tokens when the upstream refuses the refresh token, and says so once", async () => {
		const up = refreshing({ kind: "invalid_grant" });
		const h = await linked({ offered: up.offered }, { refreshToken: "r-1", expiresInSeconds: 0 });
		expect(await h.ask(h.token)).toMatchObject({
			status: 410,
			json: { error: "re_authentication_required" },
		});
		expect((await h.ask(h.token)).status).toBe(404);
	});

	it("removes the tokens when the upstream asks the user to act there first, and says so once", async () => {
		const up = refreshing({ kind: "interaction_required" });
		const h = await linked({ offered: up.offered }, { refreshToken: "r-1", expiresInSeconds: 0 });
		expect(await h.ask(h.token)).toMatchObject({
			status: 403,
			json: { error: "upstream_interaction_required" },
		});
		expect(h.events.map((e) => [e.kind, e.attributes?.reason])).toContainEqual([
			"federation.token.failed",
			"interaction_required",
		]);
		expect((await h.ask(h.token)).status).toBe(404);
	});

	it("keeps the tokens while the upstream is down or limits, and hands them once it answers", async () => {
		const up = refreshing(new Unavailable("upstream"), {
			kind: "limited",
			retryAfterSeconds: 7,
		});
		const h = await linked({ offered: up.offered }, { refreshToken: "r-1", expiresInSeconds: 0 });
		expect(await h.ask(h.token)).toMatchObject({
			status: 503,
			json: { error: "temporarily_unavailable" },
		});
		expect(h.events).toEqual([]);
		const limited = await h.ask(h.token);
		expect([limited.status, limited.json, limited.headers["retry-after"]]).toEqual([
			429,
			{ error: "rate_limited" },
			"7",
		]);
		expect((await h.ask(h.token)).json).toMatchObject({ access_token: "up-2" });
	});

	it("passes on how long to wait only in whole seconds from one to a day", async () => {
		const limited = (retryAfterSeconds: number): UpstreamRefresh => ({
			kind: "limited",
			retryAfterSeconds,
		});
		const told = [0, 1, 86_400, 86_401, 1.5];
		const up = refreshing(...told.map(limited));
		const h = await linked({ offered: up.offered }, { refreshToken: "r-1", expiresInSeconds: 0 });
		const said: (string | undefined)[] = [];
		for (const _ of told) {
			const got = await h.ask(h.token);
			expect(got.status).toBe(429);
			said.push(got.headers["retry-after"]);
		}
		expect(said).toEqual([undefined, "1", "86400", undefined, undefined]);
	});

	it("refuses to refresh without a refresh token, or for an upstream that offers none, recording why", async () => {
		const absent = await linked({ offered: refreshing().offered }, { expiresInSeconds: 0 });
		expect((await absent.ask(absent.token)).json).toEqual({ error: "refresh_token_absent" });
		// An upstream that offers no refresh, or an IdP the settings no longer hold, never will: log in again.
		const none = await linked({}, { refreshToken: "r-1", expiresInSeconds: 0 });
		expect(await none.ask(none.token)).toMatchObject({
			status: 410,
			json: { error: "refresh_not_supported" },
		});
		expect(none.events.map((e) => [e.kind, e.attributes?.reason])).toContainEqual([
			"federation.token.failed",
			"not_supported",
		]);
	});

	it("answers a failed refresh the same, without asking the upstream, for a while", async () => {
		const up = refreshing(new RangeError("up-1 r-1 went wrong"), refreshed());
		const h = await linked({ offered: up.offered }, { refreshToken: "r-1", expiresInSeconds: 0 });
		for (const _ of [1, 2]) {
			expect(await h.ask(h.token)).toMatchObject({
				status: 500,
				json: { error: "refresh_failed" },
			});
		}
		expect(up.asked).toHaveLength(1);
		h.advance(30_000);
		expect((await h.ask(h.token)).status).toBe(200);
		expect(JSON.stringify(h.events)).not.toMatch(/went wrong|up-1|r-1/);
	});

	it("answers unavailable when its store cannot tell", async () => {
		const h = await linked();
		h.stores.down.failNext("read");
		expect(await h.ask(h.token)).toMatchObject({
			status: 503,
			json: { error: "temporarily_unavailable" },
		});
	});

	it("gives its store only sealed tokens", async () => {
		const h = await linked({}, { refreshToken: "r-secret", idToken: "id-secret" });
		expect(h.stores.given.length).toBeGreaterThan(0);
		expect(JSON.stringify(h.stores.given)).not.toMatch(/up-1|r-secret|id-secret|read/);
	});
});

describe("the upstream logout route", () => {
	const ending: Offered = {
		endSession: (at) => {
			const url = new URL("https://idp.example/logout");
			for (const [key, value] of Object.entries(at)) url.searchParams.set(key, String(value));
			return url.href;
		},
	};

	it("forgets the IdP's tokens first, then sends the browser to the upstream with its hint", async () => {
		const h = await linked({ offered: ending }, { idToken: "id-1" });
		const out = await h.logout(h.token, { post_logout_redirect_uri: back, state: "s1" });
		expect([out.status, out.headers["cache-control"]]).toEqual([303, "no-store"]);
		expect(Object.fromEntries(new URL(String(out.headers.location)).searchParams)).toEqual({
			idTokenHint: "id-1",
			postLogoutRedirectUri: back,
			state: "s1",
		});
		expect(h.events.map((e) => [e.kind, e.attributes])).toEqual([
			[
				"federation.logout.succeeded",
				{ idp: "corp", client: "app", redirected: "true", source: "127.0.0.1" },
			],
		]);
		expect((await h.ask(h.token)).status).toBe(404);
	});

	it("still sends the login's hint after a refresh that gave no ID token, or an empty one", async () => {
		for (const answered of [refreshed(), refreshed({ idToken: "" })]) {
			const offered: Offered = { ...refreshing(answered).offered, ...ending };
			const due = { idToken: "id-1", refreshToken: "r-1", expiresInSeconds: 0 };
			const h = await linked({ offered }, due);
			expect((await h.ask(h.token)).json).toMatchObject({ access_token: "up-2" });
			const out = await h.logout(h.token);
			expect(new URL(String(out.headers.location)).searchParams.get("idTokenHint")).toBe("id-1");
		}
	});

	it("drops a return the client did not register, even one that begins with a registered one", async () => {
		for (const asked of ["https://evil.example/", `${back}/elsewhere`, `${back}.evil.example`]) {
			const h = await linked({ offered: ending });
			const out = await h.logout(h.token, { post_logout_redirect_uri: asked });
			expect(new URL(String(out.headers.location)).searchParams.has("postLogoutRedirectUri")).toBe(
				false,
			);
		}
	});

	it("drops the return quietly when the client cannot be read, and still logs out", async () => {
		const h = await linked({ offered: ending }, { idToken: "id-1" });
		const { token } = await h.issue(h.session, unreadable);
		const out = await h.logout(token, { post_logout_redirect_uri: back });
		expect(out.status).toBe(303);
		expect(Object.fromEntries(new URL(String(out.headers.location)).searchParams)).toEqual({
			idTokenHint: "id-1",
		});
		expect((await h.ask(h.token)).status).toBe(404);
	});

	it("answers disconnected where the upstream has no end of session, or it fails", async () => {
		const failing: Offered = {
			endSession: () => {
				throw new RangeError("no");
			},
		};
		for (const offered of [{}, failing]) {
			const h = await linked({ offered });
			expect(await h.logout(h.token)).toMatchObject({ status: 200, json: { disconnected: true } });
			expect(h.events.map((e) => [e.kind, e.attributes?.redirected])).toEqual([
				["federation.logout.succeeded", "false"],
			]);
			expect((await h.ask(h.token)).status).toBe(404);
			const warned = h.logged().filter((l) => l.event === "federation-tokens.end_session_failed");
			expect(warned.map((l) => l.fields)).toEqual(
				offered === failing ? [{ idp: "corp", kind: "RangeError" }] : [],
			);
		}
	});

	it("answers not linked for an IdP the session has no tokens from, and keeps the others", async () => {
		const h = await linked();
		expect(await h.logout(h.token, {}, "other")).toMatchObject({
			status: 404,
			json: { error: "federation_not_linked" },
		});
		expect((await h.ask(h.token)).status).toBe(200);
	});
});
