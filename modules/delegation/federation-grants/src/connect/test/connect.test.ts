import { createHash } from "node:crypto";
import { testRequest } from "@mod/http/testing";
import { Unavailable } from "@mod/kernel";
import { sessions } from "@mod/session";
import { type DelegatedExchange, UpstreamRefused } from "@mod/upstreams";
import { describe, expect, it } from "vitest";
import {
	type Answer,
	back,
	connector,
	origin,
	scopes,
	shortToUse,
	upstreamLogin,
	upstreamTokens,
} from "./harness.ts";

type Connector = Awaited<ReturnType<typeof connector>>;

const failed = (h: Connector) =>
	h.events
		.filter((e) => e.kind === "federation.grant.authorization_failed")
		.map((e) => e.attributes?.outcome);
const errorOf = (h: Connector, answer: Answer) => h.location(answer).searchParams.get("error");
const statusOf = (h: Connector, id: string) => (h.stores.peek(id) as { status?: string }).status;

describe("the link", () => {
	it("answers only a live intent's link: not another step, nor one replaced or past its time", async () => {
		const h = await connector();
		const flow = await h.started();
		expect((await h.step("connect", flow.browser, { request: flow.challenge })).status).toBe(400);
		const replaced = await h.lodge();
		await h.stores.grants.change(replaced.id, (record) => {
			const r = record as unknown as { intent: object };
			return { value: { ...r, intent: { ...r.intent, id: "another-intent" } } as never };
		});
		expect((await h.open(replaced.link, await h.login())).opened.status).toBe(400);
		// The intent ends by its own time on the kernel's clock, whatever the store keeps the link for.
		const late = await h.lodge({ endsAt: h.now() });
		expect((await h.open(late.link, await h.login())).opened.status).toBe(400);
	});

	it("refuses a short session with no step-up page, and audits each refusal to raise it", async () => {
		const h = await connector({ requirements: [shortToUse()] });
		const opened = await h.open((await h.lodge()).link, await h.login());
		expect(opened.opened).toMatchObject({ status: 403, text: "Sign in again to continue." });
		expect(failed(h)).toEqual(["reauthentication_required"]);
		const raising = await connector({
			settings: { "step-up-page": `${origin}/raise` },
			requirements: [shortToUse()],
		});
		const { link } = await raising.lodge();
		const alice = await raising.login();
		const first = (await raising.open(link, alice)).opened;
		expect(raising.location(first).searchParams.get("redirect_to")).toMatch("/connect?request=");
		expect(failed(raising)).toEqual([]);
		expect((await raising.open(link, alice)).opened.status).toBe(403);
		expect(failed(raising)).toEqual(["reauthentication_required"]);
		const untold = await connector({ requirements: [shortToUse({ every: true })] });
		await untold.open((await untold.lodge()).link, await untold.login());
		expect(failed(untold)).toEqual(["reauthentication_required"]);
	});

	it("gives the one step-up only to the request that marked it, and to the intent it was for", async () => {
		for (const raced of [
			{ stepped: { requirement: "mfa", at: 1_800_000_000_000 } },
			{ id: "another-intent", stepped: undefined },
		] as const) {
			const h = await connector({
				settings: { "step-up-page": `${origin}/raise` },
				requirements: [shortToUse()],
			});
			const { link } = await h.lodge();
			h.meanwhile({}, raced);
			const opened = await h.open(link, await h.login());
			expect(opened.opened.status, JSON.stringify(raced)).toBe(403);
		}
	});

	it("names the requirement to the step-up page, and gives each requirement and each later login a trip of its own", async () => {
		const asked = { requirement: "mfa" };
		const h = await connector({
			settings: { "step-up-page": `${origin}/raise` },
			requirements: [
				{
					name: "mfa",
					judges: ["use", "credentials"],
					admits: async (_context, level) =>
						level === "use" && asked.requirement === "mfa"
							? { kind: "short", answer: { error: "mfa_required" } }
							: { kind: "admit" },
				},
				{
					name: "email",
					judges: ["use", "credentials"],
					admits: async (_context, level) =>
						level === "use" && asked.requirement === "email"
							? { kind: "short", answer: { error: "email_unverified" } }
							: { kind: "admit" },
				},
			],
		});
		const { link } = await h.lodge();
		const alice = await h.login();
		const first = (await h.open(link, alice)).opened;
		expect(first.status).toBe(303);
		expect(h.location(first).searchParams.get("requirement")).toBe("mfa");
		// Back still short of the same requirement, in the same login: refused, not sent round again.
		expect((await h.open(link, alice)).opened.status).toBe(403);
		// Short of another requirement: a trip of its own.
		asked.requirement = "email";
		const other = (await h.open(link, alice)).opened;
		expect(h.location(other).searchParams.get("requirement")).toBe("email");
		expect((await h.open(link, alice)).opened.status).toBe(403);
		// A later login, short again: a trip again.
		h.advance(1000);
		const again = (await h.open(link, await h.login())).opened;
		expect(h.location(again).searchParams.get("requirement")).toBe("email");
	});

	it("reads an intent marked by an earlier version as a trip for no requirement", async () => {
		const h = await connector({
			settings: { "step-up-page": `${origin}/raise` },
			requirements: [shortToUse()],
		});
		const { link } = await h.lodge({ stepped: true } as never);
		const alice = await h.login();
		expect((await h.open(link, alice)).opened.status).toBe(303);
		expect((await h.open(link, alice)).opened.status).toBe(403);
	});

	it("tells a short session the link's client or connection is gone before it sends it to raise", async () => {
		const h = await connector({
			settings: { "step-up-page": `${origin}/raise` },
			requirements: [shortToUse()],
		});
		const { link } = await h.lodge();
		h.relist([], [back]);
		expect((await h.open(link, await h.login())).opened).toMatchObject({
			status: 403,
			text: "This connection is not available.",
		});
	});

	it("refuses a link the client may no longer use, or whose connection is gone", async () => {
		const h = await connector();
		const { link } = await h.lodge();
		h.relist([], [back]);
		expect((await h.open(link, await h.login())).opened).toMatchObject({
			status: 403,
			text: "This connection is not available.",
		});
		const before = await connector();
		const kept = await before.lodge();
		const after = await connector({
			stores: before.stores,
			settings: {
				connections: { mail: { idp: "corp", scopes, "max-access-token-lifetime": "1h" } },
			},
		});
		expect((await after.open(kept.link, await after.login())).opened.status).toBe(403);
	});

	it("binds the intent to the first browser even when another takes it meanwhile", async () => {
		for (const raced of [{ session: "another" }, { ended: "pushed_out" }]) {
			const h = await connector();
			const { link } = await h.lodge();
			h.meanwhile({}, raced);
			const opened = await h.open(link, await h.login());
			expect(opened.opened.status, JSON.stringify(raced)).toBe(400);
		}
	});
});

describe("the question and the decision", () => {
	it("shows only a question: no other step, no missing challenge, and its resource", async () => {
		const h = await connector({ resource: "https://api.example/" });
		const flow = await h.started();
		expect((await h.step("question", flow.browser, { challenge: flow.state })).status).toBe(400);
		expect((await h.step("question", flow.browser)).json).toEqual({
			error: "invalid_request",
			error_description: "challenge is required",
		});
		const alice = await h.login();
		const { challenge } = await h.open((await h.lodge()).link, alice);
		const shown = await h.step("question", alice, { challenge });
		expect(shown.json?.resource).toBe("https://api.example/");
	});

	it("refuses a decision without a challenge or with another word, and takes a question once", async () => {
		const h = await connector();
		const alice = await h.login();
		const { challenge } = await h.open((await h.lodge()).link, alice);
		expect((await h.step("decide", alice, { decision: "accept" })).json).toEqual({
			error: "invalid_request",
			error_description: "challenge is required",
		});
		expect((await h.step("decide", alice, { challenge, decision: "maybe" })).status).toBe(400);
		const both = await Promise.all([h.decide(challenge, alice), h.decide(challenge, alice)]);
		expect(both.map(({ answered }) => answered.status).sort()).toEqual([303, 400]);
		const other = await h.login();
		const second = await h.open((await h.lodge()).link, other);
		const denied = await Promise.all([
			h.decide(second.challenge, other, "deny"),
			h.decide(second.challenge, other, "deny"),
		]);
		expect(denied.map(({ answered }) => answered.status).sort()).toEqual([303, 400]);
	});

	it("refuses a question the client may no longer use, and sends a denial back only to a listed return", async () => {
		const h = await connector();
		const alice = await h.login();
		const { challenge } = await h.open((await h.lodge()).link, alice);
		h.relist([], []);
		expect(await h.step("question", alice, { challenge })).toMatchObject({
			status: 403,
			json: { error: "access_denied", error_description: "connection_not_permitted" },
		});
		h.relist(["cal"], []);
		const denied = await h.decide(challenge, alice, "deny");
		expect(denied.answered.status).toBe(400);
		expect(denied.answered.headers.location).toBeUndefined();
	});
});

describe("the callback", () => {
	it("hands the upstream the verifier of its challenge, its nonce, scopes and resource, and the issuer it said", async () => {
		const resource = "https://api.example/";
		const h = await connector({ resource });
		const seen: DelegatedExchange[] = [];
		h.script.exchange = async (x) => {
			seen.push(x);
			return upstreamLogin();
		};
		const flow = await h.started();
		await h.callback(flow.state, flow.browser, { code: ["c"], iss: ["https://up.example"] });
		const start = h.asked.starts[0];
		const [exchanged] = seen;
		expect(
			createHash("sha256")
				.update(exchanged?.verifier ?? "")
				.digest("base64url"),
		).toBe(start?.challenge);
		expect(exchanged?.verifier).not.toBe("");
		expect(exchanged?.nonce).toBe(start?.nonce);
		expect(exchanged).toMatchObject({ iss: "https://up.example", scopes, resource, code: "c" });
		expect(start?.resource).toBe(resource);
	});

	it("passes on a fault of the exchange that is no outage", async () => {
		const h = await connector();
		h.script.exchange = async () => {
			throw new TypeError("not now");
		};
		const flow = await h.started();
		await expect(h.callback(flow.state, flow.browser)).rejects.toThrow(TypeError);
	});

	it("audits a failure with the request's source", async () => {
		const h = await connector();
		h.script.startThrows = true;
		await h.started();
		const event = h.events.find((e) => e.kind === "federation.grant.authorization_failed");
		expect(event?.attributes?.source).toBe("127.0.0.1");
	});

	it("answers a callback to a connection name that is no name 404", async () => {
		const h = await connector();
		const flow = await h.started();
		const params = { state: flow.state, code: "c" };
		const path = "/session/federation-grants/callback/Cal";
		const named = await h.step("callback", flow.browser, params, path);
		expect(named).toMatchObject({ status: 404, text: "Not found." });
	});

	it("ends the intent when the IdP no longer offers its delegation at the callback", async () => {
		const h = await connector();
		const flow = await h.started();
		h.script.withdrawn = true;
		expect(errorOf(h, await h.callback(flow.state, flow.browser))).toBe("grant_not_authorizable");
	});

	it("asks the upstream nothing for another browser, and spends a state once even while it is used", async () => {
		const h = await connector();
		let exchanges = 0;
		let release: () => void = () => undefined;
		const held = new Promise<void>((resolve) => {
			release = resolve;
		});
		h.script.exchange = async () => {
			exchanges++;
			await held;
			return upstreamLogin();
		};
		const flow = await h.started();
		const other = await h.login();
		// Another browser carries no round trip: nothing is taken, nothing asked.
		expect((await h.callback(flow.state, other)).status).toBe(400);
		expect(exchanges).toBe(0);
		const second = await h.started();
		const using = h.callback(second.state, second.browser);
		const again = await h.callback(second.state, second.browser);
		release();
		expect(again.status).toBe(400);
		expect((await using).status).toBe(303);
		expect(exchanges).toBe(1);
	});

	it("clears the round trip's cookie on every answer after its take, unavailable and unreadable included", async () => {
		const h = await connector();
		const tripOf = (answer: Answer) =>
			(answer.cookies.find((c) => c.includes("federation-grants.cal=")) ?? "").split(";")[0] ?? "";
		const cleared = (answer: Answer) =>
			answer.cookies.some((c) => /^__Host-federation-grants\.cal=;.*Max-Age=0/.test(c));
		const done = await h.started();
		expect(cleared(await h.callback(done.state, done.browser))).toBe(true);
		const down = await h.started();
		h.stores.down.failNext("read");
		const unavailable = await h.callback(down.state, down.browser);
		expect([unavailable.status, cleared(unavailable)]).toEqual([503, true]);
		const odd = await h.started();
		const key = tripOf(odd.answered).split("=")[1] ?? "";
		await h.trips.change(key, (record) => ({
			value: { ...(record as object), carried: { unheard: 1 } } as never,
		}));
		const unread = await h.callback(odd.state, odd.browser);
		expect([unread.status, cleared(unread)]).toEqual([400, true]);
		// Spent, though unread: the browser's next callback finds nothing.
		expect(cleared(await h.callback(odd.state, odd.browser))).toBe(false);
	});

	it("audits a browser route the store cannot answer as a failed connection, unavailable, whatever the record does", async () => {
		const h = await connector();
		const failed = () => h.events.filter((e) => e.kind === "federation.grant.authorization_failed");
		const down = await h.started();
		h.stores.down.failNext("read");
		expect((await h.callback(down.state, down.browser)).status).toBe(503);
		expect(failed().map((e) => e.attributes?.outcome)).toEqual(["unavailable"]);
		// Recording is best effort: a record that throws leaves the answer a 503.
		const push = h.events.push;
		h.events.push = () => {
			throw new Error("record failed");
		};
		const again = await h.started();
		h.stores.down.failNext("read");
		expect((await h.callback(again.state, again.browser)).status).toBe(503);
		h.events.push = push;
		// Anything else that throws is not an outage, and is not audited as one.
		const broken = await h.started();
		h.script.exchange = async () => {
			throw new Error("broken");
		};
		await expect(h.callback(broken.state, broken.browser)).rejects.toThrow("broken");
		expect(failed()).toHaveLength(1);
	});

	it("keeps only the later of two round trips of one connection begun in one browser", async () => {
		const h = await connector();
		const first = await h.started();
		const second = await h.started({}, first.browser);
		expect((await h.callback(first.state, first.browser)).status).toBe(400);
		expect((await h.callback(second.state, second.browser)).status).toBe(303);
	});

	it("sets the round trip's cookie for the intent's time left in whole seconds, at least one", async () => {
		const h = await connector();
		const flow = await h.started({ endsAt: 1_800_000_000_000 + 1500 });
		const set = flow.answered.cookies.find((c) => c.includes("federation-grants.cal=")) ?? "";
		expect(set).toMatch(/Max-Age=2(;|$)/);
	});

	it("refuses an activation once the browser's session closed during the exchange", async () => {
		const h = await connector();
		const flow = await h.started();
		h.script.exchange = async () => {
			const closing = testRequest({ headers: new Map([["cookie", flow.browser]]) });
			await h.app.get(sessions).closeRequest(closing);
			return upstreamLogin();
		};
		expect(errorOf(h, await h.callback(flow.state, flow.browser))).toBe(
			"reauthentication_required",
		);
	});

	it("keeps a connection the pending list cannot drop: audited as authorized, and the browser sent back", async () => {
		const h = await connector();
		const flow = await h.started();
		h.stores.pending.remove = async () => {
			throw new Unavailable("pending");
		};
		const done = await h.callback(flow.state, flow.browser);
		expect([done.status, h.location(done).searchParams.get("grant_id"), errorOf(h, done)]).toEqual([
			303,
			flow.id,
			null,
		]);
		expect(statusOf(h, flow.id)).toBe("active");
		const authorized = h.events.filter((e) => e.kind === "federation.grant.authorized");
		expect(authorized.map((e) => e.subject)).toEqual(["alice"]);
		expect(failed(h)).toEqual([]);
		expect(h.logs()).toContainEqual(
			expect.objectContaining({
				event: "federation-grants.pending_remove_failed",
				fields: { kind: "Unavailable" },
			}),
		);
	});

	it("refuses an activation once the intent's time ran out during the exchange", async () => {
		const h = await connector();
		const flow = await h.started({ endsAt: h.now() + 1000 });
		h.script.exchange = async () => {
			h.advance(1000);
			return upstreamLogin();
		};
		expect(errorOf(h, await h.callback(flow.state, flow.browser))).toBe("grant_not_authorizable");
		expect(statusOf(h, flow.id)).toBe("pending");
	});

	it("activates only the intent it was for, and writes nothing over another", async () => {
		for (const raced of [
			{ ended: "pushed_out" },
			{ id: "another-intent" },
			{ id: "another-intent", ended: "connected" },
		]) {
			const h = await connector();
			const flow = await h.started();
			h.meanwhile({}, raced);
			const done = await h.callback(flow.state, flow.browser);
			expect(errorOf(h, done), JSON.stringify(raced)).toBe("grant_not_authorizable");
			expect(statusOf(h, flow.id)).toBe("pending");
		}
	});
});

/**
 * A first connection's callback: what the upstream answers the exchange with (over a bearer login of
 * `u-alice`), and the error the browser is sent back with; none for an activation.
 */
const callbackCases: readonly {
	readonly name: string;
	readonly settings?: Readonly<Record<string, unknown>>;
	/** Who holds which upstream account, or `down` when the users cannot say. */
	readonly holders?: Readonly<Record<string, string>>;
	/** The upstream account the client named. */
	readonly expectedUpstream?: string;
	readonly tokens?: Readonly<Record<string, unknown>>;
	/** The exchange throws the upstream being unavailable, or refusing. */
	readonly thrown?: "unavailable" | "refused" | "copied";
	/** The callback's query over the state and `code=code-1`. */
	readonly query?: Readonly<Record<string, readonly string[]>>;
	readonly error: string | null;
}[] = [
	{ name: "activates a bearer token with a refresh token", error: null },
	{
		name: "refuses a token of another type",
		tokens: { tokenType: "DPoP" },
		error: "upstream_token_ineligible",
	},
	{
		name: "refuses a token without a refresh token",
		tokens: { refreshToken: undefined },
		error: "refresh_token_absent",
	},
	{
		name: "refuses a token without a life",
		tokens: { expiresInSeconds: undefined },
		error: "upstream_token_ineligible",
	},
	{
		name: "refuses a token living past the longest",
		tokens: { expiresInSeconds: 7200 },
		error: "upstream_token_ineligible",
	},
	{
		name: "refuses a scope wider than shown",
		tokens: { scope: ["openid", "offline_access", "read", "write"] },
		error: "scope_exceeded",
	},
	{
		name: "refuses an upstream account another user holds",
		holders: { "u-alice": "mallory" },
		error: "identity_conflict",
	},
	{
		name: "goes no further when the users cannot say",
		holders: { "u-alice": "down" },
		error: "identity_unverifiable",
	},
	{
		name: "takes an upstream account the subject holds",
		holders: { "u-alice": "alice" },
		error: null,
	},
	{
		name: "asks the users nothing without an identity check",
		holders: { "u-alice": "down" },
		settings: { "identity-check": "none" },
		error: null,
	},
	{
		name: "refuses another upstream account than the client named",
		expectedUpstream: "u-other",
		error: "account_mismatch",
	},
	{
		name: "takes the upstream account the client named",
		expectedUpstream: "u-alice",
		error: null,
	},
	{
		name: "answers an unavailable upstream",
		thrown: "unavailable",
		error: "temporarily_unavailable",
	},
	{ name: "answers an upstream that refuses the code", thrown: "refused", error: "upstream_error" },
	{
		name: "answers an upstream refusal from another copy of upstreams as a refusal",
		thrown: "copied",
		error: "upstream_error",
	},
	{
		name: "answers the upstream's error",
		query: { error: ["access_denied"] },
		error: "access_denied",
	},
	{ name: "answers a callback without a code", query: { code: [] }, error: "upstream_error" },
	{ name: "answers a repeated parameter", query: { iss: ["a", "b"] }, error: "upstream_error" },
];

describe("a first connection's callback", () => {
	for (const c of callbackCases) {
		it(c.name, async () => {
			const h = await connector({ settings: c.settings ?? {}, holders: c.holders ?? {} });
			h.script.exchange = async () => {
				if (c.thrown === "copied") {
					// As another copy of upstreams in the bundle would throw it: another class, the same mark.
					throw Object.assign(new Error("upstream refused"), {
						[Symbol.for("@mod/upstreams.refused")]: true,
					});
				}
				if (c.thrown) throw c.thrown === "refused" ? new UpstreamRefused() : new Unavailable("up");
				return upstreamLogin(upstreamTokens(c.tokens ?? {}));
			};
			const flow = await h.started(
				c.expectedUpstream ? { expectedUpstream: c.expectedUpstream } : {},
			);
			const done = await h.callback(flow.state, flow.browser, c.query);
			expect(errorOf(h, done)).toBe(c.error);
			expect(statusOf(h, flow.id)).toBe(c.error ? "pending" : "active");
		});
	}
});
