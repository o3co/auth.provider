import { keys } from "@mod/keys";
import { DestinationRefused } from "@mod/outbound";
import { sessions } from "@mod/session";
import { expect, it } from "vitest";
import { issuer, keptNotices, servedEach, settled, until } from "./harness.ts";

const serve = servedEach();

it("posts each client of a closing session a logout token, however the session closes [oidc-bcl-2.4-a] [oidc-bcl-2.4-b] [oidc-bcl-2.4-c] [oidc-bcl-2.4-d] [oidc-bcl-2.4-e] [oidc-bcl-2.4-f] [oidc-bcl-2.4-g] [oidc-bcl-2.4-h] [oidc-bcl-2.4-i] [oidc-bcl-2.4-j] [oidc-bcl-2.4-k] [oidc-bcl-2.4-m]", async () => {
	const h = await serve();
	const { session } = await h.login();
	await h.redeemed(session.id, "app");
	await h.app.get(sessions).close(session.id);
	await until(() => h.sent.length > 0);
	expect(h.sent.map((s) => [s.url, s.request?.method])).toEqual([
		["https://app.example/bc", "POST"],
	]);
	const request = h.sent[0]?.request;
	expect(request?.headers).toEqual({ "content-type": "application/x-www-form-urlencoded" });
	const token = new URLSearchParams(String(request?.body)).get("logout_token") ?? "";
	const verified = await h.app.get(keys).verify(token, "logout+jwt");
	if (verified.kind !== "valid") throw new Error(verified.reason);
	const { iat, exp, jti, ...claims } = verified.claims;
	expect(claims).toEqual({
		iss: issuer,
		sub: "alice",
		aud: "app",
		sid: session.id,
		events: { "http://schemas.openid.net/event/backchannel-logout": {} },
	});
	expect([typeof jti, Number(exp) - Number(iat)]).toEqual(["string", 300]);
	await settled(h, 500);
	expect(await keptNotices(h)).toEqual([]);
});

it("leaves out the session for a client that did not ask for it, and tells no client without a URL", async () => {
	const h = await serve({
		sections: {
			app: {
				"backchannel-logout-uri": "https://app.example/bc",
				"backchannel-logout-session-required": false,
			},
			quiet: {},
		},
	});
	const { session } = await h.login();
	await h.redeemed(session.id, "app");
	await h.redeemed(session.id, "quiet");
	await h.app.get(sessions).close(session.id);
	await until(() => h.sent.length > 0);
	const token = new URLSearchParams(String(h.sent[0]?.request?.body)).get("logout_token") ?? "";
	const verified = await h.app.get(keys).verify(token, "logout+jwt");
	expect(verified.kind === "valid" && "sid" in verified.claims).toBe(false);
	expect(h.sent).toHaveLength(1);
});

it("keeps a notice the client could not take yet, and the sweep delivers it, a sweep's interval between tries [oidc-bcl-2.5-a]", async () => {
	const h = await serve();
	const answers = [503, 429, 408];
	const triedAt: number[] = [];
	h.answering.answer = async () => {
		triedAt.push(Date.now());
		return answers.shift() ?? 200;
	};
	const { session } = await h.login();
	await h.redeemed(session.id, "app");
	await h.app.get(sessions).close(session.id);
	await until(() => h.sent.length > 0);
	expect(await keptNotices(h)).toHaveLength(1);
	await until(() => h.sent.length >= 4, 6000);
	await settled(h);
	expect([h.sent.length, await keptNotices(h)]).toEqual([4, []]);
	// Each try again waits for a sweep, a second here, never sent at once after the one that failed.
	const gaps = triedAt.slice(1).map((at, i) => at - (triedAt[i] as number));
	expect(
		gaps.every((gap) => gap >= 900),
		JSON.stringify(gaps),
	).toBe(true);
	expect(h.logs().filter((l) => l.event === "rp-logout.notices_kept")).toContainEqual(
		expect.objectContaining({ level: "warn", fields: { count: 1 } }),
	);
}, 10_000);

it.each([
	["the client refuses it", async () => 400],
	[
		"the destination policy refuses it",
		async (): Promise<number> => {
			throw new DestinationRefused("redirect");
		},
	],
	[
		"a second bundled copy of the destination policy refuses it",
		async (): Promise<number> => {
			throw Object.assign(new Error("outbound destination refused: redirect"), {
				[Symbol.for("@mod/outbound-policy.destination-refused")]: true,
				reason: "redirect",
			});
		},
	],
])("settles a notice once %s [oidc-bcl-2.5-b]", async (_name, answer) => {
	const h = await serve();
	h.answering.answer = answer;
	const { session } = await h.login();
	await h.redeemed(session.id, "app");
	await h.app.get(sessions).close(session.id);
	await until(() => h.sent.length > 0);
	await settled(h, 500);
	expect([h.sent.length, await keptNotices(h)]).toEqual([1, []]);
});

it("posts to a back channel with a query as registered, adding nothing to it [oidc-bcl-2.2-b]", async () => {
	const h = await serve({
		sections: { app: { "backchannel-logout-uri": "https://app.example/bc?tenant=a&x=1" } },
	});
	const { session } = await h.login();
	await h.redeemed(session.id, "app");
	await h.app.get(sessions).close(session.id);
	await until(() => h.sent.length > 0);
	expect(h.sent.map((s) => s.url)).toEqual(["https://app.example/bc?tenant=a&x=1"]);
	expect([...new URLSearchParams(String(h.sent[0]?.request?.body)).keys()]).toEqual([
		"logout_token",
	]);
	await settled(h, 500);
});

it("gives up a notice past its time, without sending it again", async () => {
	const h = await serve({ settings: { "notify-within": "1m" } });
	h.answering.answer = async () => 503;
	const { session } = await h.login();
	await h.redeemed(session.id, "app");
	await h.app.get(sessions).close(session.id);
	await until(() => h.sent.length > 0);
	h.advance(61_000);
	await settled(h);
	expect([h.sent.length, await keptNotices(h)]).toEqual([1, []]);
});

it("keeps the clients a session redeemed codes for, and nothing for one it never closes", async () => {
	const h = await serve();
	const { session } = await h.login();
	await h.redeemed(session.id, "app");
	await h.redeemed(session.id, "app");
	expect((await h.stores.clients.members(session.id)).map((m) => m.member)).toEqual(["app"]);
	await new Promise((resolve) => setTimeout(resolve, 1300));
	expect(h.sent).toEqual([]);
});

it("delivers a notice a newer host wrote with fields this one does not know", async () => {
	const h = await serve();
	const notice = { client: "app", session: "s-1", subject: "alice", until: 9e15, added: "x" };
	await h.stores.notices.add(JSON.stringify(notice));
	await until(() => h.sent.length > 0, 4000);
	await settled(h);
	expect([h.sent.length, await keptNotices(h)]).toEqual([1, []]);
});

it("sends a notice tried again with the same token id, so the client can tell a repeat", async () => {
	const h = await serve();
	const answers = [503];
	h.answering.answer = async () => answers.shift() ?? 200;
	const { session } = await h.login();
	await h.redeemed(session.id, "app");
	await h.app.get(sessions).close(session.id);
	await until(() => h.sent.length >= 2, 6000);
	const ids = await Promise.all(
		h.sent.map(async (s) => {
			const token = new URLSearchParams(String(s.request?.body)).get("logout_token") ?? "";
			const verified = await h.app.get(keys).verify(token, "logout+jwt");
			return verified.kind === "valid" ? verified.claims.jti : undefined;
		}),
	);
	expect(ids[0]).toBeTypeOf("string");
	expect(ids[1]).toBe(ids[0]);
}, 10_000);

it("remembers a session's clients until the session ends, however short remember-for is", async () => {
	const h = await serve({ settings: { "remember-for": "1m" } });
	const { session } = await h.login();
	await h.redeemed(session.id, "app");
	h.advance(61_000);
	await h.app.get(sessions).close(session.id);
	await until(() => h.sent.length > 0);
	expect(h.sent.map((s) => s.url)).toEqual(["https://app.example/bc"]);
});

it("remembers a client for remember-for where the session's end is unknown, and no longer", async () => {
	const h = await serve({ settings: { "remember-for": "2h" } });
	await h.redeemed("unknown", "app");
	h.advance(7_199_000);
	expect(await h.stores.clients.members("unknown")).toHaveLength(1);
	h.advance(2000);
	expect(await h.stores.clients.members("unknown")).toEqual([]);
});

it("logs the clients the store pushes out of a session's set", async () => {
	const h = await serve();
	const { session } = await h.login();
	for (const client of ["a", "b", "c", "d"]) await h.redeemed(session.id, client);
	expect(h.logs().filter((l) => l.event === "rp-logout.clients_pushed_out")).toEqual([]);
	await h.redeemed(session.id, "e");
	expect(h.logs().filter((l) => l.event === "rp-logout.clients_pushed_out")).toEqual([
		expect.objectContaining({ level: "warn", fields: { count: 1 } }),
	]);
});

it("settles a notice the client takes with any 2xx, as taken [oidc-bcl-2.5-b]", async () => {
	const h = await serve();
	h.answering.answer = async () => 204;
	const { session } = await h.login();
	await h.redeemed(session.id, "app");
	await h.app.get(sessions).close(session.id);
	await until(() => h.sent.length > 0);
	await settled(h, 500);
	expect([h.sent.length, await keptNotices(h)]).toEqual([1, []]);
	expect(h.logs().filter((l) => l.event === "rp-logout.backchannel_rejected")).toEqual([]);
});
