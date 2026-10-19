import type { UpstreamRefresh, UpstreamTokens } from "@mod/upstreams";
import { describe, expect, it, vi } from "vitest";
import { harness, type Offered } from "./harness.ts";

type Said = Partial<Record<keyof UpstreamTokens, unknown>>;
const answer = (said: Said): UpstreamRefresh =>
	({
		kind: "refreshed",
		tokens: { accessToken: "up-2", tokenType: "Bearer", expiresInSeconds: 600, scope: [], ...said },
	}) as unknown as UpstreamRefresh;

/** What the module warned of, by event. */
const warned = (h: { logged(): readonly { event: string; fields?: unknown }[] }, event: string) =>
	h.logged().flatMap((l) => (l.event === `federation-tokens.${event}` ? [l.fields] : []));

/** A session linked to `corp` with what the login gave, refreshing as `refresh` answers. */
async function linked(
	given: Said,
	refresh: Offered["refresh"] = async () => answer({}),
	settings: Parameters<typeof harness>[0] = {},
) {
	const h = await harness({ ...settings, offered: { refresh } });
	const session = await h.login();
	const receipt = await h.receive(session, given as Partial<UpstreamTokens>);
	const { token } = await h.issue(session);
	return { ...h, session, token, receipt, get: () => h.ask(token) };
}

describe("when a token ends", () => {
	it("takes an end at login that is not a positive number as due, renewing it at the first request", async () => {
		for (const said of [0, -5, Number.NaN, "300"]) {
			const h = await linked({ refreshToken: "r-1", expiresInSeconds: said });
			expect((await h.get()).json).toMatchObject({ access_token: "up-2", expires_in: 600 });
		}
	});

	it("takes no end at login as none, or as due where a refresh token can renew it", async () => {
		const kept = await linked({});
		expect((await kept.get()).json).toEqual({
			access_token: "up-1",
			token_type: "Bearer",
			scope: "read",
		});
		const renewed = await linked({ refreshToken: "r-1" });
		expect((await renewed.get()).json).toMatchObject({ access_token: "up-2" });
	});

	it("caps an end at login, or a refresh's, at the longest lifetime", async () => {
		const settings = { settings: { "max-lifetime": "1h" } };
		const login = await linked({ expiresInSeconds: 1e12 }, undefined, settings);
		expect((await login.get()).json).toMatchObject({ expires_in: 3600 });
		for (const said of [1e12, undefined]) {
			const h = await linked(
				{ refreshToken: "r-1", expiresInSeconds: 0 },
				async () => answer({ expiresInSeconds: said }),
				settings,
			);
			expect((await h.get()).json).toMatchObject({ access_token: "up-2", expires_in: 3600 });
		}
	});

	it("refuses a refresh whose end is not a positive number, keeping the refresh token it rotated", async () => {
		for (const said of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, "600", null]) {
			const asked: string[] = [];
			const h = await linked({ refreshToken: "r-1", expiresInSeconds: 0 }, async (refreshToken) => {
				asked.push(refreshToken);
				return asked.length === 1
					? answer({ refreshToken: "r-2", expiresInSeconds: said })
					: answer({});
			});
			expect((await h.get()).json).toEqual({ error: "refresh_failed" });
			h.advance(30_000);
			expect((await h.get()).status).toBe(200);
			expect(asked).toEqual(["r-1", "r-2"]);
		}
	});

	it("renews a token with less than a second left, however little of its life is spent", async () => {
		const h = await linked({ refreshToken: "r-1", expiresInSeconds: 1 });
		h.advance(1);
		expect((await h.get()).json).toMatchObject({ access_token: "up-2" });
	});

	it("renews a refreshed token that said no end only once half the longest lifetime is spent", async () => {
		const answers = [answer({ expiresInSeconds: undefined }), answer({ accessToken: "up-3" })];
		const h = await linked(
			{ refreshToken: "r-1", expiresInSeconds: 0 },
			async () => answers.shift() ?? answer({}),
			{ settings: { "max-lifetime": "1m", "refresh-before": "1h" } },
		);
		expect((await h.get()).json).toMatchObject({ access_token: "up-2", expires_in: 60 });
		h.advance(29_999);
		expect((await h.get()).json).toMatchObject({ access_token: "up-2" });
		h.advance(1);
		expect((await h.get()).json).toMatchObject({ access_token: "up-3" });
	});

	it("refreshes again a token whose refreshed end comes near, and hands one less than a second from its end as unavailable", async () => {
		const h = await linked({ expiresInSeconds: 40 }, undefined, {
			settings: { "refresh-before": "0s" },
		});
		h.advance(39_500);
		expect((await h.get()).json).toEqual({ error: "temporarily_unavailable" });
	});
});

describe("the scope", () => {
	const granted = { refreshToken: "r-1", expiresInSeconds: 0, scope: ["read", "write"] };

	/** A session whose first refresh narrows its scope to `read`, the next answering `next`. */
	const narrowed = async (next: Said) => {
		const answers = [answer({ scope: ["read"], expiresInSeconds: 1 }), answer(next)];
		const h = await linked(granted, async () => answers.shift() ?? answer({}), {
			settings: { "refresh-before": "0s" },
		});
		expect((await h.get()).json).toMatchObject({ scope: "read" });
		h.advance(1000);
		return h;
	};

	it.each([
		["an empty scope", { scope: [] }],
		["no scope at all", { scope: undefined }],
	])(
		"narrows as the refresh answers, and comes back to the grant when the next says %s",
		async (_, next) => {
			const h = await narrowed(next);
			expect((await h.get()).json).toMatchObject({ scope: "read write" });
		},
	);

	it("keeps the scope it held for an answer wider than the grant, or unreadable", async () => {
		for (const scope of [["read", "admin"], [1], "read"]) {
			const h = await linked(granted, async () => answer({ scope }));
			expect((await h.get()).json).toMatchObject({ access_token: "up-2", scope: "read write" });
			const narrow = await narrowed({ scope });
			expect((await narrow.get()).json).toMatchObject({ access_token: "up-2", scope: "read" });
		}
	});
});

describe("what the upstream says, read once at the boundary", () => {
	it("keeps no login tokens with an unreadable part, and answers not linked", async () => {
		for (const said of [
			{ accessToken: "" },
			{ accessToken: 7 },
			{ refreshToken: 5 },
			{ idToken: {} },
			{ refreshToken: "" },
			{ idToken: "" },
			{ scope: "read" },
			{ scope: ["read", ""] },
		]) {
			const h = await linked(said);
			expect((await h.get()).status).toBe(404);
			expect(warned(h, "login_tokens_refused")).toEqual([{ idp: "corp" }]);
		}
	});

	it("removes the previous login's tokens when it refuses the next login's", async () => {
		const h = await linked({});
		await h.receive(h.session, { accessToken: "" });
		expect((await h.get()).status).toBe(404);
	});

	it("takes a token type that is not text, or only begins with Bearer, as no bearer", async () => {
		for (const tokenType of [1, ["Bearer"], { toString: () => "Bearer" }, "bearerx"]) {
			const h = await linked({ tokenType });
			expect((await h.get()).status).toBe(502);
		}
	});

	it("refuses a refresh without an access token or with another type, keeping the record and warning why", async () => {
		for (const [said, reason] of [
			[{ accessToken: undefined }, "no_access_token"],
			[{ accessToken: 3 }, "no_access_token"],
			[{ tokenType: "mac" }, "invalid_token_type"],
			[{ tokenType: "bearerx" }, "invalid_token_type"],
			[{ tokenType: ["Bearer"] }, "invalid_token_type"],
		] as const) {
			const h = await linked({ refreshToken: "r-1", expiresInSeconds: 0 }, async () =>
				answer(said),
			);
			expect((await h.get()).json).toEqual({ error: "refresh_failed" });
			expect(await h.stores.records.read(h.session.id)).toBeDefined();
			expect(warned(h, "refresh_failed")).toEqual([{ idp: "corp", reason }]);
		}
	});

	it("keeps the refresh token it held over a refresh that gives an empty one", async () => {
		const asked: string[] = [];
		const h = await linked({ refreshToken: "r-1", expiresInSeconds: 0 }, async (refreshToken) => {
			asked.push(refreshToken);
			return answer({ refreshToken: "", expiresInSeconds: 1 });
		});
		expect((await h.get()).json).toMatchObject({ access_token: "up-2" });
		h.advance(1000);
		expect((await h.get()).json).toMatchObject({ access_token: "up-2" });
		expect(asked).toEqual(["r-1", "r-1"]);
	});

	it("asks the upstream again after a failed refresh for another session, IdP or access token", async () => {
		const up: Offered = {
			refresh: async () => {
				asked++;
				throw new RangeError("down");
			},
		};
		let asked = 0;
		const h = await harness({ offered: up });
		const due = { refreshToken: "r-1", expiresInSeconds: 0 };
		const [mine, theirs] = [await h.login(), await h.login("bob")];
		for (const [session, idp] of [
			[mine, "corp"],
			[mine, "other"],
			[theirs, "corp"],
		] as const) {
			await h.receive(session, due, idp);
		}
		const [myToken, theirToken] = [(await h.issue(mine)).token, (await h.issue(theirs)).token];
		expect((await h.ask(myToken)).json).toEqual({ error: "refresh_failed" });
		expect((await h.ask(myToken, "other")).json).toEqual({ error: "refresh_not_supported" });
		expect((await h.ask(theirToken)).json).toEqual({ error: "refresh_failed" });
		await h.receive(mine, { ...due, accessToken: "up-new" });
		expect((await h.ask(myToken)).json).toEqual({ error: "refresh_failed" });
		expect(asked).toBe(3);
	});

	it("removes a record of another shape, or one that no longer opens, as not linked", async () => {
		const h = await linked({});
		const record = (await h.stores.records.read(h.session.id)) as unknown as {
			idps: Record<string, { version: string; sealed: string }>;
		};
		const broken = { ...record, idps: { corp: { ...record.idps.corp, sealed: "x" } } };
		await h.stores.records.update(h.session.id, () => ({
			value: broken as never,
			lifetimeMs: 60_000,
		}));
		expect((await h.get()).status).toBe(404);
		expect(await h.stores.records.read(h.session.id)).toEqual({ format: 1, idps: {} });
		expect(warned(h, "record_unreadable")).toEqual([{ idp: "corp" }]);
		await h.stores.records.update(h.session.id, () => ({
			value: { odd: true } as never,
			lifetimeMs: 60_000,
		}));
		expect((await h.get()).status).toBe(404);
	});
});

describe("a refresh racing other writers", () => {
	const due = { refreshToken: "r-1", expiresInSeconds: 0 };

	it("brings back no tokens an upstream logout removed while it ran", async () => {
		let during = async () => {};
		const h = await linked(due, async () => {
			await during();
			return answer({});
		});
		during = async () => {
			expect((await h.logout(h.token)).status).toBe(200);
		};
		expect((await h.get()).status).toBe(404);
		expect(await h.stores.records.read(h.session.id)).toMatchObject({ idps: {} });
	});

	it("writes nothing over tokens a new login linked while it ran", async () => {
		let during = async () => {};
		const h = await linked(due, async () => {
			await during();
			return answer({});
		});
		during = async () => {
			await h.receive(h.session, { accessToken: "up-new", expiresInSeconds: 600 });
		};
		expect((await h.get()).status).toBe(503);
		during = async () => {};
		expect((await h.get()).json).toMatchObject({ access_token: "up-new" });
	});

	it("refreshes once for requests that come together", async () => {
		let calls = 0;
		const h = await linked(due, async () => {
			calls++;
			await new Promise((resolve) => setTimeout(resolve, 150));
			return answer({});
		});
		const both = await Promise.all([h.get(), h.get()]);
		expect(both.map((b) => b.json?.access_token)).toEqual(["up-2", "up-2"]);
		expect(calls).toBe(1);
	});

	it("waits no longer than its lock lasts for another's refresh", async () => {
		const h = await linked(due, undefined, { settings: { "lock-lifetime": "1s" } });
		await h.stores.locks.hold(`${h.session.id}\ncorp`, "another", 60_000);
		const tries = vi.spyOn(h.stores.locks, "hold");
		const got = await h.get();
		expect([got.status, got.json]).toEqual([503, { error: "lock_timeout" }]);
		// Counted, not timed: one try every 100 ms over the lock's second, the first at once.
		expect(tries).toHaveBeenCalledTimes(11);
	});

	it("takes a token that stopped being a bearer while it waited for the lock as ineligible", async () => {
		const h = await linked(due);
		const lock = `${h.session.id}\ncorp`;
		await h.stores.locks.hold(lock, "another", 60_000);
		const got = h.get();
		// Let the request read the token and start waiting before the next login replaces it.
		await new Promise((resolve) => setTimeout(resolve, 50));
		await h.receive(h.session, { accessToken: "up-mac", tokenType: "mac" });
		await h.stores.locks.update(lock, (held) => ({ value: held, lifetimeMs: 1 }));
		expect((await got).status).toBe(502);
	});

	it("takes its lock under a mark of its own each time", async () => {
		const marks: string[] = [];
		const at: { h?: Awaited<ReturnType<typeof linked>> } = {};
		at.h = await linked(due, async () => {
			await at.h?.stores.locks.update(`${at.h.session.id}\ncorp`, (held) => {
				marks.push(held);
				return undefined;
			});
			return answer({ expiresInSeconds: 1 });
		});
		await at.h.get();
		at.h.advance(1000);
		await at.h.get();
		expect(marks).toHaveLength(2);
		expect(marks[0]).not.toBe(marks[1]);
	});

	it("lets go of its lock only while it still holds it, never one another host took after it ran out", async () => {
		const at: { h?: Awaited<ReturnType<typeof linked>> } = {};
		const lock = () => `${at.h?.session.id}\ncorp`;
		at.h = await linked(
			due,
			async () => {
				// The upstream answers late: the lock runs out, and another host takes it.
				at.h?.advance(1000);
				expect(await at.h?.stores.locks.hold(lock(), "another", 60_000)).toBe("created");
				return answer({});
			},
			{ settings: { "lock-lifetime": "1s" } },
		);
		expect((await at.h.get()).json).toMatchObject({ access_token: "up-2" });
		// Past the moment a lock let go would end: the other host's must still be held.
		at.h.advance(1000);
		expect(await at.h.stores.locks.hold(lock(), "third", 60_000)).toBe("exists");
	});
});

describe("as a receiver and a participant", () => {
	it("withdraws one IdP's tokens and keeps the others", async () => {
		const h = await linked({});
		await h.receive(h.session, { accessToken: "up-o" }, "other");
		await h.receivers[0]?.withdrawn(h.session.id, "corp", h.receipt);
		expect((await h.get()).status).toBe(404);
		expect((await h.ask(h.token, "other")).json).toMatchObject({ access_token: "up-o" });
	});

	it("withdraws, given its receipt, only what that login kept, and nothing written since", async () => {
		const h = await harness();
		const session = await h.login();
		const [keeper] = h.receivers;
		const tokens = (accessToken: string) => ({ accessToken, tokenType: "Bearer", scope: ["read"] });
		const first = await keeper?.received({ session, idp: "corp", tokens: tokens("up-1") });
		// Another login of the same IdP writes its own tokens in the meantime.
		const second = await keeper?.received({ session, idp: "corp", tokens: tokens("up-2") });
		expect(typeof first).toBe("string");
		expect(second).not.toBe(first);
		const { token } = await h.issue(session);
		await keeper?.withdrawn(session.id, "corp", first as string);
		expect((await h.ask(token)).json).toMatchObject({ access_token: "up-2" });
		await keeper?.withdrawn(session.id, "corp", second as string);
		expect((await h.ask(token)).status).toBe(404);
	});

	it("keeps nothing it answers a receipt of, where the login's tokens were not kept", async () => {
		const h = await harness();
		const session = await h.login();
		const [keeper] = h.receivers;
		const refused = { accessToken: "", tokenType: "Bearer", scope: ["read"] };
		expect(await keeper?.received({ session, idp: "corp", tokens: refused })).toBeUndefined();
	});

	it("withdraws nothing without a receipt, as its login kept nothing", async () => {
		const h = await linked({});
		await h.receivers[0]?.withdrawn(h.session.id, "corp", undefined);
		expect((await h.get()).json).toMatchObject({ access_token: "up-1" });
	});

	it("withdraws a closed session's tokens, whatever is left of it, and again harmlessly", async () => {
		const h = await linked({});
		h.stores.down.failNext("remove");
		expect((await h.close(h.session)).kind).toBe("pending");
		expect(await h.stores.records.read(h.session.id)).toBeDefined();
		await h.receivers[0]?.withdrawn(h.session.id, "corp", h.receipt);
		expect(await h.stores.records.read(h.session.id)).toBeUndefined();
		await h.receivers[0]?.withdrawn(h.session.id, "corp", h.receipt);
		expect(await h.stores.records.read(h.session.id)).toBeUndefined();
	});

	it("writes a login's tokens into the record another login created first, while it was writing its own", async () => {
		const h = await harness();
		const session = await h.login();
		h.stores.during.save = async () => {
			h.stores.during.save = async () => {};
			await h.receive(session, { accessToken: "up-o" }, "other");
		};
		await h.receive(session);
		const { token } = await h.issue(session);
		expect((await h.ask(token)).json).toMatchObject({ access_token: "up-1" });
		expect((await h.ask(token, "other")).json).toMatchObject({ access_token: "up-o" });
	});

	it("replaces a login's tokens with the next login's", async () => {
		const h = await linked({});
		await h.receive(h.session, { accessToken: "up-again" });
		expect((await h.get()).json).toMatchObject({ access_token: "up-again" });
	});
});

describe("how long a session's record lives", () => {
	it("keeps the record a login wrote until the session ends, never longer", async () => {
		const h = await linked({});
		h.advance(3_600_000 - 1);
		expect(await h.stores.records.read(h.session.id)).toBeDefined();
		h.advance(1);
		expect(await h.stores.records.read(h.session.id)).toBeUndefined();
	});

	it("keeps the record a refresh wrote until the session ends, never longer", async () => {
		const h = await linked({ refreshToken: "r-1", expiresInSeconds: 600 });
		h.advance(1_800_000);
		expect((await h.get()).json).toMatchObject({ access_token: "up-2" });
		h.advance(1_800_000 - 1);
		expect(await h.stores.records.read(h.session.id)).toBeDefined();
		h.advance(1);
		expect(await h.stores.records.read(h.session.id)).toBeUndefined();
	});

	it("writes no tokens for a session that lets nobody in, even one whose record is still kept", async () => {
		const h = await linked({});
		h.stores.down.failNext("remove");
		expect((await h.close(h.session)).kind).toBe("pending");
		const written = h.stores.given.length;
		await h.receive(h.session, { accessToken: "up-late" });
		expect(h.stores.given).toHaveLength(written);
		const closed = await h.login("bob");
		await h.close(closed);
		await h.receive(closed);
		expect(await h.stores.records.read(closed.id)).toBeUndefined();
	});

	it("writes no tokens for a session short of a requirement, as for one that lets nobody in", async () => {
		const h = await harness();
		const session = await h.login();
		h.shorten("alice");
		await h.receive(session);
		expect(h.stores.given).toEqual([]);
		expect(await h.stores.records.read(session.id)).toBeUndefined();
		expect(warned(h, "login_tokens_not_kept")).toEqual([{ idp: "corp" }]);
	});

	it("keeps no tokens for a session that closes while they are written", async () => {
		const h = await harness();
		const session = await h.login();
		h.stores.during.save = async () => {
			h.stores.during.save = async () => {};
			await h.close(session);
		};
		await h.receive(session);
		expect(await h.stores.records.read(session.id)).toBeUndefined();
		expect(warned(h, "login_tokens_not_kept")).toEqual([{ idp: "corp" }]);
	});
});
