import { takesUnused } from "@mod/kernel/testing";
import { afterEach, describe, expect, it } from "vitest";
import { harness, type Offered } from "./harness.ts";

type Harness = Awaited<ReturnType<typeof harness>>;

let stop = async () => {};
afterEach(() => stop());

/** A linked session's token route served over http, with the section given. */
async function served(settings: Parameters<typeof harness>[0] = {}) {
	const h = await harness(settings);
	const session = await h.login();
	await h.receive(session);
	const { token } = await h.issue(session);
	const listened = await h.listen();
	stop = listened.stop;
	const send = async (method: "GET" | "POST") =>
		(
			await fetch(`${listened.url}/oauth/federation/corp/token`, {
				method,
				headers: { authorization: `Bearer ${token}` },
			})
		).status;
	return { ...h, send };
}

describe("the routes as composed", () => {
	it("answers only POST", async () => {
		const s = await served();
		expect([await s.send("GET"), await s.send("POST")]).toEqual([405, 200]);
	});

	it("limits requests per source to the section's count in each window", async () => {
		const s = await served({ settings: { requests: 2, window: "1m" } });
		expect([await s.send("POST"), await s.send("POST"), await s.send("POST")]).toEqual([
			200, 200, 429,
		]);
		s.advance(59_999);
		expect(await s.send("POST")).toBe(429);
		s.advance(1);
		expect(await s.send("POST")).toBe(200);
	});
});

it("answers no access token it was presented, and logs, records and stores none, handing, refusing or unable to tell [rfc9700-4.9.3-a]", async () => {
	const failing: Offered = {
		refresh: async () => {
			throw new RangeError("bug");
		},
	};
	const seen: unknown[] = [];
	/** One request presenting a token issued in a linked session, `before` run once it is served. */
	const ask = async (
		options: Parameters<typeof harness>[0],
		given: Parameters<Harness["receive"]>[1],
		before: (h: Harness, session: Awaited<ReturnType<Harness["login"]>>) => unknown,
	) => {
		const h = await harness(options);
		const session = await h.login();
		await h.receive(session, given);
		const { token } = await h.issue(session);
		const listened = await h.listen();
		stop = listened.stop;
		await before(h, session);
		const res = await fetch(`${listened.url}/oauth/federation/corp/token`, {
			method: "POST",
			headers: { authorization: `Bearer ${token}` },
		});
		const answer = [res.status, [...res.headers], await res.text()];
		seen.push(answer[0]);
		await listened.stop();
		// The answer, the log, the audit events and what the store was given.
		expect(JSON.stringify([answer, h.logged(), h.events, h.stores.given])).not.toContain(token);
	};
	await ask({}, {}, () => {});
	await ask({}, {}, (h, session) => h.close(session));
	await ask({}, {}, (h) => h.stores.down.failNext("read"));
	await ask({ offered: failing }, { refreshToken: "r-1", expiresInSeconds: 0 }, () => {});
	expect(seen).toEqual([200, 401, 503, 500]);
});

it("takes all it names", async () => {
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused((await harness()).input))["federation-tokens"]).toBeUndefined();
});
