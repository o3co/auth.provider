import { takesUnused } from "@mod/kernel/testing";
import { afterEach, describe, expect, it } from "vitest";
import { harness } from "./harness.ts";

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

it("takes all it names", async () => {
	expect(await takesUnused((await harness()).input)).toEqual({});
});
