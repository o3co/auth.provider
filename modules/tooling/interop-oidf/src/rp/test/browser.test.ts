import { rm } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { selfSigned } from "@mod/conformance-front";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { browser } from "../browser.ts";

const dir = join(tmpdir(), `rp-browser-${process.pid}`);
const stops: (() => Promise<void>)[] = [];

/** An https server on loopback under a certificate of its own, answering as `handle` says. */
async function site(name: string, handle: (req: IncomingMessage, res: ServerResponse) => void) {
	const { key, cert } = await selfSigned("localhost", join(dir, name));
	const server = createServer({ key, cert }, handle);
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	stops.push(() => new Promise((resolve) => server.close(() => resolve())));
	return { origin: `https://127.0.0.1:${(server.address() as AddressInfo).port}`, cert };
}

let rp: { origin: string; cert: string };
let op: { origin: string; cert: string };
const seenAtRp: { url: string | undefined; cookie: string | undefined; body: string }[] = [];

beforeAll(async () => {
	op = await site("op", (req, res) => {
		const at = new URL(req.url ?? "/", "https://op");
		if (at.pathname === "/authorize") {
			res.writeHead(302, {
				location: `${at.searchParams.get("back")}?code=c1&state=${at.searchParams.get("state")}`,
			});
		} else if (at.pathname === "/loop") res.writeHead(302, { location: "/loop" });
		else if (at.pathname === "/chain") {
			const left = Number(at.searchParams.get("left"));
			if (left === 0) res.writeHead(200);
			else res.writeHead(302, { location: `/chain?left=${left - 1}` });
		} else if (at.pathname === "/slow") return;
		else res.writeHead(404);
		res.end();
	});
	rp = await site("rp", (req, res) => {
		let body = "";
		req.on("data", (chunk: Buffer) => {
			body += chunk;
		});
		req.on("end", () => {
			seenAtRp.push({ url: req.url, cookie: req.headers.cookie, body });
			const at = new URL(req.url ?? "/", "https://rp");
			if (at.pathname === "/start") {
				res.writeHead(302, {
					"set-cookie": ["trip=t1; Path=/; HttpOnly; Secure", "stale=x; Max-Age=60"],
					location: `${op.origin}/authorize?state=s1&back=${rp.origin}/callback`,
				});
			} else if (at.pathname === "/callback") {
				res.writeHead(302, {
					"set-cookie": ["trip=; Max-Age=0", "session=u1; Path=/"],
					location: `${rp.origin}/landing`,
				});
			} else if (at.pathname === "/landing") res.writeHead(200, { "content-type": "text/plain" });
			else res.writeHead(400, { "content-type": "text/plain" });
			res.end(at.pathname === "/landing" ? "welcome" : "");
		});
	});
});

afterAll(async () => {
	for (const stop of stops.reverse()) await stop();
	await rm(dir, { recursive: true, force: true });
});

describe("the harness's browser", () => {
	it("follows redirects among the origins it trusts, keeping each host's cookies", async () => {
		const b = browser({ [rp.origin]: rp.cert, [op.origin]: op.cert });
		const landed = await b.visit(`${rp.origin}/start`, { follow: () => true });
		expect(landed).toMatchObject({ url: `${rp.origin}/landing`, status: 200, body: "welcome" });
		expect(landed.hops.map((h) => [new URL(h.url).pathname, h.status])).toEqual([
			["/start", 302],
			["/authorize", 302],
			["/callback", 302],
			["/landing", 200],
		]);
		// The callback carried the trip's cookie; the landing, the session's alone.
		const callback = seenAtRp.find((s) => s.url?.startsWith("/callback"));
		expect(callback?.cookie).toBe("trip=t1; stale=x");
		expect(seenAtRp.at(-1)?.cookie).toBe("stale=x; session=u1");
		expect([...b.cookies(new URL(rp.origin).host).keys()]).toEqual(["stale", "session"]);
	});

	it("stops at the answer whose redirect it is told not to follow", async () => {
		const b = browser({ [rp.origin]: rp.cert, [op.origin]: op.cert });
		const landed = await b.visit(`${rp.origin}/start`, {
			follow: (url) => url.pathname !== "/landing",
		});
		expect(landed.url).toBe(`${rp.origin}/callback?code=c1&state=s1`);
		expect(landed.status).toBe(302);
		expect(landed.hops.at(-1)?.location).toBe(`${rp.origin}/landing`);
	});

	it("posts a form where given a body, and goes on with GETs", async () => {
		const b = browser({ [rp.origin]: rp.cert, [op.origin]: op.cert });
		const landed = await b.visit(`${rp.origin}/start`, { follow: () => false }, "a=1");
		expect(landed.hops).toEqual([
			{
				method: "POST",
				url: `${rp.origin}/start`,
				status: 302,
				location: expect.stringContaining("/authorize"),
			},
		]);
		expect(seenAtRp.at(-1)?.body).toBe("a=1");
	});

	it("trusts each origin's own certificate alone", async () => {
		const b = browser({ [rp.origin]: op.cert, [op.origin]: op.cert });
		await expect(b.visit(`${rp.origin}/start`, { follow: () => true })).rejects.toThrow();
		const unknown = browser({ [rp.origin]: rp.cert });
		await expect(unknown.visit(`${rp.origin}/start`, { follow: () => true })).rejects.toThrow(
			`the browser trusts no certificate for ${op.origin}`,
		);
	});

	it("follows ten redirects and refuses the eleventh", async () => {
		const b = browser({ [op.origin]: op.cert });
		const ten = await b.visit(`${op.origin}/chain?left=10`, { follow: () => true });
		expect([ten.status, ten.hops.length]).toEqual([200, 11]);
		await expect(b.visit(`${op.origin}/chain?left=11`, { follow: () => true })).rejects.toThrow(
			"more than 10 redirects",
		);
	});

	it("refuses a redirect loop, and an answer that does not come in time", async () => {
		const b = browser({ [op.origin]: op.cert });
		await expect(b.visit(`${op.origin}/loop`, { follow: () => true })).rejects.toThrow(
			"more than 10 redirects",
		);
		await expect(
			b.visit(`${op.origin}/slow`, { follow: () => true, withinMs: 200 }),
		).rejects.toThrow(`${op.origin} did not answer /slow in time`);
	});
});
