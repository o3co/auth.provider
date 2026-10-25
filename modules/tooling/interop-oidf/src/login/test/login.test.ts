import { createServer, type IncomingHttpHeaders } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { loginPage } from "../login.ts";

const origin = "https://op.test:8443";

/** A provider that answers the login as told, keeping what it was sent. */
async function provider(status: number, answer: unknown, cookies: string[] = []) {
	const seen: {
		method: string | undefined;
		url: string | undefined;
		headers: IncomingHttpHeaders;
		body: string;
	}[] = [];
	const server = createServer((req, res) => {
		let body = "";
		req.on("data", (chunk) => {
			body += chunk;
		});
		req.on("end", () => {
			seen.push({ method: req.method, url: req.url, headers: req.headers, body });
			res.writeHead(status, { "content-type": "application/json", "set-cookie": cookies });
			res.end(JSON.stringify(answer));
		});
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
	stops.push(() => new Promise((resolve) => server.close(() => resolve())));
	return { base, seen };
}
const stops: (() => Promise<void>)[] = [];
afterEach(async () => {
	await Promise.all(stops.splice(0).map((stop) => stop()));
});

const back = `${origin}/oauth/authorize?client_id=client&state=a`;

describe("the login page the harness serves for the suite's browser", () => {
	it("is a form of named fields with no script, carrying the return URL it was given", () => {
		const page = loginPage("http://127.0.0.1:1", origin).form(`${back}&x="<b>"`);
		expect(page).toContain('<form method="post" action="/login">');
		expect(page).toContain('name="username"');
		expect(page).toContain('name="password"');
		expect(page).toContain(
			`<input type="hidden" name="redirect_to" value="${back.replaceAll("&", "&amp;")}&amp;x=&quot;&lt;b&gt;&quot;">`,
		);
		expect(page).toMatch(/<button type="submit"/);
		expect(page).not.toMatch(/<script/i);
	});

	it("logs in at the provider as the browser, from its address, and sends it back with its session", async () => {
		const p = await provider(200, { redirect_to: back }, [
			"__Host-session=s1; Path=/; Secure; HttpOnly",
		]);
		const answer = await loginPage(p.base, origin).submit(
			new URLSearchParams({ username: "alice", password: "pw", redirect_to: back }),
			{ cookie: "__Host-csrf=c1", address: "172.17.0.2" },
		);
		expect(p.seen).toHaveLength(1);
		const sent = p.seen[0];
		expect(sent?.method).toBe("POST");
		expect(sent?.url).toBe("/session/login");
		expect(sent?.headers?.origin).toBe(origin);
		expect(sent?.headers?.["x-forwarded-proto"]).toBe("https");
		expect(sent?.headers?.["x-forwarded-for"]).toBe("172.17.0.2");
		expect(sent?.headers?.cookie).toBe("__Host-csrf=c1");
		expect(sent?.headers?.["content-type"]).toBe("application/x-www-form-urlencoded");
		expect(Object.fromEntries(new URLSearchParams(sent?.body))).toEqual({
			username: "alice",
			password: "pw",
			redirect_to: back,
		});
		expect(answer.status).toBe(302);
		expect(answer.headers.location).toBe(back);
		expect(answer.headers["set-cookie"]).toEqual(["__Host-session=s1; Path=/; Secure; HttpOnly"]);
	});

	it("shows the form again, refused, where the provider refuses the login", async () => {
		const p = await provider(401, { error: "invalid_credentials" });
		const answer = await loginPage(p.base, origin).submit(
			new URLSearchParams({ username: "alice", password: "wrong", redirect_to: back }),
			{ address: "172.17.0.2" },
		);
		expect(answer.status).toBe(401);
		expect(answer.body).toContain("invalid_credentials");
		expect(answer.body).toContain('name="redirect_to"');
		expect(answer.headers.location).toBeUndefined();
	});

	it("says the login is done where the provider gives nowhere to go", async () => {
		const p = await provider(200, {});
		const answer = await loginPage(p.base, origin).submit(
			new URLSearchParams({ username: "alice", password: "pw" }),
			{ address: "172.17.0.2" },
		);
		expect(answer.status).toBe(200);
		expect(answer.headers.location).toBeUndefined();
	});

	it("gives up on a provider that never answers the login, refusing it", async () => {
		const silent = createServer(() => {});
		await new Promise<void>((resolve) => silent.listen(0, "127.0.0.1", resolve));
		stops.push(() => new Promise((resolve) => silent.close(() => resolve())));
		silent.unref();
		const base = `http://127.0.0.1:${(silent.address() as AddressInfo).port}`;
		const answer = await loginPage(base, origin, 200).submit(
			new URLSearchParams({ username: "alice", password: "pw" }),
			{ address: "172.17.0.2" },
		);
		expect(answer.status).toBe(504);
		expect(answer.body).toContain("did not answer");
	});
});
