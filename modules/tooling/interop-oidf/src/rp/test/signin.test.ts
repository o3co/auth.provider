import { rm } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { selfSigned } from "@mod/conformance-front";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { browser } from "../browser.ts";
import { probe } from "../scene.ts";
import { loggedInAs, signIn } from "../signin.ts";

const dir = join(tmpdir(), `rp-signin-${process.pid}`);
const stops: (() => Promise<void>)[] = [];

async function site(name: string, handle: (req: IncomingMessage, res: ServerResponse) => void) {
	const { key, cert } = await selfSigned("localhost", join(dir, name));
	const server = createServer({ key, cert }, handle);
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	stops.push(() => new Promise((resolve) => server.close(() => resolve())));
	return { origin: `https://127.0.0.1:${(server.address() as AddressInfo).port}`, cert };
}

const returnTarget = "https://app.example/back";
/** How the fake OP answers: a code, or the app's callback refusing it. */
let opAnswers: "code" | "refused" = "code";
/** The subject the probe's id_token names: text as a login's, or anything else. */
let probeSubject: unknown = "local-subject";
let app: { origin: string; cert: string };
let op: { origin: string; cert: string };
const idToken = (sub: unknown) =>
	`e30.${Buffer.from(JSON.stringify({ sub })).toString("base64url")}.sig`;

beforeAll(async () => {
	op = await site("op", (req, res) => {
		const back = `${app.origin}/session/oauth/federation/oidf/callback`;
		res.writeHead(302, { location: `${back}?code=${opAnswers}&state=s` });
		res.end();
		void req;
	});
	app = await site("app", (req, res) => {
		let body = "";
		req.on("data", (chunk: Buffer) => {
			body += chunk;
		});
		req.on("end", () => {
			const at = new URL(req.url ?? "/", "https://app");
			const loggedIn = req.headers.cookie?.includes("session=") === true;
			if (at.pathname === "/session/oauth/federation/oidf") {
				expect(at.searchParams.get("redirect_to")).toBe(returnTarget);
				res.writeHead(302, { location: `${op.origin}/authorize` });
			} else if (at.pathname === "/session/oauth/federation/oidf/callback") {
				if (at.searchParams.get("code") === "code") {
					res.writeHead(303, { "set-cookie": "session=u; Path=/", location: returnTarget });
				} else res.writeHead(502, { "content-type": "application/json" });
			} else if (at.pathname === "/oauth/authorize") {
				const sent = loggedIn ? "code=c9" : "error=login_required";
				res.writeHead(302, { location: `${probe.redirectUri}?${sent}&state=probe` });
			} else if (at.pathname === "/oauth/token") {
				const form = new URLSearchParams(body);
				expect(form.get("code")).toBe("c9");
				expect(form.get("client_id")).toBe(probe.id);
				res.writeHead(200, { "content-type": "application/json" });
				res.end(JSON.stringify({ id_token: idToken(probeSubject) }));
				return;
			} else res.writeHead(404);
			res.end(at.pathname.endsWith("/callback") ? '{"error":"exchange_failed"}' : "");
		});
	});
});

afterAll(async () => {
	for (const stop of stops.reverse()) await stop();
	await rm(dir, { recursive: true, force: true });
});

const fresh = () => browser({ [app.origin]: app.cert, [op.origin]: op.cert });

describe("a sign-in through the suite", () => {
	it("stops at the app's redirect to the return target, and finds the browser logged in", async () => {
		opAnswers = "code";
		const b = fresh();
		expect(await loggedInAs(b, { origin: app.origin })).toBeUndefined();
		const signed = await signIn(b, { origin: app.origin, returnTarget });
		expect(signed.returned).toBe(true);
		expect(signed.callback.url).toContain("/session/oauth/federation/oidf/callback?code=code");
		expect(await loggedInAs(b, { origin: app.origin })).toBe("local-subject");
	});

	it("tells a callback the app refused, the browser not logged in", async () => {
		opAnswers = "refused";
		const b = fresh();
		const signed = await signIn(b, { origin: app.origin, returnTarget });
		expect(signed.returned).toBe(false);
		expect([signed.callback.status, signed.callback.body]).toEqual([
			502,
			'{"error":"exchange_failed"}',
		]);
		expect(await loggedInAs(b, { origin: app.origin })).toBeUndefined();
	});

	it("never reads a login the probe's code proves as logged out, whatever its id_token names", async () => {
		opAnswers = "code";
		for (const named of [undefined, "", 7, null]) {
			probeSubject = named;
			const b = fresh();
			await signIn(b, { origin: app.origin, returnTarget });
			await expect(loggedInAs(b, { origin: app.origin }), String(named)).rejects.toThrow(
				"the probe's id_token names no subject",
			);
		}
		probeSubject = "local-subject";
	});
});
