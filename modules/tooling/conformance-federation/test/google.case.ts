import { generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { federationScene } from "../src/main.ts";
import { type Browser, browser as openBrowser, probeClient } from "./browser.ts";
import { type Authorized, fakeUpstream, googleShape } from "./upstream.ts";

const origin = "https://issuer.example";
const landing = "https://app.example/home";
const start = "/session/oauth/federation/google";
const pair = generateKeyPairSync("ed25519");
const client = { id: "g-client.apps.example", secret: "g-client-secret-0123456789" };

let google: Awaited<ReturnType<typeof fakeUpstream>>;
let running: Started;
let base = "";
beforeAll(async () => {
	google = await fakeUpstream(client, { shape: googleShape });
	running = await areaTarget().start(
		federationScene({
			origin,
			keys: {
				signing: {
					kid: "g",
					alg: "EdDSA",
					privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
					publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
				},
			},
			idps: [
				{
					name: "google",
					type: "google",
					issuer: google.base,
					clientId: client.id,
					clientSecret: client.secret,
				},
			],
			landing,
			returnTargets: [],
			users: [
				{
					identifier: "alice",
					password: "correct horse battery",
					upstream: { idp: "google", subject: "1078-alice" },
				},
			],
			clients: [probeClient],
		}),
	);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
	await google?.stop();
});

const browser = () => openBrowser(() => base, origin);
/** Starts a login, checks what Google is asked, and authorizes it there; answers the callback query. */
async function authorized(b: Browser, as: Authorized, query = "") {
	const started = await b.get(`${start}${query}`);
	expect(started.status).toBe(302);
	// Checked by path alone: the host is the target's to choose.
	const asked = new URL(started.location);
	expect(asked.pathname).toBe("/o/oauth2/v2/auth");
	expect(asked.searchParams.get("nonce")).toMatch(/./);
	expect(asked.searchParams.get("scope")?.split(" ")).toContain("openid");
	return { query: google.authorize(started.location, as), asked: asked.searchParams };
}

describe("federation through Google", () => {
	it("logs a browser in by Google's subject, asking for offline access", async () => {
		const b = browser();
		const { query, asked } = await authorized(b, { subject: "1078-alice" });
		expect([asked.get("access_type"), asked.get("prompt")]).toEqual(["offline", "consent"]);
		const back = await b.get(`${start}/callback?${query}`);
		expect([back.status, back.location]).toEqual([302, landing]);
		expect(await b.session()).toBe(true);
	});

	it("refuses a callback without Google's iss, or naming another, before its code is used", async () => {
		for (const iss of [undefined, "https://evil.example"]) {
			const b = browser();
			const { query } = await authorized(b, { subject: "1078-alice" });
			const code = query.get("code") ?? "";
			if (iss) query.set("iss", iss);
			else query.delete("iss");
			expect((await b.get(`${start}/callback?${query}`)).status, String(iss)).toBe(502);
			expect(google.tokenCalls).not.toContain(code);
			expect(await b.session()).toBe(false);
		}
	});

	it("refuses an id_token Google did not sign, one for another login, and one under another algorithm", async () => {
		const cases: Record<string, Authorized> = {
			forged: { subject: "1078-alice", forged: true },
			"another nonce": { subject: "1078-alice", nonce: "not-this-login" },
			ES256: { subject: "1078-alice", elliptic: true },
		};
		for (const [named, as] of Object.entries(cases)) {
			const b = browser();
			const { query } = await authorized(b, as);
			expect((await b.get(`${start}/callback?${query}`)).status, named).toBe(502);
			expect(await b.session()).toBe(false);
		}
	});
});

describe.skipIf(areaTarget().differs("google-freshness-not-forwarded"))(
	"federation through Google: freshness",
	() => {
		it("passes a request to log in again on to Google, and logs in when Google says it just did", async () => {
			const b = browser();
			const now = Math.floor(Date.now() / 1000);
			const { query, asked } = await authorized(
				b,
				{ subject: "1078-alice", authTime: now },
				"?prompt=login&max_age=60",
			);
			expect(asked.get("prompt")?.split(" ")).toContain("login");
			expect(asked.get("max_age")).toBe("60");
			const back = await b.get(`${start}/callback?${query}`);
			expect([back.status, back.location]).toEqual([302, landing]);
			expect(await b.session()).toBe(true);
		});

		it("refuses a login Google says is older than the max age", async () => {
			const b = browser();
			const old = Math.floor(Date.now() / 1000) - 3600;
			const { query } = await authorized(
				b,
				{ subject: "1078-alice", authTime: old },
				"?max_age=60",
			);
			expect((await b.get(`${start}/callback?${query}`)).status).toBe(401);
			expect(await b.session()).toBe(false);
		});
	},
);
