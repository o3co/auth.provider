import { generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { federationScene } from "../src/main.ts";
import { type Browser, browser as openBrowser, probeClient } from "./browser.ts";
import { fakeGithub } from "./github.ts";

const origin = "https://issuer.example";
const landing = "https://app.example/home";
const start = "/session/oauth/federation/gh";
const pair = generateKeyPairSync("ed25519");
const client = { id: "gh-client", secret: "gh-client-secret-0123456789" };
const able = areaTarget().can("idp-github");

let github: Awaited<ReturnType<typeof fakeGithub>>;
let running: Started;
let base = "";
beforeAll(async () => {
	if (!able) return;
	github = await fakeGithub(client);
	running = await areaTarget().start(
		federationScene({
			origin,
			keys: {
				signing: {
					kid: "gh",
					alg: "EdDSA",
					privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
					publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
				},
			},
			idps: [
				{
					name: "gh",
					type: "github",
					issuer: github.base,
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
					upstream: { idp: "gh", subject: "583231" },
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
	await github?.stop();
});

const browser = () => openBrowser(() => base, origin);
async function authorized(b: Browser, id: number, query = "") {
	const started = await b.get(`${start}${query}`);
	expect(started.status).toBe(302);
	// Checked by path alone: the host is the target's to choose.
	expect(new URL(started.location).pathname).toBe("/login/oauth/authorize");
	return github.authorize(started.location, id);
}

describe.runIf(able)("federation through GitHub", () => {
	it("logs a browser in by the user's numeric id", async () => {
		const b = browser();
		const back = await b.get(`${start}/callback?${await authorized(b, 583231)}`);
		expect([back.status, back.location]).toEqual([302, landing]);
		expect(await b.session()).toBe(true);
	});

	it("refuses a code GitHub refuses, though GitHub answers it with 200", async () => {
		const b = browser();
		const query = await authorized(b, 583231);
		query.set("code", "not-a-code");
		expect((await b.get(`${start}/callback?${query}`)).status).toBe(502);
		expect(await b.session()).toBe(false);
	});

	it("refuses an answer naming another issuer before its code is used", async () => {
		const b = browser();
		const query = await authorized(b, 583231);
		const code = query.get("code") ?? "";
		query.set("iss", "https://evil.example/login/oauth");
		expect((await b.get(`${start}/callback?${query}`)).status).toBe(502);
		expect(github.tokenCalls).not.toContain(code);
	});

	it("refuses a GitHub user linked to no one", async () => {
		const b = browser();
		expect((await b.get(`${start}/callback?${await authorized(b, 1)}`)).status).toBe(401);
		expect(await b.session()).toBe(false);
	});
});
