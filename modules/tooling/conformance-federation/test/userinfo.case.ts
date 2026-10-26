import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { areaTarget, type Started } from "@mod/conformance";
import { selfSigned, startFront } from "@mod/conformance-front";
import { startTunnel } from "@mod/conformance-tunnel";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { federationScene, readsUserinfo } from "../src/main.ts";
import { type Browser, browser as openBrowser, probeClient } from "./browser.ts";
import { fakeUpstream } from "./upstream.ts";

const origin = "https://issuer.example";
const landing = "https://app.example/home";
const start = "/session/oauth/federation/corp";
const pair = generateKeyPairSync("ed25519");
const client = { id: "as-client", secret: "as-client-secret-0123456789" };
const able = areaTarget().can(readsUserinfo);

const keys = {
	signing: {
		kid: "fed",
		alg: "EdDSA" as const,
		privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
		publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
	},
};
/** The scene: one OpenID Connect IdP at `issuer` that reads UserInfo, and alice linked to its subject. */
const sceneAt = (issuer: string, proxy?: string) =>
	federationScene({
		origin,
		keys,
		idps: [
			{
				name: "corp",
				issuer,
				clientId: client.id,
				clientSecret: client.secret,
				readUserinfo: true,
			},
		],
		landing,
		returnTargets: ["https://app.example/back"],
		users: [
			{
				identifier: "alice",
				password: "correct horse battery",
				upstream: { idp: "corp", subject: "u-alice" },
			},
		],
		clients: [probeClient],
		...(proxy ? { proxy } : {}),
	});

let dir = "";
let upstream: Awaited<ReturnType<typeof fakeUpstream>>;
let running: Started;
let base = "";
const stops: (() => Promise<unknown>)[] = [];
beforeAll(async () => {
	if (!able) return;
	dir = await mkdtemp(join(tmpdir(), "federation-userinfo-"));
	// The upstream on https, as reading UserInfo needs: a front before the fake, reached by a tunnel.
	const tls = await selfSigned("idp.test", join(dir, "front"));
	let upstreamBase = "http://127.0.0.1:1";
	const front = await startFront({
		upstream: () => upstreamBase,
		publicHost: "idp.test",
		listen: "127.0.0.1",
		tls,
	});
	stops.push(() => front.stop());
	upstream = await fakeUpstream(client, { origin: front.origin });
	stops.push(() => upstream.stop());
	upstreamBase = upstream.base;
	const at = new URL(front.origin);
	const tunnel = await startTunnel({ allow: { [at.host]: `127.0.0.1:${at.port}` } });
	stops.push(() => tunnel.stop());
	const trusted = join(dir, "idp.pem");
	await writeFile(trusted, tls.cert);
	running = await areaTarget().start(sceneAt(upstream.issuer, `http://127.0.0.1:${tunnel.port}`), {
		trustedCertificates: [trusted],
	});
	const app = running;
	if (app.kind !== "running") throw new Error(`refused:\n${app.output}`);
	stops.push(() => app.stop());
	base = app.baseUrl;
});
afterAll(async () => {
	for (const stop of stops.reverse()) await stop();
	if (dir) await rm(dir, { recursive: true, force: true });
});

const browser = () => openBrowser(() => base, origin);

/** Starts a login and authorizes it upstream as alice, answering the callback query. */
async function authorized(b: Browser) {
	const started = await b.get(start);
	expect(started.status).toBe(302);
	return upstream.authorize(started.location, { subject: "u-alice" });
}

describe.runIf(able)("federation: reading the upstream's UserInfo", () => {
	it("logs a browser in through an upstream on https, reading its UserInfo once the id_token holds", async () => {
		const b = browser();
		const before = upstream.userinfoCalls.length;
		const back = await b.get(`${start}/callback?${await authorized(b)}`);
		expect([back.status, back.location]).toEqual([302, landing]);
		expect(await b.session()).toBe(true);
		expect(upstream.userinfoCalls.slice(before)).toEqual(["u-alice"]);
	});

	it("refuses a login whose UserInfo names another subject, opening no session [oidc-core-5.3.2-n]", async () => {
		const b = browser();
		upstream.answerUserinfo({ json: { sub: "u-mallory", name: "Mallory" } });
		const back = await b.get(`${start}/callback?${await authorized(b)}`);
		expect(back.status).toBe(502);
		expect(await b.session()).toBe(false);
	});

	it("answers a login unavailable while UserInfo is down, opening no session", async () => {
		const b = browser();
		upstream.answerUserinfo({ status: 503, json: {} });
		const back = await b.get(`${start}/callback?${await authorized(b)}`);
		expect(back.status).toBe(503);
		expect(await b.session()).toBe(false);
	});

	it("refuses to start reading UserInfo from an upstream on plain http", async () => {
		const plain = await fakeUpstream(client);
		try {
			const started = await areaTarget().start(sceneAt(plain.issuer));
			if (started.kind === "running") await started.stop();
			expect(started.kind).toBe("refused");
		} finally {
			await plain.stop();
		}
	});
});
