import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { areaTarget, auditEvents, type Scripted, type Started } from "@mod/conformance";
import { selfSigned, startFront } from "@mod/conformance-front";
import { startTunnel } from "@mod/conformance-tunnel";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { federationScene, type IdpScene, readsUserinfo } from "../src/main.ts";
import { type Browser, browser as openBrowser, probeClient } from "./browser.ts";
import { fakeUpstream } from "./upstream.ts";

const origin = "https://issuer.example";
const landing = "https://app.example/home";
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
/** An IdP reading UserInfo, its client the scene's. */
const reading = (name: string, issuer: string, more: Partial<IdpScene> = {}): IdpScene => ({
	name,
	issuer,
	clientId: client.id,
	clientSecret: client.secret,
	readUserinfo: true,
	...more,
});
/** The scene: the IdPs given, alice linked at `corp` and carol at `spare`. */
const sceneOf = (idps: readonly IdpScene[], proxy?: string) =>
	federationScene({
		origin,
		keys,
		idps,
		landing,
		returnTargets: ["https://app.example/back"],
		users: [
			{
				identifier: "alice",
				password: "correct horse battery",
				upstream: { idp: "corp", subject: "u-alice" },
			},
			{
				identifier: "carol",
				password: "correct horse battery",
				upstream: { idp: "spare", subject: "u-carol" },
			},
		],
		clients: [probeClient],
		...(proxy ? { proxy } : {}),
	});

let dir = "";
let corp: Awaited<ReturnType<typeof fakeUpstream>>;
let spare: Awaited<ReturnType<typeof fakeUpstream>>;
let running: Started;
let base = "";
const stops: (() => Promise<unknown>)[] = [];
/** An https front for the fake at `upstream()`, named `host`, its certificate made for it. */
async function frontFor(host: string, upstream: () => string) {
	const tls = await selfSigned(host, join(dir, host));
	const front = await startFront({ upstream, publicHost: host, listen: "127.0.0.1", tls });
	stops.push(() => front.stop());
	return { front, cert: tls.cert };
}
beforeAll(async () => {
	if (!able) return;
	dir = await mkdtemp(join(tmpdir(), "federation-userinfo-"));
	// Upstreams on https, as reading UserInfo needs: fronts before the fakes, reached by a tunnel.
	let corpBase = "http://127.0.0.1:1";
	let spareBase = "http://127.0.0.1:1";
	const corpFront = await frontFor("idp.test", () => corpBase);
	const spareFront = await frontFor("spare.test", () => spareBase);
	// spare's UserInfo answers under a certificate the app does not trust.
	const untrusted = await frontFor("info.test", () => spareBase);
	corp = await fakeUpstream(client, { origin: corpFront.front.origin });
	spare = await fakeUpstream(client, {
		origin: spareFront.front.origin,
		userinfoOrigin: untrusted.front.origin,
	});
	stops.push(
		() => corp.stop(),
		() => spare.stop(),
	);
	corpBase = corp.base;
	spareBase = spare.base;
	const routes = [corpFront, spareFront, untrusted].map(({ front }) => new URL(front.origin));
	const tunnel = await startTunnel({
		allow: Object.fromEntries(routes.map((at) => [at.host, `127.0.0.1:${at.port}`])),
	});
	stops.push(() => tunnel.stop());
	const trusted = join(dir, "trusted.pem");
	await writeFile(trusted, `${corpFront.cert}\n${spareFront.cert}`);
	running = await areaTarget().start(
		sceneOf(
			[
				reading("corp", corp.issuer),
				reading("spare", spare.issuer, { endpointHosts: ["info.test"] }),
			],
			`http://127.0.0.1:${tunnel.port}`,
		),
		{ trustedCertificates: [trusted] },
	);
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
const audits = areaTarget().can(auditEvents.need);

/** A login through `idp` as `subject`, the callback's answer, and the audit events while it came. */
async function loggingIn(idp: "corp" | "spare", subject: string) {
	const b: Browser = browser();
	const started = await b.get(`/session/oauth/federation/${idp}`);
	expect(started.status).toBe(302);
	const query = (idp === "corp" ? corp : spare).authorize(started.location, { subject });
	const callback = () => b.get(`/session/oauth/federation/${idp}/callback?${query}`);
	if (!audits) return { b, back: await callback(), events: undefined };
	const { result, events } = await auditEvents.of(running).during(callback);
	return { b, back: result, events: events.map((e) => [e.kind, e.attributes?.reason]) };
}

describe.runIf(able)("federation: reading the upstream's UserInfo", () => {
	it("logs a browser in through an upstream on https, reading its UserInfo once the id_token holds", async () => {
		const before = corp.userinfoCalls.length;
		const { b, back, events } = await loggingIn("corp", "u-alice");
		expect([back.status, back.location]).toEqual([302, landing]);
		expect(await b.session()).toBe(true);
		expect(corp.userinfoCalls.slice(before)).toEqual(["u-alice"]);
		if (events) expect(events).toEqual([["federation.login.succeeded", undefined]]);
	});

	it("refuses a login whose UserInfo names another subject, or answers anything but its JSON, opening no session [oidc-core-5.3.2-n]", async () => {
		const refusing: Scripted[] = [
			{ json: { sub: "u-mallory", name: "Mallory" } },
			{ status: 401, headers: { "www-authenticate": 'Bearer error="invalid_token"' }, text: "" },
			{ status: 403, json: { error: "insufficient_scope" } },
			{ headers: { "content-type": "application/jwt" }, text: "eyJ.a.b" },
		];
		for (const answer of refusing) {
			corp.answerUserinfo(answer);
			const { b, back, events } = await loggingIn("corp", "u-alice");
			expect(back.status, JSON.stringify(answer)).toBe(502);
			expect(await b.session()).toBe(false);
			if (events) expect(events).toEqual([["federation.login.failed", "exchange_failed"]]);
		}
	});

	it("answers a login unavailable while UserInfo is down, too slow, too large or not trusted, opening no session", async () => {
		const down: (Scripted | (() => Promise<Scripted>))[] = [
			{ status: 503, json: {} },
			() =>
				new Promise((resolve) => setTimeout(() => resolve({ json: { sub: "u-alice" } }), 7_000)),
			{ json: { sub: "u-alice", name: "x".repeat(70_000) } },
		];
		for (const answer of down) {
			corp.answerUserinfo(answer);
			const { b, back, events } = await loggingIn("corp", "u-alice");
			expect(back.status).toBe(503);
			expect(await b.session()).toBe(false);
			if (events) expect(events).toEqual([]);
		}
		// spare's UserInfo answers under a certificate the app does not trust.
		const before = spare.userinfoCalls.length;
		const { b, back } = await loggingIn("spare", "u-carol");
		expect(back.status).toBe(503);
		expect(await b.session()).toBe(false);
		expect(spare.userinfoCalls.length).toBe(before);
	}, 30_000);

	it("refuses to start reading UserInfo from an upstream on plain http", async () => {
		const plain = await fakeUpstream(client);
		try {
			const started = await areaTarget().start(sceneOf([reading("corp", plain.issuer)]));
			if (started.kind === "running") await started.stop();
			expect(started.kind).toBe("refused");
		} finally {
			await plain.stop();
		}
	});
});
