import { generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type Browser, browser as openBrowser, probeClient } from "../../../test/browser.ts";
import { fakeUpstream } from "../../../test/upstream.ts";
import { federationScene } from "../../main.ts";

const origin = "https://issuer.example";
const landing = "https://app.example/home";
const start = "/session/oauth/federation/corp";
const password = "correct horse battery";
const pair = generateKeyPairSync("ed25519");
const client = { id: "as-client", secret: "as-client-secret-0123456789" };

let upstream: Awaited<ReturnType<typeof fakeUpstream>>;
let running: Started;
let base = "";

describe("federation: linking an upstream identity to the account logged in", () => {
	beforeAll(async () => {
		upstream = await fakeUpstream(client);
		const scene = federationScene({
			origin,
			keys: {
				signing: {
					kid: "link",
					alg: "EdDSA",
					privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
					publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
				},
			},
			idps: [
				{
					name: "corp",
					issuer: upstream.issuer,
					clientId: client.id,
					clientSecret: client.secret,
				},
			],
			landing,
			returnTargets: ["https://app.example/back"],
			users: [
				{ identifier: "alice", password },
				{ identifier: "bob", password, upstream: { idp: "corp", subject: "u-bob" } },
			],
			clients: [probeClient],
		});
		running = await areaTarget().start(scene);
		if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
		base = running.baseUrl;
	});
	afterAll(async () => {
		if (running?.kind === "running") await running.stop();
		await upstream?.stop();
	});

	const browser = () => openBrowser(() => base, origin);
	const sameOrigin = { "sec-fetch-site": "same-origin" };
	/** A browser logged in by password as `user`. */
	async function loggedIn(user: string) {
		const b = browser();
		expect((await b.submit("/session/login", { username: user, password })).status).toBeLessThan(
			400,
		);
		return b;
	}
	/** Starts a link from the deployment's own page, and authorizes it upstream as `subject`. */
	async function linking(b: Browser, subject: string, path = `${start}?link=1`) {
		const started = await b.navigate(path, sameOrigin);
		expect(started.status).toBe(302);
		return upstream.authorize(started.location, { subject });
	}
	/** Whom a fresh browser logging in through the upstream as `subject` is logged in as, or its refusal. */
	async function federatedAs(subject: string) {
		const b = browser();
		const started = await b.get(start);
		const back = await b.get(
			`${start}/callback?${await upstream.authorize(started.location, { subject })}`,
		);
		return back.status === 302 ? await b.loggedInAs() : back.status;
	}

	it("links the identity to the account logged in, which a login through the upstream then opens", async () => {
		const alice = await loggedIn("alice");
		const query = await linking(alice, "u-new");
		const back = await alice.get(`${start}/callback?${query}`);
		expect([back.status, back.location]).toEqual([302, landing]);
		expect(await federatedAs("u-new")).toBe(await alice.loggedInAs());
	});

	it("answers a link started with no session login_required", async () => {
		const started = await browser().navigate(`${start}?link=1`, sameOrigin);
		expect([started.status, started.body?.error]).toEqual([401, "login_required"]);
	});

	it("refuses a link started from another site, without going upstream", async () => {
		const alice = await loggedIn("alice");
		const started = await alice.navigate(`${start}?link=1`, { "sec-fetch-site": "cross-site" });
		expect([started.status, started.body?.error]).toEqual([403, "link_requires_trusted_origin"]);
	});

	it.skipIf(areaTarget().differs("link-start-origin"))(
		"refuses a link started where the browser does not say it came from this origin",
		async () => {
			const alice = await loggedIn("alice");
			for (const headers of [{ "sec-fetch-site": "none" }, { referer: `${origin}/account` }]) {
				const started = await alice.navigate(`${start}?link=1`, headers);
				expect([started.status, started.body?.error]).toEqual([
					403,
					"link_requires_trusted_origin",
				]);
			}
		},
	);

	it("refuses an identity linked to another account, leaving that account's login as it was", async () => {
		const alice = await loggedIn("alice");
		const back = await alice.get(`${start}/callback?${await linking(alice, "u-bob")}`);
		expect([back.status, back.body?.error]).toEqual([409, "identity_conflict"]);
		const bob = await loggedIn("bob");
		expect(await federatedAs("u-bob")).toBe(await bob.loggedInAs());
	});

	it("takes an identity already linked to the account again, changing nothing", async () => {
		const alice = await loggedIn("alice");
		expect((await alice.get(`${start}/callback?${await linking(alice, "u-again")}`)).status).toBe(
			302,
		);
		const again = await alice.get(`${start}/callback?${await linking(alice, "u-again")}`);
		expect(again.status).toBe(302);
		expect(await federatedAs("u-again")).toBe(await alice.loggedInAs());
	});

	/** A link started as alice, its callback reached after the browser logged in as bob, or out. */
	async function afterSessionChange(subject: string, change: "bob" | "out") {
		const b = await loggedIn("alice");
		const query = await linking(b, subject);
		if (change === "bob") {
			const relogin = await b.submit("/session/login", { username: "bob", password });
			expect(relogin.status).toBeLessThan(400);
		} else {
			await b.submit("/session/logout", {});
		}
		return b.get(`${start}/callback?${query}`);
	}

	it("links nothing when the browser logged in as another account, or out, before the callback", async () => {
		for (const [subject, change] of [
			["u-switched", "bob"],
			["u-out", "out"],
		] as const) {
			const back = await afterSessionChange(subject, change);
			expect(back.status, change).toBeGreaterThanOrEqual(400);
			expect(await federatedAs(subject), change).toBe(401);
		}
	});

	it.skipIf(areaTarget().differs("link-state-outlives-session"))(
		"answers such a callback login_required, its transaction kept apart from the session",
		async () => {
			for (const [subject, change] of [
				["u-switched-2", "bob"],
				["u-out-2", "out"],
			] as const) {
				const back = await afterSessionChange(subject, change);
				expect([back.status, back.body?.error], change).toEqual([401, "login_required"]);
			}
		},
	);

	it("links nothing on a login started without link, even in a browser logged in", async () => {
		const alice = await loggedIn("alice");
		const started = await alice.get(start);
		const query = await upstream.authorize(started.location, { subject: "u-unlinked" });
		const back = await alice.get(`${start}/callback?${query}`);
		expect([back.status, back.body?.error]).toEqual([401, "unknown_user"]);
		expect(await federatedAs("u-unlinked")).toBe(401);
	});
});
