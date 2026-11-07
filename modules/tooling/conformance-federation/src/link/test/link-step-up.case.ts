import { generateKeyPairSync } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";
import { areaTarget, type Started } from "@mod/conformance";
import { recentAuthenticationWindow } from "@mod/conformance-identity";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { browser as openBrowser, probeClient } from "../../../test/browser.ts";
import { fakeUpstream } from "../../../test/upstream.ts";
import { linkStepUpPage } from "../../area.ts";
import { federationScene, landedStatus } from "../../main.ts";

const origin = "https://issuer.example";
const start = "/session/oauth/federation/corp";
const stepUpPage = `${origin}/step-up`;
const password = "correct horse battery";
const pair = generateKeyPairSync("ed25519");
const client = { id: "as-client", secret: "as-client-secret-0123456789" };
/** The shortest window the deployment takes. */
const windowSeconds = 30;

let upstream: Awaited<ReturnType<typeof fakeUpstream>>;
let running: Started;
let base = "";

describe.runIf(areaTarget().can(recentAuthenticationWindow) && areaTarget().can(linkStepUpPage))(
	"federation: a link's start short of a recent sign-in names the step-up page, and comes back",
	() => {
		beforeAll(async () => {
			upstream = await fakeUpstream(client);
			const scene = federationScene({
				links: true,
				linkStepUpPage: stepUpPage,
				origin,
				keys: {
					signing: {
						kid: "link-step-up",
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
				// The page a login through the upstream lands on, before it navigates to the start.
				returnTargets: ["https://app.example/back", stepUpPage],
				users: [{ identifier: "alice", password }],
				clients: [probeClient],
				recentAuthenticationSeconds: windowSeconds,
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

		it(
			"sends the browser to the page with the start to come back to, which a login takes, and refuses it on another origin",
			async () => {
				const alice = browser();
				expect((await alice.submit("/session/login", { username: "alice", password })).status).toBe(
					200,
				);
				await sleep((windowSeconds + 1) * 1000);
				const short = await alice.navigate(`${start}?link=1`, sameOrigin);
				expect(short.status).toBe(403);
				const page = new URL(String(short.body?.page));
				expect(`${page.origin}${page.pathname}`).toBe(stepUpPage);
				expect(page.searchParams.get("requirement")).toBe(short.body?.requirement);
				const back = page.searchParams.get("redirect_to") ?? "";
				expect(back).toBe(`${origin}${start}?link=1`);
				// The same start on another origin, port or scheme is no place to come back to.
				for (const elsewhere of [
					`https://other.example${start}?link=1`,
					`https://issuer.example:8443${start}?link=1`,
					`http://issuer.example${start}?link=1`,
				]) {
					const refused = await alice.submit("/session/login", {
						username: "alice",
						password,
						redirect_to: elsewhere,
					});
					expect([refused.status, refused.body?.error]).toEqual([400, "invalid_redirect"]);
				}
				// Signing in again with it comes back to the start, which now goes on to the upstream.
				const again = await alice.submit("/session/login", {
					username: "alice",
					password,
					redirect_to: back,
				});
				expect([again.status, again.body?.redirect_to]).toEqual([200, back]);
				const at = new URL(back);
				const resumed = await alice.navigate(`${at.pathname}${at.search}`, sameOrigin);
				expect(resumed.status).toBe(302);
				expect(resumed.location.startsWith(upstream.issuer)).toBe(true);
			},
			(windowSeconds + 30) * 1000,
		);

		it(
			"comes back through a login at the upstream to a page on the public origin, not to the start itself",
			async () => {
				const alice = browser();
				expect((await alice.submit("/session/login", { username: "alice", password })).status).toBe(
					200,
				);
				const linking = await alice.navigate(`${start}?link=1`, sameOrigin);
				expect(linking.status).toBe(302);
				const query = await upstream.authorize(linking.location, { subject: "u-alice-step-up" });
				expect((await alice.get(`${start}/callback?${query}`)).status).toBe(landedStatus());
				await sleep((windowSeconds + 1) * 1000);
				const short = await alice.navigate(`${start}?link=1`, sameOrigin);
				expect(short.status).toBe(403);
				const back = new URL(String(short.body?.page)).searchParams.get("redirect_to") ?? "";
				const at = new URL(back);
				/** Logs in through the upstream, landing where `target` says. */
				const throughUpstream = async (target: string) => {
					const started = await alice.get(`${start}?redirect_to=${encodeURIComponent(target)}`);
					expect(started.status).toBe(302);
					// The upstream says when the user signed in, so the login counts as a recent sign-in.
					const answer = await upstream.authorize(started.location, {
						subject: "u-alice-step-up",
						authTime: Math.floor(Date.now() / 1000),
					});
					const landed = await alice.get(`${start}/callback?${answer}`);
					expect([landed.status, landed.location]).toEqual([landedStatus(), target]);
				};
				// Landing on the start itself follows a chain through the upstream's site, which a browser
				// says as `cross-site` (set here by hand): the start takes no such navigation.
				await throughUpstream(back);
				const crossed = await alice.navigate(`${at.pathname}${at.search}`, {
					"sec-fetch-site": "cross-site",
				});
				expect([crossed.status, crossed.body?.error]).toEqual([
					403,
					"link_requires_trusted_origin",
				]);
				// Landing on a page of the public origin, which then navigates to the start, goes on.
				await throughUpstream(stepUpPage);
				const resumed = await alice.navigate(`${at.pathname}${at.search}`, sameOrigin);
				expect(resumed.status).toBe(302);
				expect(resumed.location.startsWith(upstream.issuer)).toBe(true);
			},
			(windowSeconds + 30) * 1000,
		);
	},
);
