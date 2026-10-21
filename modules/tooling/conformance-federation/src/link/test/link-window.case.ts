import { generateKeyPairSync } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";
import { areaTarget, auditEvents, type Started } from "@mod/conformance";
import { recentAuthenticationWindow } from "@mod/conformance-identity";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { browser as openBrowser, probeClient } from "../../../test/browser.ts";
import { fakeUpstream } from "../../../test/upstream.ts";
import { federationScene } from "../../main.ts";

const origin = "https://issuer.example";
const start = "/session/oauth/federation/corp";
const password = "correct horse battery";
const pair = generateKeyPairSync("ed25519");
const client = { id: "as-client", secret: "as-client-secret-0123456789" };
/** The shortest window the deployment takes. */
const windowSeconds = 30;

let upstream: Awaited<ReturnType<typeof fakeUpstream>>;
let running: Started;
let base = "";

describe.runIf(areaTarget().can(recentAuthenticationWindow))(
	"federation: a link asks a recent sign-in",
	() => {
		beforeAll(async () => {
			upstream = await fakeUpstream(client);
			const scene = federationScene({
				links: true,
				origin,
				keys: {
					signing: {
						kid: "link-window",
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
				returnTargets: ["https://app.example/back"],
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
			"refuses a callback once the sign-in is older than the window, and a start then, linking nothing",
			async () => {
				const alice = browser();
				expect(
					(await alice.submit("/session/login", { username: "alice", password })).status,
				).toBeLessThan(400);
				const started = await alice.navigate(`${start}?link=1`, sameOrigin);
				expect(started.status).toBe(302);
				const query = await upstream.authorize(started.location, { subject: "u-late" });
				// The upstream step takes longer than the window.
				await sleep((windowSeconds + 1) * 1000);
				const trail = areaTarget().can(auditEvents.need) ? auditEvents.of(running) : undefined;
				const callback = () => alice.get(`${start}/callback?${query}`);
				const late = trail
					? await trail.during(callback)
					: { result: await callback(), events: [] };
				expect([late.result.status, late.result.body?.error]).toEqual([401, "login_required"]);
				if (trail) {
					expect(late.events).toEqual([
						expect.objectContaining({
							kind: "federation.identity.link_refused",
							attributes: expect.objectContaining({ idp: "corp", reason: "session_short" }),
						}),
					]);
				}
				// A start now meets the session's requirement, which names itself.
				const again = await alice.navigate(`${start}?link=1`, sameOrigin);
				expect(again.status).toBe(403);
				expect(again.body?.requirement).toEqual(expect.any(String));
				// Nothing was linked: a login through the upstream as that identity finds no account.
				const fresh = browser();
				const login = await fresh.get(start);
				const back = await fresh.get(
					`${start}/callback?${await upstream.authorize(login.location, { subject: "u-late" })}`,
				);
				expect(back.status).toBe(401);
			},
			(windowSeconds + 30) * 1000,
		);
	},
);
