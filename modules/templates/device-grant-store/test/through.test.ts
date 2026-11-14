import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientsModule from "@mod/clients/module";
import { clientSecret, clientsConfig, confidentialClient } from "@mod/clients/testing";
import cookiesModule from "@mod/cookies/module";
import { csrfStandIn } from "@mod/csrf/testing";
import { approvalRecords, deviceGrantType, deviceStore } from "@mod/device-grant";
import deviceGrant from "@mod/device-grant/module";
import { deviceGrantConfig } from "@mod/device-grant/testing";
import { sessionIssuances } from "@mod/grants";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import httpServer from "@mod/http-server/module";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import rateLimitModule from "@mod/rate-limit/module";
import secretHashModule from "@mod/secret-hash/module";
import { sessions } from "@mod/session";
import { openedOf, sessionStandIn } from "@mod/session/testing";
import sessionRequirements from "@mod/session-requirements/module";
import { simulatedStore } from "@mod/store/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { grantCaller, grantCalls } from "@mod/token-endpoint/testing";
import { tokens } from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { afterEach, expect, it } from "vitest";
import wiring from "../src/module.ts";

const origin = "https://as.example";
const runtime = quietRuntime();
let stop = async () => {};
afterEach(() => stop());

/** What records a token issued in a session to it, as session-tokens does where composed. */
const recording = defineModule({ name: "recording", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(sessionIssuances).by(() => ({ issued: async () => {} })),
]);

/** The real device-grant over this wiring, on a simulated replicated store. */
async function serve() {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [
			http,
			httpServer,
			clientsModule,
			secretHashModule,
			issuerModule,
			tokensStandIn(),
			grantCaller,
			clientAllowanceModule,
			sessionStandIn,
			sessionRequirements,
			subjectRevocationStandIn,
			csrfStandIn,
			cookiesModule,
			rateLimitModule,
			auditStandIn().module,
			simulated.module,
			deviceGrant,
			wiring,
			recording,
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "trusted-proxies": ["127.0.0.1"], "public-origin": origin }),
			...issuerConfig({ url: origin }),
			...clientsConfig([
				confidentialClient({
					id: "tv",
					sections: allowancesFor({
						grants: [deviceGrantType],
						scopes: ["read"],
						"default-scopes": ["read"],
					}),
				}),
			]),
			...deviceGrantConfig(),
		},
		runtime,
	});
	await app.start();
	stop = () => app.stop(1000);
	const base = `http://127.0.0.1:${app.get(listening).port()}`;
	const send = async (path: string, body: string, type: string, headers = {}) => {
		const res = await fetch(`${base}${path}`, {
			method: "POST",
			headers: {
				"content-type": type,
				"x-forwarded-proto": "https",
				"x-forwarded-for": "198.51.100.1",
				...headers,
			},
			body,
		});
		return {
			status: res.status,
			body: (await res.json().catch(() => ({}))) as Record<string, string>,
		};
	};
	const started = async () => {
		const form = new URLSearchParams({ client_id: "tv", client_secret: clientSecret("tv") });
		const { body } = await send(
			"/oauth/device_authorization",
			String(form),
			"application/x-www-form-urlencoded",
		);
		return { code: body.device_code ?? "", user: body.user_code ?? "" };
	};
	const login = async (subject: string) => {
		const at = runtime.clock.now();
		const facts = { subject, amr: ["pwd"], authenticatedAt: at, provenSince: at };
		const { cookies } = openedOf(await app.get(sessions).open(testRequest(), facts));
		return cookies[0]?.split(";")[0] ?? "";
	};
	const approve = async (subject: string, user: string) =>
		send(
			"/oauth/device/verification",
			JSON.stringify({ action: "approve", user_code: user }),
			"application/json",
			{ origin, cookie: await login(subject) },
		);
	const poll = async (code: string) => {
		const outcome = await app
			.get(grantCalls)
			.call(deviceGrantType, "tv", { grant_type: deviceGrantType, device_code: code });
		if (outcome.kind !== "issued") return { error: outcome.error };
		const checked = await app.get(tokens).verifyAccess(String(outcome.body.access_token));
		return { subject: checked.kind === "valid" ? checked.grant.subject : "invalid" };
	};
	/** The subject of the approval kept for a device, read confirmed. */
	const keptFor = async (code: string) => {
		const name = app.get(deviceStore).nameOf(code);
		const read = await app.get(approvalRecords).update(name, () => undefined);
		return (read?.before as unknown as { subject?: string } | undefined)?.subject;
	};
	return { simulated, started, approve, poll, keptFor };
}

it("issues only for the approval that is kept, when an approval read before a failover is lost in it (Codex's case)", async () => {
	const s = await serve();
	const { code, user } = await s.started();
	let reached = () => {};
	const atTake = new Promise<void>((resolve) => {
		reached = resolve;
	});
	let release = () => {};
	const gate = new Promise<void>((resolve) => {
		release = resolve;
	});
	let polled: Promise<{ subject?: string; error?: string }> = Promise.resolve({});
	// Alice's approval applies on the primary. Before it is confirmed, a poll reads it and pauses at
	// its take; the replica takes over, and Alice's writer is gone, so nothing it resends lands.
	s.simulated.beforeConfirm("batch", "device-grant-store.approvals", async () => {
		s.simulated.beforeNext("replaceIf", "device-grant-store.devices", async () => {
			reached();
			await gate;
		});
		polled = s.poll(code);
		await atTake;
		await s.simulated.failover();
		s.simulated.failWrites(true);
	});
	const alice = await s.approve("alice", user);
	s.simulated.failWrites(false);
	// Bob approves after: where Alice's approval was lost, his is kept now (c).
	const bob = await s.approve("bob", user);
	release();
	const first = await polled;
	const kept = await s.keptFor(code);
	expect([alice.status, bob.status, kept]).toEqual(
		kept === "alice" ? [alice.status, 409, "alice"] : [503, 200, "bob"],
	);
	// The poll issued for the approval kept, or waited; never for one a failover dropped.
	if (first.subject !== undefined) expect(first.subject).toBe(kept);
	else expect(first.error).toBe("authorization_pending");
	// A later poll issues for whoever's approval is kept, once.
	if (first.subject === undefined) expect(await s.poll(code)).toEqual({ subject: kept });
}, 60_000);
