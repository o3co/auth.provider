import { randomBytes } from "node:crypto";
import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientsModule from "@mod/clients/module";
import {
	clientSecret,
	clientsConfig,
	confidentialClient,
	publicClient,
} from "@mod/clients/testing";
import cookiesModule from "@mod/cookies/module";
import { csrfStandIn } from "@mod/csrf/testing";
import { targetRules } from "@mod/grants";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { type MetadataItem, metadata } from "@mod/issuer";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, contract, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime, recordingLog, unavailableSwitch } from "@mod/kernel/testing";
import rateLimitModule from "@mod/rate-limit/module";
import { entryRequirements, sessions } from "@mod/session";
import { sessionStandIn } from "@mod/session/testing";
import { simulatedStore } from "@mod/store/testing";
import { subjectRevocation } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { grantCaller, grantCalls } from "@mod/token-endpoint/testing";
import { issuancePolicies, tokens } from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { afterEach, describe, expect, it } from "vitest";
import {
	type DeviceStore,
	deviceGrantType,
	deviceStore,
	type StoredDevice,
	type UserCodes,
	userCodes,
} from "../src/contract.ts";
import deviceGrant from "../src/module.ts";
import { section } from "../src/section.ts";
import { type DeviceGrantSettings, deviceGrantConfig } from "../src/testing.ts";
import { recordsStandIn } from "./stand-in.ts";

const origin = "https://as.example";
let now = 1_800_000_000_000;
/** Bytes the next draws of a user code take (16 at a time; the device code takes 32), so a test can make two codes meet. */
const draws: Uint8Array[] = [];
const logged = recordingLog();
/** The warnings logged after `from`, a count of lines taken before. */
const warnedSince = (from: number) =>
	logged
		.lines()
		.slice(from)
		.filter((line) => line.level === "warn")
		.map((line) => [line.event, line.fields]);
const runtime = quietRuntime({
	log: logged.log,
	clock: { now: () => now },
	random: { bytes: (n) => (n === 16 && draws.shift()) || new Uint8Array(randomBytes(n)) },
});
let stop = async () => {};
afterEach(() => {
	draws.length = 0;
	return stop();
});
const allowed = (grants: string[]) =>
	allowancesFor({ grants, scopes: ["read", "write"], "default-scopes": ["read"] });

const published = contract<readonly MetadataItem[]>("published");
const reader = defineModule({ name: "reader" }, (m) => [
	m.provide(published).by((c) => c.collect(metadata)),
]);

async function serve(
	settings: Partial<DeviceGrantSettings> = {},
	extra: Module[] = [],
	site: { readonly "public-origin"?: string } = { "public-origin": origin },
) {
	const kept = recordsStandIn(() => now);
	const down = {
		devices: unavailableSwitch<DeviceStore>("device store"),
		codes: unavailableSwitch<UserCodes>("user codes"),
	};
	/** Time that passes before the next rewrite of a device reads it, as when the store is slow. */
	let stall = 0;
	const stores = defineModule({ name: "device-stores" }, (m) => [
		m.provide(deviceStore).by(() =>
			down.devices.wrap({
				...kept.devices,
				update: (name, change) => {
					now += stall;
					stall = 0;
					return kept.devices.update(name, change);
				},
			}),
		),
		m.provide(userCodes).by(() => down.codes.wrap(kept.userCodes)),
	]);
	const audit = auditStandIn();
	const app = await assemble({
		modules: [
			http,
			clientsModule,
			issuerModule,
			tokensStandIn(),
			grantCaller,
			clientAllowanceModule,
			sessionStandIn,
			subjectRevocationStandIn,
			csrfStandIn,
			cookiesModule,
			rateLimitModule,
			audit.module,
			simulatedStore().module,
			deviceGrant,
			stores,
			...extra,
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "trusted-proxies": ["127.0.0.1"], ...site }),
			...issuerConfig({ url: origin }),
			...clientsConfig([
				confidentialClient({ id: "tv", sections: allowed([deviceGrantType]) }),
				confidentialClient({ id: "other", sections: allowed([deviceGrantType]) }),
				confidentialClient({ id: "nodevice", sections: allowed(["client_credentials"]) }),
				publicClient({ id: "pub", sections: allowed([deviceGrantType]) }),
			]),
			...deviceGrantConfig(settings),
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
			headers: res.headers,
			body: (await res.json().catch(() => ({}))) as Record<string, string>,
		};
	};
	const post = (path: string, form: Record<string, string> | string[][], headers = {}) =>
		send(path, String(new URLSearchParams(form)), "application/x-www-form-urlencoded", headers);
	const postJson = (path: string, json: Record<string, unknown>, headers = {}) =>
		send(path, JSON.stringify(json), "application/json", headers);
	const authorize = (as = "tv", form: Record<string, string> = {}) =>
		post("/oauth/device_authorization", {
			client_id: as,
			...(as === "pub" ? {} : { client_secret: clientSecret(as) }),
			...form,
		});
	/** A device authorization's two codes, for a test that goes on to verify or poll. */
	const started = async (as?: string, form?: Record<string, string>) => {
		const { device_code = "", user_code = "" } = (await authorize(as, form)).body;
		return { code: device_code, user: user_code };
	};
	const login = async (
		subject = "alice",
		authenticatedAt: number | "unknown" = runtime.clock.now(),
	) => {
		const facts = { subject, amr: ["pwd"], authenticatedAt };
		const { cookies } = await app.get(sessions).complete(testRequest(), facts);
		return cookies[0]?.split(";")[0] ?? "";
	};
	const verify = (cookie: string, json: Record<string, unknown>, headers = {}) =>
		postJson("/oauth/device/verification", json, { origin, cookie, ...headers });
	const poll = async (deviceCode: string, as = "tv") => {
		const outcome = await app
			.get(grantCalls)
			.call(deviceGrantType, as, { grant_type: deviceGrantType, device_code: deviceCode });
		return outcome.kind === "issued" ? outcome.body : outcome.error;
	};
	/** Rewrites what the store keeps for a device, as a store that hands back what it was not given. */
	const tamper = (code: string, change: (kept: Record<string, unknown>) => object) =>
		kept.devices.update(kept.devices.nameOf(code), (record) => ({
			value: change(record as unknown as Record<string, unknown>) as unknown as StoredDevice,
		}));
	/** What the store keeps for a device. */
	const stored = async (code: string) =>
		(await kept.devices.read(kept.devices.nameOf(code))) as unknown as Record<string, unknown>;
	const slowNextUpdate = (ms: number) => {
		stall = ms;
	};
	return {
		app,
		down,
		slowNextUpdate,
		tamper,
		stored,
		authorize,
		started,
		login,
		verify,
		poll,
		post,
		events: audit.events,
	};
}

describe("device authorization", () => {
	it("gives an allowed client a device code and a user code, and refuses a client not allowed the grant", async () => {
		const s = await serve();
		const given = await s.authorize();
		expect(given.status).toBe(200);
		expect(given.headers.get("cache-control")).toBe("no-store");
		expect(given.body).toEqual({
			device_code: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
			user_code: expect.stringMatching(/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/),
			verification_uri: `${origin}/device`,
			expires_in: 600,
			interval: 5,
		});
		expect((await s.authorize("pub")).status).toBe(200);
		expect((await s.authorize("nodevice")).body.error).toBe("unauthorized_client");
		expect((await s.authorize("tv", { scope: "admin" })).body.error).toBe("invalid_scope");
		expect((await s.authorize("tv", { client_secret: "wrong" })).status).toBe(401);
		const twice = await s.post("/oauth/device_authorization", [
			["client_id", "tv"],
			["client_secret", clientSecret("tv")],
			["scope", "read"],
			["scope", "read"],
		]);
		expect([twice.status, twice.body.error]).toEqual([400, "invalid_request"]);
	});

	it("refuses a resource where the composed rule refuses one to what takes no audience", async () => {
		const strict = defineModule({ name: "strict" }, (m) => [
			m.contribute(targetRules).by(() => ({
				target: ({ audience }) => ({ kind: "audience", audience }),
				untargeted: ({ param }) =>
					param("resource")
						? { kind: "error", error: "invalid_target", description: "takes no resource" }
						: undefined,
			})),
		]);
		const s = await serve({}, [strict]);
		const asked = await s.authorize("tv", { resource: "https://api" });
		expect([asked.status, asked.body]).toEqual([
			400,
			{ error: "invalid_target", error_description: "takes no resource" },
		]);
		expect((await s.authorize()).status).toBe(200);
		const plain = await serve();
		expect((await plain.authorize("tv", { resource: "https://api" })).status).toBe(200);
	});

	it("answers the lifetime and the interval it is set to", async () => {
		const s = await serve({ "code-seconds": 300, "interval-seconds": 7 });
		expect((await s.authorize()).body).toMatchObject({ expires_in: 300, interval: 7 });
	});

	it("names among the issuer's metadata where device authorization is asked for", async () => {
		const { app } = await serve({}, [reader]);
		expect(app.get(published)).toContainEqual({
			name: "device_authorization_endpoint",
			value: `${origin}/oauth/device_authorization`,
		});
	});

	it("leaves where device authorization is asked for out of the metadata without a public origin", async () => {
		const { app } = await serve({}, [reader], {});
		expect(app.get(published)).toContainEqual({ name: "device_authorization_endpoint" });
	});

	it("draws a user code again when it meets one in use", async () => {
		const s = await serve();
		const [first, second] = [new Uint8Array(16).fill(1), new Uint8Array(16).fill(2)];
		draws.push(first);
		expect((await s.authorize()).body.user_code).toBe("CCCC-CCCC");
		draws.push(first, second);
		expect((await s.authorize()).body.user_code).toBe("DDDD-DDDD");
		// Bytes past the last whole round of the alphabet are passed over, so no letter is favored.
		draws.push(new Uint8Array(16).fill(245), new Uint8Array(16).fill(3));
		expect((await s.authorize()).body.user_code).toBe("FFFF-FFFF");
		// Five draws that all meet a code in use are given up on.
		draws.push(...Array.from({ length: 5 }, () => first));
		const crowded = await s.authorize();
		draws.length = 0;
		expect([crowded.status, crowded.body.error]).toEqual([503, "temporarily_unavailable"]);
	});

	it("answers the page's address with the code filled in only when asked to", async () => {
		const s = await serve({ "complete-uri": true });
		const given = (await s.authorize()).body;
		expect(given.verification_uri_complete).toBe(
			`${origin}/device?user_code=${encodeURIComponent(given.user_code ?? "")}`,
		);
	});

	it("limits device authorization requests per source", async () => {
		const s = await serve({ requests: 2 });
		expect([(await s.authorize()).status, (await s.authorize()).status]).toEqual([200, 200]);
		const limited = await s.authorize();
		expect([limited.status, limited.body.error]).toEqual([429, "rate_limited"]);
		now += 59_999;
		expect((await s.authorize()).status).toBe(429);
		now += 1;
		expect((await s.authorize()).status).toBe(200);
	});

	it("is unavailable when the store cannot keep the device", async () => {
		const s = await serve();
		s.down.devices.failNext("save");
		const from = logged.lines().length;
		const failed = await s.authorize();
		expect([failed.status, failed.body.error]).toEqual([503, "temporarily_unavailable"]);
		expect(warnedSince(from)).toEqual([
			["device-grant.unavailable", { what: "device store", route: "authorization" }],
		]);
	});
});

describe("polling", () => {
	it("waits, slows a device that polls too often, then issues once to an approved device, with the approval's authentication", async () => {
		const s = await serve();
		const { code, user } = await s.started();
		expect(await s.poll(code)).toBe("authorization_pending");
		expect(await s.poll(code)).toBe("slow_down"); // the interval widens to 10 s
		now += 9_999;
		expect(await s.poll(code)).toBe("slow_down"); // still under 10 s; it widens to 15 s
		now += 15_000;
		expect(await s.poll(code)).toBe("authorization_pending");
		now += 15_000;
		expect(await s.poll(code)).toBe("authorization_pending");
		const loggedInAt = now;
		const cookie = await s.login();
		now += 2_000;
		expect((await s.verify(cookie, { action: "approve", user_code: user })).body).toEqual({
			status: "approved",
			client_id: "tv",
		});
		now += 15_000;
		const issued = (await s.poll(code)) as Record<string, string>;
		expect(issued).toMatchObject({ token_type: "Bearer", scope: "read" });
		const checked = await s.app.get(tokens).verifyAccess(String(issued.access_token));
		expect(checked).toMatchObject({
			kind: "valid",
			grant: {
				subject: "alice",
				issuedTo: "tv",
				audience: [origin],
				scope: ["read"],
				amr: ["pwd"],
				authenticatedAt: Math.floor(loggedInAt / 1000) * 1000,
			},
		});
		now += 15_000;
		expect(await s.poll(code)).toBe("invalid_grant");
	});

	it("issues no authentication time an approving session did not know", async () => {
		const s = await serve();
		const { code, user } = await s.started();
		const cookie = await s.login("alice", "unknown");
		expect((await s.verify(cookie, { action: "approve", user_code: user })).status).toBe(200);
		now += 5_000;
		const issued = (await s.poll(code)) as Record<string, string>;
		const checked = await s.app.get(tokens).verifyAccess(String(issued.access_token));
		expect(checked.kind === "valid" && "authenticatedAt" in checked.grant).toBe(false);
	});

	it("writes a device in format 2, and issues from one kept in format 1 with its time", async () => {
		const s = await serve();
		const { code, user } = await s.started();
		expect((await s.stored(code)).format).toBe(2);
		const loggedInAt = now;
		const cookie = await s.login();
		expect((await s.verify(cookie, { action: "approve", user_code: user })).status).toBe(200);
		await s.tamper(code, (kept) => ({ ...kept, format: 1 }));
		now += 5_000;
		const issued = (await s.poll(code)) as Record<string, string>;
		const checked = await s.app.get(tokens).verifyAccess(String(issued.access_token));
		expect(checked.kind === "valid" && checked.grant.authenticatedAt).toBe(
			Math.floor(loggedInAt / 1000) * 1000,
		);
	});

	it("tells a denied device once, and nothing after", async () => {
		const s = await serve();
		const { code, user } = await s.started();
		const denied = await s.verify(await s.login(), { action: "deny", user_code: user });
		expect(denied.body).toEqual({ status: "denied", client_id: "tv" });
		expect(await s.poll(code)).toBe("access_denied");
		now += 10_000;
		expect(await s.poll(code)).toBe("invalid_grant");
	});

	it("spends nothing on a poll by another client, and still issues to the device's own", async () => {
		const s = await serve();
		const { code, user } = await s.started();
		await s.verify(await s.login(), { action: "approve", user_code: user });
		expect(await s.poll(code, "other")).toBe("invalid_grant");
		expect(await s.poll(code, "other")).toBe("invalid_grant");
		expect(await s.poll(code)).toMatchObject({ token_type: "Bearer" });
		expect(await s.poll("unknown")).toBe("invalid_grant");
		expect(await s.poll("")).toBe("invalid_request");
	});

	it("counts the interval from the last poll, an early one too", async () => {
		const s = await serve();
		const { code } = await s.started();
		expect(await s.poll(code)).toBe("authorization_pending");
		now += 1_000;
		expect(await s.poll(code)).toBe("slow_down"); // the interval widens to 10 s from here
		now += 9_500;
		expect(await s.poll(code)).toBe("slow_down");
	});

	it("reads an approval it does not know as none", async () => {
		const s = await serve();
		const cookie = await s.login();
		const changes = [
			({ approval: _, ...rest }: Record<string, unknown>) => rest,
			(kept: Record<string, unknown>) => ({
				...kept,
				approval: { ...(kept.approval as object), extra: 1 },
			}),
		];
		for (const change of changes) {
			const { code, user } = await s.started();
			await s.verify(cookie, { action: "approve", user_code: user });
			await s.tamper(code, change);
			expect(await s.poll(code)).toBe("invalid_grant");
		}
	});

	it("leaves the scope out of a token answer when it has none", async () => {
		const s = await serve();
		const { code, user } = await s.started();
		await s.verify(await s.login(), { action: "approve", user_code: user });
		await s.tamper(code, (kept) => ({ ...kept, scope: [] }));
		const issued = await s.poll(code);
		expect(issued).toMatchObject({ token_type: "Bearer" });
		expect(issued).not.toHaveProperty("scope");
	});

	it("issues once to two polls at once", async () => {
		const s = await serve();
		const { code, user } = await s.started();
		await s.verify(await s.login(), { action: "approve", user_code: user });
		const answers = await Promise.all([s.poll(code), s.poll(code)]);
		expect(answers.filter((a) => typeof a === "object")).toHaveLength(1);
	});

	it("tells a device polling past its lifetime that its code expired, and nothing once the record ends", async () => {
		const s = await serve();
		const { code, user } = await s.started();
		now += 600_000;
		expect(await s.poll(code)).toBe("expired_token");
		const late = await s.verify(await s.login(), { action: "lookup", user_code: user });
		expect([late.status, late.body.error]).toEqual([410, "expired_token"]);
		now += 600_000;
		expect(await s.poll(code)).toBe("invalid_grant");
	});

	it("issues nothing a contributed policy refuses, and leaves the approved code to a later poll", async () => {
		const denying = { on: false };
		const policy = defineModule({ name: "deny-alice" }, (m) => [
			m.contribute(issuancePolicies).by(() => ({
				name: "deny-alice",
				judge: async (request) =>
					denying.on && request.grant.subject === "alice"
						? { kind: "refused" as const, reason: "denied", description: "not now" }
						: { kind: "allowed" as const },
			})),
		]);
		const s = await serve({}, [policy]);
		const { code, user } = await s.started();
		await s.verify(await s.login(), { action: "approve", user_code: user });
		// Allowed when approved, refused by the time of the poll.
		denying.on = true;
		const refused = await s.app
			.get(grantCalls)
			.call(deviceGrantType, "tv", { grant_type: deviceGrantType, device_code: code });
		expect(refused).toEqual({ kind: "error", error: "invalid_grant", description: "not now" });
		denying.on = false;
		now += 15_000;
		expect(await s.poll(code)).toMatchObject({ token_type: "Bearer" });
	});

	it("refuses and records an approval a contributed policy refuses, before keeping it, as 0.17 refused an unverified email", async () => {
		const denying = { on: true };
		const policy = defineModule({ name: "deny-alice" }, (m) => [
			m.contribute(issuancePolicies).by(() => ({
				name: "deny-alice",
				judge: async (request) =>
					denying.on && request.grant.subject === "alice"
						? { kind: "refused" as const, reason: "denied", description: "not now" }
						: { kind: "allowed" as const },
			})),
		]);
		const s = await serve({}, [policy]);
		const { code, user } = await s.started();
		const cookie = await s.login();
		const refused = await s.verify(cookie, { action: "approve", user_code: user });
		expect([refused.status, refused.body]).toEqual([
			403,
			{ error: "access_denied", error_description: "not now" },
		]);
		expect((await s.stored(code)).state).toBe("pending");
		// Recorded with the policy and its reason, never its description, which may name a contact.
		expect(s.events).toEqual([
			{
				kind: "device.approval_refused",
				at: now,
				subject: "alice",
				attributes: {
					client: "tv",
					policy: "deny-alice",
					reason: "denied",
					source: "198.51.100.1",
				},
			},
		]);
		denying.on = false;
		expect((await s.verify(cookie, { action: "approve", user_code: user })).status).toBe(200);
	});

	it("asks the issuance policies with the approving session, at approval and at the poll", async () => {
		const asked: (string | undefined)[] = [];
		const policy = defineModule({ name: "watching" }, (m) => [
			m.contribute(issuancePolicies).by(() => ({
				name: "watching",
				judge: async (request) => {
					asked.push(request.session);
					return { kind: "allowed" as const };
				},
			})),
		]);
		const s = await serve({}, [policy]);
		const { code, user } = await s.started();
		await s.verify(await s.login(), { action: "approve", user_code: user });
		const approval = (await s.stored(code)).approval as { session?: string };
		expect(approval.session).toEqual(expect.any(String));
		expect(await s.poll(code)).toMatchObject({ token_type: "Bearer" });
		expect(asked.length).toBeGreaterThanOrEqual(2);
		for (const session of asked) expect(session).toBe(approval.session);
	});

	it("issues nothing once the approving session closed, as a code redemption does", async () => {
		const s = await serve();
		const { code, user } = await s.started();
		await s.verify(await s.login(), { action: "approve", user_code: user });
		const approval = (await s.stored(code)).approval as { session: string };
		await s.app.get(sessions).close(approval.session);
		expect(await s.poll(code)).toBe("invalid_grant");
	});

	it("answers no token issued while the approving session closed", async () => {
		let asked = 0;
		let close = async () => {};
		const closing = defineModule({ name: "closing" }, (m) => [
			m.contribute(issuancePolicies).by(() => ({
				name: "closing",
				judge: async () => {
					// The approval, the poll's check, then the issuance: the session closes meanwhile.
					if (++asked === 3) await close();
					return { kind: "allowed" as const };
				},
			})),
		]);
		const s = await serve({}, [closing]);
		const { code, user } = await s.started();
		await s.verify(await s.login(), { action: "approve", user_code: user });
		const approval = (await s.stored(code)).approval as { session: string };
		close = async () => {
			await s.app.get(sessions).close(approval.session);
		};
		expect(await s.poll(code)).toBe("invalid_grant");
		expect(asked).toBe(3);
	});

	it("refuses a subject revoked after approving", async () => {
		const s = await serve();
		const { code, user } = await s.started();
		await s.verify(await s.login(), { action: "approve", user_code: user });
		now += 1000;
		await s.app.get(subjectRevocation).revoke("alice");
		expect(await s.poll(code)).toBe("invalid_grant");
		// A session that authenticated after the revocation approves as usual.
		now += 1000;
		const later = await s.started();
		await s.verify(await s.login(), { action: "approve", user_code: later.user });
		expect(await s.poll(later.code)).toMatchObject({ token_type: "Bearer" });
	});

	it("takes no approval from a session whose subject was revoked after it logged in", async () => {
		const s = await serve();
		const { code, user } = await s.started();
		const cookie = await s.login();
		now += 1000;
		await s.app.get(subjectRevocation).revoke("alice");
		now += 1000;
		const late = await s.verify(cookie, { action: "approve", user_code: user });
		expect([late.status, late.body.error]).toEqual([401, "login_required"]);
		expect(await s.poll(code)).toBe("authorization_pending");
	});

	it("tells a device its code expired when it ends while the store rewrites the record", async () => {
		const s = await serve();
		const { code, user } = await s.started();
		await s.verify(await s.login(), { action: "approve", user_code: user });
		s.slowNextUpdate(600_000);
		expect(await s.poll(code)).toBe("expired_token");
		expect(await s.poll(code)).toBe("expired_token");
	});
});

describe("verification", () => {
	it("looks up a code for a signed-in user, forgiving case, spaces and hyphens, and nothing else", async () => {
		const s = await serve();
		const { user } = await s.started("tv", { scope: "read write" });
		const cookie = await s.login();
		const loose = ` ${user.toLowerCase().replace("-", " ")} `;
		const found = await s.verify(cookie, { action: "lookup", user_code: loose });
		expect(found.body).toEqual({
			client_id: "tv",
			scope: "read write",
			expires_at: new Date(now + 600_000).toISOString(),
		});
		const bent = await s.verify(cookie, { action: "lookup", user_code: `${user.slice(0, 8)}A` });
		expect([bent.status, bent.body.error]).toEqual([404, "invalid_user_code"]);
		const unknown = await s.verify(cookie, { action: "lookup", user_code: "BBBB-BBBB" });
		expect([unknown.status, unknown.body.error]).toEqual([404, "invalid_user_code"]);
		// A code with a letter the alphabet lacks is refused without asking the store.
		s.down.codes.failNext("read");
		const vowel = await s.verify(cookie, { action: "lookup", user_code: "BBBB-BBBA" });
		expect([vowel.status, vowel.body.error]).toEqual([404, "invalid_user_code"]);
		const short = await s.verify(cookie, { action: "lookup", user_code: "BBBB-BBB" });
		expect([short.status, short.body.error]).toEqual([404, "invalid_user_code"]);
	});

	it("refuses a character that upper-cases into the alphabet, without asking the store", async () => {
		const s = await serve();
		draws.push(new Uint8Array(16).fill(14));
		const { user } = await s.started();
		expect(user).toBe("SSSS-SSSS");
		const cookie = await s.login();
		// Each of these upper-cases to a code in use.
		for (const typed of ["SSSS-SSS\u017f", "SSSS-SS\u00df", "SSSS-SS\ufb06"]) {
			s.down.codes.failNext("read");
			const bent = await s.verify(cookie, { action: "lookup", user_code: typed });
			expect([bent.status, bent.body.error], typed).toEqual([404, "invalid_user_code"]);
		}
	});

	it("asks for a session and same-origin evidence, and a known action", async () => {
		const s = await serve();
		const { user } = await s.started();
		const none = await s.verify("", { action: "lookup", user_code: user });
		expect([none.status, none.body.error]).toEqual([401, "login_required"]);
		const cookie = await s.login();
		const foreign = await s.verify(
			cookie,
			{ action: "lookup", user_code: user },
			{ origin: "https://evil.example" },
		);
		expect(foreign.status).toBe(403);
		const odd = await s.verify(cookie, { action: "steal", user_code: user });
		expect([odd.status, odd.body.error]).toEqual([400, "invalid_request"]);
	});

	it("takes its body as JSON only, reading a field only when it is a string", async () => {
		const s = await serve();
		const { user } = await s.started();
		const cookie = await s.login();
		const form = await s.post(
			"/oauth/device/verification",
			{ action: "lookup", user_code: user },
			{ origin, cookie },
		);
		expect(form.status).toBe(415);
		const listed = await s.verify(cookie, { action: ["lookup"], user_code: user });
		expect([listed.status, listed.body.error]).toEqual([400, "invalid_request"]);
		const numbered = await s.verify(cookie, { action: "lookup", user_code: [user] });
		expect([numbered.status, numbered.body.error]).toEqual([404, "invalid_user_code"]);
	});

	it("refuses to decide a code that ends while the store rewrites the record", async () => {
		const s = await serve();
		const cookie = await s.login();
		for (const action of ["approve", "deny"]) {
			const { code, user } = await s.started();
			s.slowNextUpdate(600_000);
			const late = await s.verify(cookie, { action, user_code: user });
			expect([late.status, late.body.error]).toEqual([410, "expired_token"]);
			expect((await s.stored(code)).state).toBe("pending");
			expect(await s.poll(code)).toBe("expired_token");
		}
		expect(s.events).toEqual([]);
	});

	it("reads a kept record of a shape it does not know as none, at the page and at the poll", async () => {
		const s = await serve({ attempts: 100 });
		const cookie = await s.login();
		const bent = [
			...["", 1e300, Number.MAX_SAFE_INTEGER, 8_640_000_000_000_001, -1].map((expiresAt) => ({
				expiresAt,
			})),
			{ format: 3 },
			{ state: "lost" },
			{ extra: 1 },
		];
		for (const change of bent) {
			const { code, user } = await s.started();
			await s.tamper(code, (kept) => ({ ...kept, ...change }));
			const read = await s.verify(cookie, { action: "lookup", user_code: user });
			expect([read.status, read.body.error], JSON.stringify(change)).toEqual([
				404,
				"invalid_user_code",
			]);
			expect(await s.poll(code), JSON.stringify(change)).toBe("invalid_grant");
		}
	});

	it("reads a kept record with a field that throws when read as none", async () => {
		const s = await serve({ attempts: 100 });
		const cookie = await s.login();
		const { code, user } = await s.started();
		await s.tamper(code, (kept) =>
			Object.defineProperty({ ...kept }, "state", {
				enumerable: true,
				get: () => {
					throw new Error("a field that throws");
				},
			}),
		);
		const read = await s.verify(cookie, { action: "lookup", user_code: user });
		expect([read.status, read.body.error]).toEqual([404, "invalid_user_code"]);
		expect(await s.poll(code)).toBe("invalid_grant");
	});

	it("decides a code once", async () => {
		const s = await serve();
		const { code, user } = await s.started();
		const loggedInAt = now;
		const cookie = await s.login();
		now += 2_000;
		expect((await s.verify(cookie, { action: "approve", user_code: user })).status).toBe(200);
		expect((await s.stored(code)).approval).toEqual({
			subject: "alice",
			approvedAt: now,
			amr: ["pwd"],
			authenticatedAt: loggedInAt,
			session: expect.any(String),
		});
		for (const action of ["approve", "deny"]) {
			const again = await s.verify(cookie, { action, user_code: user });
			expect([again.status, again.body.error]).toEqual([409, "already_decided"]);
		}
		expect(await s.poll(code)).toMatchObject({ token_type: "Bearer" });
	});

	it("counts every decision a subject tries, so codes cannot be guessed", async () => {
		const s = await serve({ attempts: 2 });
		const cookie = await s.login();
		for (let i = 0; i < 2; i++) {
			expect((await s.verify(cookie, { action: "lookup", user_code: "BBBB-BBBB" })).status).toBe(
				404,
			);
		}
		const limited = await s.verify(cookie, { action: "lookup", user_code: "BBBB-BBBB" });
		expect([limited.status, limited.body.error, limited.headers.get("retry-after")]).toEqual([
			429,
			"slow_down",
			"300",
		]);
		const other = await s.verify(await s.login("bob"), {
			action: "lookup",
			user_code: "BBBB-BBBB",
		});
		expect(other.status).toBe(404);
	});

	it("limits attempts by the default budget when the section names none", async () => {
		const s = await serve();
		const cookie = await s.login();
		const lookup = () => s.verify(cookie, { action: "lookup", user_code: "BBBB-BBBB" });
		for (let i = 0; i < 5; i++) expect((await lookup()).status).toBe(404);
		expect((await lookup()).status).toBe(429);
	});

	it("asks the session's entry requirements at use for an approval, and at none for the rest", async () => {
		const strict = defineModule({ name: "strict" }, (m) => [
			m.contribute(entryRequirements).by(() => ({
				name: "fresh",
				judges: ["use"],
				admits: async (_context, level) =>
					level === "use" ? { kind: "short", answer: { page: "/raise" } } : { kind: "admit" },
			})),
		]);
		const s = await serve({}, [strict]);
		const { user } = await s.started();
		const cookie = await s.login();
		expect((await s.verify(cookie, { action: "lookup", user_code: user })).status).toBe(200);
		const short = await s.verify(cookie, { action: "approve", user_code: user });
		expect([short.status, short.body]).toEqual([
			403,
			{ error: "step_up_required", requirement: "fresh", answer: { page: "/raise" } },
		]);
		expect((await s.verify(cookie, { action: "deny", user_code: user })).status).toBe(200);
	});

	it("records each decision with its subject, client, source and scope, and nothing else", async () => {
		const s = await serve();
		const first = (await s.authorize("tv", { scope: "read write" })).body;
		const second = (await s.authorize()).body;
		const cookie = await s.login();
		await s.verify(cookie, { action: "lookup", user_code: first.user_code });
		await s.verify(cookie, { action: "approve", user_code: first.user_code });
		await s.verify(cookie, { action: "deny", user_code: second.user_code });
		await s.verify(cookie, { action: "deny", user_code: first.user_code });
		const decided = (kind: string, scope: string) => ({
			kind,
			at: now,
			subject: "alice",
			attributes: { client: "tv", source: "198.51.100.1", scope },
		});
		expect(s.events).toEqual([
			decided("device.approved", "read write"),
			decided("device.denied", "read"),
		]);
		const codes = [first.user_code, first.device_code, second.user_code, second.device_code];
		for (const code of codes) expect(JSON.stringify(s.events)).not.toContain(code);
	});

	it("records a subject over its attempt limit, and a decision whose write could not be told", async () => {
		const s = await serve({ attempts: 1 });
		const { user } = await s.started();
		const bob = await s.login("bob");
		await s.verify(bob, { action: "lookup", user_code: "BBBB-BBBB" });
		await s.verify(bob, { action: "approve", user_code: "BBBB-BBBB" });
		s.down.devices.failNext("update");
		const cookie = await s.login();
		const from = logged.lines().length;
		const lost = await s.verify(cookie, { action: "approve", user_code: user });
		expect([lost.status, lost.body.error]).toEqual([503, "temporarily_unavailable"]);
		expect(warnedSince(from)).toEqual([
			["device-grant.unavailable", { what: "device store", route: "verification" }],
		]);
		expect(s.events).toEqual([
			{
				kind: "device.rate_limited",
				at: now,
				subject: "bob",
				attributes: { action: "approve", source: "198.51.100.1" },
			},
			{
				kind: "device.decision_outcome_unknown",
				at: now,
				subject: "alice",
				attributes: { action: "approve", client: "tv", source: "198.51.100.1" },
			},
		]);
	});
});

it("takes its verification page only as an https URL kept as written: no userinfo, no fragment", () => {
	const page = (value: string) => section.safeParse({ "verification-uri": value }).success;
	expect(page("https://as.example/device?ui=1")).toBe(true);
	for (const value of [
		"https://u@as.example/device",
		"https://as.example/#/device",
		"https:as.example/device",
	]) {
		expect(page(value), value).toBe(false);
	}
});

it("takes each number in its bounds as a whole number, defaults each as the card says, and no other key", () => {
	const parsed = (settings: Record<string, unknown>) =>
		section.safeParse({ "verification-uri": "https://as.example/device", ...settings });
	const bounds: [string, number, number, number][] = [
		["code-seconds", 30, 3600, 600],
		["interval-seconds", 1, 60, 5],
		["attempts", 1, 100, 5],
		["attempts-window-seconds", 60, 86_400, 300],
		["requests", 1, 100_000, 60],
		["window-seconds", 1, 86_400, 60],
	];
	for (const [key, min, max, byDefault] of bounds) {
		const takes = (value: number) => parsed({ [key]: value }).success;
		expect([takes(min), takes(max), takes(min + 0.5)], key).toEqual([true, true, false]);
		expect([takes(min - 1), takes(max + 1)], key).toEqual([false, false]);
		expect(parsed({}).data?.[key as keyof typeof section.shape], key).toBe(byDefault);
	}
	expect(parsed({}).data?.["complete-uri"]).toBe(false);
	expect(parsed({ "verification-uri": "http://as.example/device" }).success).toBe(false);
	expect(parsed({ unknown: 1 }).success).toBe(false);
});
