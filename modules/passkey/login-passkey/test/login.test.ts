import { auditStandIn } from "@mod/audit/testing";
import cookiesModule from "@mod/cookies/module";
import { csrfStandIn } from "@mod/csrf/testing";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import {
	assemble,
	type BootRefused,
	contract,
	defineModule,
	kernelConfig,
	type Module,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime, recordingLog, takesUnused } from "@mod/kernel/testing";
import { loginSource } from "@mod/login-attributes";
import { type LoginGate, loginGates, logins } from "@mod/login-gates";
import gatesModule from "@mod/login-gates/module";
import { passkeyWitnessStandIn } from "@mod/passkey-witness/testing";
import witnessingModule from "@mod/passkey-witnessing/module";
import { registrations } from "@mod/passkeys";
import passkeysModule from "@mod/passkeys/module";
import { passkeysConfig } from "@mod/passkeys/testing";
import rateLimitModule from "@mod/rate-limit/module";
import secretHashModule from "@mod/secret-hash/module";
import type { LoginFacts } from "@mod/session";
import { sessions } from "@mod/session";
import { sessionStandIn, stubSessions } from "@mod/session/testing";
import { simulatedStore } from "@mod/store/testing";
import { subjectRevocation } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { users } from "@mod/users";
import usersModule from "@mod/users/module";
import { memoryUsersStores, testUser, usersConfig } from "@mod/users/testing";
import { ceremonies } from "@mod/webauthn";
import webauthn from "@mod/webauthn/module";
import {
	type CreationOptions,
	type RequestOptions,
	softwareAuthenticator,
	testOrigin,
	webauthnConfig,
} from "@mod/webauthn/testing";
import webauthnStore from "@mod/webauthn-store/module";
import { afterEach, describe, expect, it } from "vitest";
import loginModule from "../src/module.ts";

/** The gates composed, collected as login-gates sees them. */
const collectedGates = contract<readonly LoginGate[]>("test.gates");
const gatesProbe = defineModule(
	{ name: "gates-probe", replicaSafe: true, takes: [loginGates] },
	(m) => [m.provide(collectedGates).by((c) => c.collect(loginGates))],
);

let stop = async () => {};
afterEach(async () => {
	await stop();
	stop = async () => {};
});

type Authenticator = ReturnType<typeof softwareAuthenticator>;

interface Setup {
	readonly section?: Record<string, unknown>;
	/** A gate the login passes through, as a test needs one. */
	readonly gate?: (
		facts: LoginFacts,
	) => Promise<
		{ kind: "pass" } | { kind: "held"; answer: unknown; cookies?: string[] } | { kind: "refused" }
	>;
	readonly users?: Module;
	readonly sessions?: Module;
	readonly extra?: Module[];
}

const logged = recordingLog();
/** The lines naming `event` since `from`. */
const loggedSince = (from: number, event: string) =>
	logged
		.lines()
		.slice(from)
		.filter((line) => line.event === event);

async function serve(setup: Setup = {}) {
	const audit = auditStandIn();
	const seen: LoginFacts[] = [];
	const gate = defineModule({ name: "test-gate", replicaSafe: false, takes: [] }, (m) => [
		m.contribute(loginGates).by(() => ({
			name: "test",
			hold: async (_request, facts) => {
				seen.push(facts);
				return setup.gate ? setup.gate(facts) : { kind: "pass" };
			},
		})),
	]);
	const input = {
		modules: [
			http,
			gatesModule,
			csrfStandIn,
			cookiesModule,
			setup.users ?? usersModule,
			secretHashModule,
			memoryUsersStores().module,
			setup.sessions ?? sessionStandIn,
			subjectRevocationStandIn,
			rateLimitModule,
			simulatedStore().module,
			webauthnStore,
			webauthn,
			passkeysModule,
			loginModule,
			audit.module,
			gate,
			gatesProbe,
			...(setup.extra ?? []),
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "trusted-proxies": ["127.0.0.1"], "public-origin": testOrigin }),
			...webauthnConfig(),
			...passkeysConfig(),
			...(setup.users
				? {}
				: usersConfig([
						testUser("alice", "pw", { subject: "s-alice", attributes: { groups: ["staff"] } }),
						testUser("bob", "pw", { subject: "s-bob" }),
					])),
			"login-passkey": setup.section ?? {},
		},
		runtime: quietRuntime({ log: logged.log }),
	};
	const app = await assemble(input);
	await app.start();
	stop = () => app.stop(1000);
	const base = `http://127.0.0.1:${app.get(listening).port()}`;
	const post = async (path: string, body: unknown, headers: Record<string, string> = {}) => {
		const res = await fetch(`${base}${path}`, {
			method: "POST",
			headers: {
				"content-type": "application/json",
				"x-forwarded-proto": "https",
				"x-forwarded-for": "198.51.100.9",
				origin: testOrigin,
				...headers,
			},
			body: JSON.stringify(body),
		});
		const text = await res.text();
		return {
			status: res.status,
			cookies: res.headers.getSetCookie(),
			body: (text ? JSON.parse(text) : undefined) as Record<string, unknown>,
		};
	};
	/** A passkey registered for `subject` on a new authenticator. */
	const registered = async (
		subject: string,
		settings: Parameters<typeof softwareAuthenticator>[0] = {},
	) => {
		const authenticator = softwareAuthenticator(settings);
		const regs = app.get(registrations);
		const options = (await regs.creation(subject)).options as CreationOptions;
		const response = authenticator.create(options, { origin: testOrigin });
		expect((await regs.register(subject, response)).kind).toBe("registered");
		return authenticator;
	};
	/** The options a browser asks, and the requester cookie they set. */
	const options = async () => {
		const answered = await post("/session/login/passkey/options", {});
		expect(answered.status).toBe(200);
		const cookie = answered.cookies.map((c) => c.split(";")[0]).join("; ");
		return { options: answered.body as unknown as RequestOptions, cookie };
	};
	/** A login with `authenticator`, its options asked first, `between` run before the assertion is sent. */
	const login = async (
		authenticator: Authenticator,
		{
			between,
			body = {},
			cookie,
		}: { between?: () => Promise<void>; body?: Record<string, unknown>; cookie?: string } = {},
	) => {
		const asked = await options();
		const response = authenticator.get(asked.options, { origin: testOrigin });
		await between?.();
		return post(
			"/session/login/passkey",
			{ response, ...body },
			{ cookie: cookie ?? asked.cookie },
		);
	};
	const revoke = (subject: string) => app.get(subjectRevocation).revoke(subject);
	const sessionCookie = (cookies: readonly string[]) =>
		cookies.some((c) => /^(__Host-)?session=[^;]+/.test(c));
	return {
		app,
		input,
		post,
		registered,
		options,
		login,
		revoke,
		seen,
		events: audit.events,
		sessionCookie,
	};
}

const failed = { status: 401, body: { error: "passkey_login_failed" } };
const refusedBy = (reason: string) =>
	expect.objectContaining({
		kind: "passkey.session.refused",
		attributes: expect.objectContaining({ reason }),
	});

describe("a passkey login", () => {
	it("opens a session for the passkey's subject, with the user's attributes, authenticated at its opening", async () => {
		const s = await serve();
		const key = await s.registered("s-alice");
		const answered = await s.login(key);
		expect(answered.status).toBe(200);
		expect(answered.body).toEqual({});
		expect(s.sessionCookie(answered.cookies)).toBe(true);
		const [facts] = s.seen;
		expect(facts?.subject).toBe("s-alice");
		expect(facts?.attributes?.values.groups).toEqual(["staff"]);
		expect(facts?.authenticatedAt).toBe("opening");
		expect(s.events).toContainEqual(
			expect.objectContaining({ kind: "passkey.session.opened", subject: "s-alice" }),
		);
	});

	it("proves pop, and mfa only where the user was verified and counts-as-mfa is on", async () => {
		const verified = await serve();
		await verified.login(await verified.registered("s-alice"));
		expect(verified.seen[0]?.amr).toEqual(["pop", "mfa"]);
		const unverified = await serve();
		await unverified.login(await unverified.registered("s-alice", { userVerified: false }));
		expect(unverified.seen[0]?.amr).toEqual(["pop"]);
		const notCounted = await serve({ section: { "counts-as-mfa": false } });
		await notCounted.login(await notCounted.registered("s-alice"));
		expect(notCounted.seen[0]?.amr).toEqual(["pop"]);
	});

	it("redeems a challenge only with the requester cookie its options set", async () => {
		const s = await serve();
		const key = await s.registered("s-alice");
		const without = await s.login(key, { cookie: "" });
		expect({ status: without.status, body: without.body }).toEqual(failed);
		const other = await s.options();
		const elsewhere = await s.login(key, { cookie: other.cookie });
		expect({ status: elsewhere.status, body: elsewhere.body }).toEqual(failed);
		// The cookie sent with no value: no browser's mark, refused alike.
		const blank = await s.login(key, { cookie: `${other.cookie.split("=")[0]}=` });
		expect({ status: blank.status, body: blank.body }).toEqual(failed);
		expect(s.seen).toEqual([]);
	});

	it("answers a credential it does not keep as it answers any refusal, telling nothing of it", async () => {
		const s = await serve();
		const stranger = softwareAuthenticator();
		const user = { handle: Buffer.from("stranger").toString("base64url"), name: "kim" };
		const made = s.app.get(ceremonies).creation(user, [], "preferred");
		stranger.create(made.options as CreationOptions, { origin: testOrigin });
		const answered = await s.login(stranger);
		expect({ status: answered.status, body: answered.body }).toEqual(failed);
		expect(s.events).toContainEqual(refusedBy("unknown-credential"));
	});

	it("refuses a subject users does not know, and is unavailable where users cannot look one up by subject", async () => {
		const s = await serve();
		const key = await s.registered("s-nobody");
		const unknown = await s.login(key);
		expect({ status: unknown.status, body: unknown.body }).toEqual(failed);
		expect(s.events).toContainEqual(refusedBy("unknown_user"));
		const unanswerable = defineModule({ name: "users-stub", replicaSafe: true, takes: [] }, (m) => [
			m.provide(users).by(() => ({ bySubject: async () => ({ kind: "unanswerable" }) }) as never),
		]);
		const u = await serve({ users: unanswerable });
		const answered = await u.login(await u.registered("s-alice"));
		expect(answered.status).toBe(503);
		expect(u.seen).toEqual([]);
	});

	it("refuses a gate's refusal as any other, opening nothing", async () => {
		const s = await serve({ gate: async () => ({ kind: "refused" }) });
		const answered = await s.login(await s.registered("s-alice"));
		expect({ status: answered.status, body: answered.body }).toEqual(failed);
		expect(s.sessionCookie(answered.cookies)).toBe(false);
		expect(s.events).toContainEqual(refusedBy("gate_refused"));
	});

	it("hands a gate's hold on, with its answer and cookies", async () => {
		const s = await serve({
			gate: async () => ({ kind: "held", answer: { held: 1 }, cookies: ["held=1; Path=/"] }),
		});
		const answered = await s.login(await s.registered("s-alice"));
		expect(answered.status).toBe(403);
		expect(answered.body).toEqual({ held: 1 });
		expect(answered.cookies).toContain("held=1; Path=/");
		expect(s.events).toContainEqual(
			expect.objectContaining({ kind: "passkey.session.held", subject: "s-alice" }),
		);
	});
});

describe("a revocation of the subject since the challenge was made", () => {
	it("refuses before the session opens (step 1), opening nothing", async () => {
		const s = await serve();
		const key = await s.registered("s-alice");
		const answered = await s.login(key, { between: () => s.revoke("s-alice") });
		expect({ status: answered.status, body: answered.body }).toEqual(failed);
		expect(s.seen).toEqual([]);
		expect(s.sessionCookie(answered.cookies)).toBe(false);
		expect(s.events).toContainEqual(refusedBy("revoked"));
	});

	it("refuses a held login before its hold is handed on (step 5), its cookies kept back", async () => {
		const s = await serve({
			gate: async (facts) => {
				// Landing as the gates run, after the transaction began, before the hold is answered.
				await s.revoke(facts.subject);
				return { kind: "held", answer: { held: 1 }, cookies: ["held=1; Path=/"] };
			},
		});
		const answered = await s.login(await s.registered("s-alice"));
		expect({ status: answered.status, body: answered.body }).toEqual(failed);
		expect(answered.cookies).not.toContain("held=1; Path=/");
		expect(s.events).toContainEqual(refusedBy("revoked"));
		expect(s.events.map((e) => e.kind)).not.toContain("passkey.session.held");
	});

	it("closes a session opened meanwhile before its cookie goes out (step 6)", async () => {
		const closed: string[] = [];
		const opening = defineModule({ name: "session", replicaSafe: false, takes: [] }, (m) => [
			m.provide(sessions).by(() =>
				stubSessions({
					complete: async () => ({
						session: { id: "opened-1", context: {} as never },
						cookies: ["session=opened-1; Path=/"],
					}),
					close: async (id) => {
						closed.push(id);
						return { kind: "closed", cookies: [] };
					},
				}),
			),
		]);
		const s = await serve({
			sessions: opening,
			gate: async (facts) => {
				await s.revoke(facts.subject);
				return { kind: "pass" };
			},
		});
		const answered = await s.login(await s.registered("s-alice"));
		expect({ status: answered.status, body: answered.body }).toEqual(failed);
		expect(s.sessionCookie(answered.cookies)).toBe(false);
		expect(s.events).toContainEqual(refusedBy("revoked"));
		expect(s.events.map((e) => e.kind)).not.toContain("passkey.session.opened");
		expect(closed).toEqual(["opened-1"]);
	});
});

/** Whether the answer ends the requester's cookie. */
const endsRequester = (cookies: readonly string[]) =>
	cookies.some((c) => /^(__Host-)?passkey-login=;/.test(c) && /Max-Age=0/i.test(c));

describe("the requests it takes", () => {
	it("ends the requester's cookie with every login answer, a malformed request's and an unavailable one's too", async () => {
		const s = await serve();
		const key = await s.registered("s-alice");
		const asked = await s.options();
		for (const body of [
			{},
			{ response: "x" },
			{ response: {}, redirect_to: "https://elsewhere.example/" },
		]) {
			const answered = await s.post("/session/login/passkey", body, { cookie: asked.cookie });
			expect(answered.status, JSON.stringify(body)).toBe(400);
			expect(endsRequester(answered.cookies), JSON.stringify(body)).toBe(true);
		}
		expect(endsRequester((await s.login(key)).cookies)).toBe(true);
		const down = defineModule({ name: "users-stub", replicaSafe: true, takes: [] }, (m) => [
			m.provide(users).by(
				() =>
					({
						bySubject: async () => {
							throw new Unavailable("users");
						},
					}) as never,
			),
		]);
		const u = await serve({ users: down });
		const answered = await u.login(await u.registered("s-alice"));
		expect(answered.status).toBe(503);
		expect(endsRequester(answered.cookies)).toBe(true);
	});

	it("refuses a destination login-gates does not allow, before the assertion is looked at", async () => {
		const s = await serve();
		const answered = await s.login(await s.registered("s-alice"), {
			body: { redirect_to: "https://elsewhere.example/" },
		});
		expect(answered).toMatchObject({ status: 400, body: { error: "invalid_redirect" } });
		expect(s.seen).toEqual([]);
	});

	it("checks the request's origin on both routes", async () => {
		const s = await serve();
		for (const path of ["/session/login/passkey/options", "/session/login/passkey"]) {
			const answered = await s.post(path, {}, { origin: "https://elsewhere.example" });
			expect(answered.status, path).toBe(403);
		}
	});

	it("counts attempts per source on both routes, past which it answers too_many_requests", async () => {
		const s = await serve({ section: { attempts: 2 } });
		await s.options();
		await s.options();
		const past = await s.post("/session/login/passkey/options", {});
		expect(past.status).toBe(429);
	});

	it("answers a body with no response as invalid_request", async () => {
		const s = await serve();
		const asked = await s.options();
		const answered = await s.post("/session/login/passkey", {}, { cookie: asked.cookie });
		expect(answered).toMatchObject({ status: 400, body: { error: "invalid_request" } });
	});
});

/** A passkey witness and the witnessing that asks it, as `refused-when-held` needs. */
const witnessed = () => [passkeyWitnessStandIn().module, witnessingModule];

it("takes all it names, a passkey holder's password allowed or refused", async () => {
	const allowed = await serve();
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused(allowed.input))["login-passkey"]).toBeUndefined();
	await stop();
	const refused = await serve({ section: { password: "refused-when-held" }, extra: witnessed() });
	expect((await takesUnused(refused.input))["login-passkey"]).toBeUndefined();
});

describe("the gate credential-policy", () => {
	it("refuses to boot refused-when-held without a passkey witness, as a lost store would read as holding none", async () => {
		const refused = await serve({ section: { password: "refused-when-held" } }).catch(
			(error: unknown) => error,
		);
		expect((refused as BootRefused).refusals).toContainEqual({
			where: "login-passkey.password",
			reason: expect.stringContaining("passkey witness"),
		});
	});

	/** A password login of `subject` through the gates, its groups as given. */
	const passwordLogin = (
		s: Awaited<ReturnType<typeof serve>>,
		subject: string,
		groups: string[] = [],
	) =>
		s.app.get(logins).login(testRequest(), {
			subject,
			amr: ["pwd"],
			authenticatedAt: Date.now(),
			attributes: { source: loginSource.users, values: { groups } },
		});

	it("refuses a password login of a subject holding a passkey where the password is refused-when-held", async () => {
		const s = await serve({ section: { password: "refused-when-held" }, extra: witnessed() });
		await s.registered("s-alice");
		expect((await passwordLogin(s, "s-alice")).kind).toBe("refused");
		expect(s.seen).toEqual([]);
		expect(s.events).toContainEqual(
			expect.objectContaining({ kind: "passkey.password_refused", subject: "s-alice" }),
		);
		// One holding none, and a passkey login, pass it.
		expect((await passwordLogin(s, "s-bob")).kind).toBe("opened");
		const passkeyLogin = await s.login(await s.registered("s-alice"));
		expect(passkeyLogin.status).toBe(200);
	});

	it("lets the exempt group's password logins through, warning so at every start", async () => {
		const from = logged.lines().length;
		const s = await serve({
			section: { password: "refused-when-held", "password-exempt-group": "staff" },
			extra: witnessed(),
		});
		expect(loggedSince(from, "login-passkey.password_exempt_group")).toEqual([
			{
				level: "warn",
				event: "login-passkey.password_exempt_group",
				fields: {
					reason: "a group's members keep password logins where passkey holders are refused them",
				},
			},
		]);
		await s.registered("s-alice");
		expect((await passwordLogin(s, "s-alice", ["staff"])).kind).toBe("opened");
		expect((await passwordLogin(s, "s-alice", ["others"])).kind).toBe("refused");
	});

	it("passes every login where the password is allowed, as by default", async () => {
		const from = logged.lines().length;
		const s = await serve({ section: { "password-exempt-group": "staff" } });
		expect(loggedSince(from, "login-passkey.password_exempt_group")).toEqual([]);
		await s.registered("s-alice");
		expect((await passwordLogin(s, "s-alice")).kind).toBe("opened");
	});

	it("is asked again when a login a later gate held resumes", async () => {
		const s = await serve({ section: { password: "refused-when-held" }, extra: witnessed() });
		const gates = s.app.get(collectedGates);
		expect(gates.find((g) => g.name === "credential-policy")?.rechecked).toBe(true);
	});
});
