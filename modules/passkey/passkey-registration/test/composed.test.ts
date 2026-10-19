import { auditStandIn } from "@mod/audit/testing";
import cookiesModule from "@mod/cookies/module";
import { csrfStandIn } from "@mod/csrf/testing";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import loginGates from "@mod/login-gates/module";
import { proofSteps } from "@mod/mfa";
import mfaModule from "@mod/mfa/module";
import { mfaConfig } from "@mod/mfa/testing";
import mfaEntry from "@mod/mfa-entry/module";
import mfaStore from "@mod/mfa-store/module";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import sealModule from "@mod/seal/module";
import { sealConfig } from "@mod/seal/testing";
import { sessions } from "@mod/session";
import { sessionStandIn } from "@mod/session/testing";
import sessionRequirements from "@mod/session-requirements/module";
import { simulatedStore } from "@mod/store/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import webauthn from "@mod/webauthn/module";
import {
	type CreationOptions,
	softwareAuthenticator,
	type Twist,
	testOrigin,
	webauthnConfig,
} from "@mod/webauthn/testing";
import webauthnStore from "@mod/webauthn-store/module";
import { afterEach, expect, it } from "vitest";
import registration from "../src/module.ts";

const runtime = quietRuntime();
let stop = async () => {};
afterEach(() => stop());

type Options = CreationOptions & { excludeCredentials: { id: string }[] };

/** A step that proves factors, as a login flow contributes one: mfa boots with none otherwise. */
const step = defineModule({ name: "step" }, (m) => [
	m.contribute(proofSteps).by(() => ({ name: "step" })),
]);

/** The routes over webauthn on a simulated store, with mfa judging entry when asked; `browser` signs in a subject. */
async function serve(
	settings: Parameters<typeof webauthnConfig>[0] = {},
	{ withMfa = false } = {},
) {
	const store = simulatedStore();
	const mfa = withMfa
		? [auditStandIn().module, sealModule, loginGates, mfaStore, mfaModule, mfaEntry, step]
		: [];
	const app = await assemble({
		modules: [
			http,
			csrfStandIn,
			cookiesModule,
			sessionStandIn,
			sessionRequirements,
			subjectRevocationStandIn,
			rateLimitStandIn,
			store.module,
			webauthnStore,
			webauthn,
			registration,
			...mfa,
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": testOrigin, "trusted-proxies": ["127.0.0.1"] }),
			...webauthnConfig(settings),
			...(withMfa ? { ...sealConfig(), ...mfaConfig() } : {}),
		},
		runtime,
	});
	await app.start();
	stop = () => app.stop(1000);
	const base = `http://127.0.0.1:${app.get(listening).port()}`;
	/** A browser signed in as `subject`, at a time the login knows unless told it does not. */
	const browser = async (
		subject: string,
		authenticatedAt: number | "unknown" = runtime.clock.now(),
	) => {
		const done = await app
			.get(sessions)
			.complete(testRequest(), { subject, amr: ["pwd"], authenticatedAt });
		const cookie = done.cookies.map((c) => c.split(";")[0]).join("; ");
		return async (path: string, body?: unknown) => {
			const res = await fetch(`${base}/oauth/webauthn/registration/${path}`, {
				method: "POST",
				headers: {
					origin: testOrigin,
					"x-forwarded-proto": "https",
					"x-forwarded-for": "198.51.100.1",
					cookie,
					...(body === undefined ? {} : { "content-type": "application/json" }),
				},
				...(body === undefined ? {} : { body: JSON.stringify(body) }),
			});
			return { status: res.status, body: (await res.json()) as Record<string, unknown> };
		};
	};
	return { store, browser, sessions: app.get(sessions) };
}

type Post = Awaited<ReturnType<Awaited<ReturnType<typeof serve>>["browser"]>>;

/** Asks for options and answers them with a software authenticator. */
async function register(post: Post, twist: Twist = {}) {
	const options = (await post("options")).body as unknown as Options;
	const response = softwareAuthenticator().create(options, { origin: testOrigin }, twist);
	return { options, response, answer: await post("verify", { response, nickname: "laptop" }) };
}

it("registers a passkey for the session's subject, and excludes it from the next options", async () => {
	const { browser } = await serve();
	const post = await browser("sam");
	const first = await register(post);
	expect(first.answer).toEqual({
		status: 200,
		body: { credentialId: first.response.id, transports: ["internal"], backedUp: false },
	});
	const next = (await post("options")).body as unknown as Options;
	expect(next.user.id).toBe(first.options.user.id);
	expect(next.excludeCredentials.map((c) => c.id)).toEqual([first.response.id]);
});

it("takes a challenge once, and only for the session's subject", async () => {
	const { browser } = await serve();
	const post = await browser("sam");
	const { response } = await register(post);
	expect(await post("verify", { response })).toEqual({
		status: 400,
		body: { error: "challenge_invalid" },
	});
	const options = (await post("options")).body as unknown as Options;
	const answered = softwareAuthenticator().create(options, { origin: testOrigin });
	// kim holds a challenge of her own, so only the subject the challenge was opened for refuses it.
	const kims = await browser("kim");
	await kims("options");
	expect((await kims("verify", { response: answered })).body).toEqual({
		error: "challenge_invalid",
	});
});

it("refuses a credential id another subject holds, and the subject's limit", async () => {
	const { browser } = await serve({ "max-credentials": 1 });
	const sams = await browser("sam");
	const first = await register(sams);
	expect(
		(await register(await browser("kim"), { credentialId: first.response.id })).answer,
	).toEqual({
		status: 400,
		body: {
			error: "credential_id_conflict",
			error_description: "credential ID already registered",
		},
	});
	expect((await register(sams)).answer).toEqual({
		status: 400,
		body: { error: "credential_limit" },
	});
});

it("answers 503 when the store cannot tell", async () => {
	const { browser, store } = await serve();
	const post = await browser("sam");
	store.unreachable(true);
	expect(await post("options")).toEqual({
		status: 503,
		body: { error: "temporarily_unavailable" },
	});
});

it("refuses a session whose sign-in time is unknown where mfa judges entry, before any challenge", async () => {
	const { browser } = await serve({}, { withMfa: true });
	const unknown = await browser("dee", "unknown");
	expect(await unknown("options")).toEqual({ status: 403, body: { error: "step_up_required" } });
	const known = await browser("sam");
	expect((await known("options")).status).toBe(200);
});

it("leaves the credentials entry to mfa's requirement where mfa is composed, not to session's floor", async () => {
	const { sessions: open } = await serve({}, { withMfa: true });
	const facts = { subject: "dee", amr: ["pwd"], authenticatedAt: "unknown" as const };
	const { cookies } = await open.complete(testRequest(), facts);
	const cookie = cookies.map((c) => c.split(";")[0]).join("; ");
	const request = testRequest({
		headers: new Map([["cookie", cookie]]),
		source: { scheme: "https" },
	});
	expect(await open.enterFor(request, "credentials")).toMatchObject({
		kind: "short",
		requirement: "mfa",
	});
});

it("needs a recent sign-in at a known time where nothing judges entry", async () => {
	const { browser } = await serve();
	const stepUp = { status: 403, body: { error: "step_up_required" } };
	expect(await (await browser("dee", "unknown"))("options")).toEqual(stepUp);
	expect(await (await browser("old", runtime.clock.now() - 301_000))("options")).toEqual(stepUp);
	expect((await (await browser("sam"))("options")).status).toBe(200);
});
