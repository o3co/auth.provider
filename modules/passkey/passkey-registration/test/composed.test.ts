import { auditStandIn } from "@mod/audit/testing";
import cookiesModule from "@mod/cookies/module";
import { csrfStandIn } from "@mod/csrf/testing";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import loginGates from "@mod/login-gates/module";
import { proofSteps } from "@mod/mfa";
import mfaModule from "@mod/mfa/module";
import { mfaConfig } from "@mod/mfa/testing";
import mfaEntry from "@mod/mfa-entry/module";
import mfaStore from "@mod/mfa-store/module";
import passkeys from "@mod/passkeys/module";
import { passkeysConfig } from "@mod/passkeys/testing";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import sealModule from "@mod/seal/module";
import { sealConfig } from "@mod/seal/testing";
import { sessions } from "@mod/session";
import { openedOf, sessionStandIn } from "@mod/session/testing";
import sessionRequirements from "@mod/session-requirements/module";
import { simulatedStore } from "@mod/store/testing";
import { subjectRevocation } from "@mod/subject-revocation";
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
const step = defineModule({ name: "step", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(proofSteps).by(() => ({ name: "step" })),
]);

/** The routes over webauthn on a simulated store, with mfa judging entry when asked. */
function composition(
	settings: Parameters<typeof passkeysConfig>[0] = {},
	{ withMfa = false } = {},
	store = simulatedStore(),
) {
	const mfa = withMfa ? [sealModule, loginGates, mfaStore, mfaModule, mfaEntry, step] : [];
	return {
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
			passkeys,
			registration,
			auditStandIn().module,
			...mfa,
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": testOrigin, "trusted-proxies": ["127.0.0.1"] }),
			...webauthnConfig(),
			...passkeysConfig(settings),
			...(withMfa ? { ...sealConfig(), ...mfaConfig() } : {}),
		},
		runtime,
	};
}

/** The routes of `composition`, served; `browser` signs in a subject. */
async function serve(
	settings: Parameters<typeof passkeysConfig>[0] = {},
	{ withMfa = false } = {},
) {
	const store = simulatedStore();
	const app = await assemble(composition(settings, { withMfa }, store));
	await app.start();
	stop = () => app.stop(1000);
	const base = `http://127.0.0.1:${app.get(listening).port()}`;
	/** A browser signed in as `subject`, at a time the login knows unless told it does not. */
	const browser = async (
		subject: string,
		authenticatedAt: number | "unknown" = runtime.clock.now(),
	) => {
		const done = openedOf(
			await app.get(sessions).open(testRequest(), { subject, amr: ["pwd"], authenticatedAt }),
		);
		const cookie = done.cookies.map((c) => c.split(";")[0]).join("; ");
		return async (path: string, body?: unknown, method = "POST") => {
			const url = path.startsWith("/") ? path : `/oauth/webauthn/registration/${path}`;
			const res = await fetch(`${base}${url}`, {
				method,
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
	return {
		store,
		browser,
		sessions: app.get(sessions),
		revoke: (subject: string) => app.get(subjectRevocation).revoke(subject),
	};
}

type Post = Awaited<ReturnType<Awaited<ReturnType<typeof serve>>["browser"]>>;

/** Asks for options and answers them with a software authenticator. */
async function register(post: Post, twist: Twist = {}) {
	const options = (await post("options")).body as unknown as Options;
	const response = softwareAuthenticator().create(options, { origin: testOrigin }, twist);
	return { options, response, answer: await post("verify", { response, nickname: "laptop" }) };
}

it("takes all it names, with mfa and without", async () => {
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused(composition()))["passkey-registration"]).toBeUndefined();
	expect(
		(await takesUnused(composition({}, { withMfa: true })))["passkey-registration"],
	).toBeUndefined();
});

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
	const { cookies } = openedOf(await open.open(testRequest(), facts));
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

it("lists, renames and removes the subject's passkeys through passkeys, telling when the last goes", async () => {
	const { browser } = await serve();
	const post = await browser("sam");
	const { response } = await register(post);
	const listed = await post("/oauth/webauthn/registrations", undefined, "GET");
	expect(listed.body).toEqual({
		passkeys: [
			expect.objectContaining({ credentialId: response.id, nickname: "laptop", backedUp: false }),
		],
	});
	expect(
		(await post("/oauth/webauthn/registrations/rename", { id: response.id, nickname: "phone" }))
			.status,
	).toBe(200);
	expect((await post("/oauth/webauthn/registrations", undefined, "GET")).body).toEqual({
		passkeys: [expect.objectContaining({ nickname: "phone" })],
	});
	// Another subject cannot rename or remove it.
	const kims = await browser("kim");
	expect((await kims("/oauth/webauthn/registrations/remove", { id: response.id })).status).toBe(
		404,
	);
	expect(await post("/oauth/webauthn/registrations/remove", { id: response.id })).toEqual({
		status: 200,
		body: { last: true },
	});
	expect((await post("/oauth/webauthn/registrations", undefined, "GET")).body).toEqual({
		passkeys: [],
	});
});

it("keeps nothing of a registration a revocation reaches as its record is written, through passkeys and its store", async () => {
	const { store, browser, revoke } = await serve();
	const post = await browser("sam");
	const options = (await post("options")).body as unknown as Options;
	const response = softwareAuthenticator().create(options, { origin: testOrigin });
	// The revocation lands as passkeys writes the record, before it asks again whether the subject was
	// revoked: the record alone (`putIfAbsent`), or with its list as one (`batchAcross`), whichever comes.
	let revoked = false;
	const revokeOnce = async () => {
		if (revoked) return;
		revoked = true;
		await revoke("sam");
	};
	store.beforeNext("putIfAbsent", "webauthn-store.credentials", revokeOnce);
	store.beforeNext("batchAcross", "webauthn-store.credentials", revokeOnce);
	expect(await post("verify", { response })).toEqual({
		status: 401,
		body: { error: "unauthorized" },
	});
	expect(revoked).toBe(true);
	const kims = await browser("kim");
	const theirs = (await kims("options")).body as unknown as Options;
	// The id the revoked registration wrote is free again: nothing of it was kept.
	const taken = softwareAuthenticator().create(
		theirs,
		{ origin: testOrigin },
		{ credentialId: response.id },
	);
	expect((await kims("verify", { response: taken })).status).toBe(200);
});
