import { generateKeyPairSync } from "node:crypto";
import { areaTarget, faultyTarget, sceneOf } from "@mod/conformance";
import { identityArea } from "@mod/conformance-identity";
import { keysArea } from "@mod/conformance-keys";
import { secondFactorArea } from "@mod/conformance-second-factor";
import {
	beginBinding,
	browser,
	issuer,
	password,
	running,
	totp,
} from "@mod/conformance-second-factor/testing";
import {
	type Client,
	type CreationOptions,
	softwareAuthenticator,
	type Twist,
} from "@mod/webauthn/testing";
import { describe, expect, it } from "vitest";
import { type PasskeyPart, passkeyArea } from "../src/main.ts";

const pair = generateKeyPairSync("ed25519");
const rpId = new URL(issuer).hostname;
const at: Client = { origin: issuer };
const options = "/oauth/webauthn/registration/options";
const verify = "/oauth/webauthn/registration/verify";

function sceneFor(
	users: string[],
	{
		passkey = {},
		more = [],
	}: { passkey?: Partial<PasskeyPart>; more?: (readonly [string, unknown])[] } = {},
) {
	return sceneOf(
		keysArea.part({
			signing: {
				kid: "passkey",
				alg: "EdDSA",
				privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		}),
		identityArea.part({
			origin: issuer,
			users: users.map((identifier) => ({ identifier, password })),
			login: { attempts: 100, windowSeconds: 600 },
		}),
		passkeyArea.part({ rpId, origins: [issuer], ...passkey }),
		...more,
	);
}

type Browser = ReturnType<typeof browser>;
type Offered = CreationOptions & { excludeCredentials: { id: string }[] };

/** POSTs `body` as JSON, the way the passkey routes take it. */
const postJson = (b: Browser, path: string, body: Record<string, unknown> = {}) =>
	b.send("POST", path, body, {}, "json");
/** The creation options the browser's session is offered; any other answer fails here, as itself. */
const offeredTo = async (b: Browser) => {
	const answered = await postJson(b, options);
	expect(answered, "the creation options").toMatchObject({ status: 200 });
	return answered.body as unknown as Offered;
};
/** A client framed by the page at `topOrigin`. */
const framedBy = (topOrigin: string): Client => ({ ...at, crossOrigin: true, topOrigin });

/** Asks the browser's session for options, and answers them with a new credential. */
async function register(
	b: Browser,
	{
		client = at,
		twist = {},
		authenticator = softwareAuthenticator(),
	}: {
		client?: Client;
		twist?: Twist;
		authenticator?: ReturnType<typeof softwareAuthenticator>;
	} = {},
) {
	const offered = await offeredTo(b);
	const response = authenticator.create(offered, client, twist);
	return { offered, response, answer: await postJson(b, verify, { response }) };
}

/** Signs `username` in at `base`, in a browser of its own. */
async function signedIn(base: () => string, username: string) {
	const b = browser(base);
	expect((await b.login(username)).status).toBe(200);
	return b;
}

describe("H. passkey registration from a session", () => {
	const s = running(sceneFor(["alice", "bob", "carol", "dave", "erin"]));
	const base = () => s.at.base;

	it("registers a passkey for the signed-in user, and excludes it from the next options", async () => {
		const b = await signedIn(base, "alice");
		const { response, answer } = await register(b);
		expect(answer).toEqual({
			status: 200,
			body: { credentialId: response.id, transports: ["internal"], backedUp: false },
		});
		const next = await offeredTo(b);
		expect(next.excludeCredentials.map((c) => c.id)).toEqual([response.id]);
	});

	it("answers 401 to a browser with no session", async () => {
		expect(await postJson(browser(base), options)).toEqual({
			status: 401,
			body: { error: "unauthorized" },
		});
	});

	it("refuses an origin not listed", async () => {
		// A browser elsewhere would not ask for this relying party: only a client that overlooks it can.
		const elsewhere = await register(await signedIn(base, "bob"), {
			client: { origin: "https://evil.example" },
			twist: { overlook: true },
		});
		expect(elsewhere.answer).toMatchObject({ status: 400, body: { error: "origin_mismatch" } });
	});

	it("refuses a challenge answered twice", async () => {
		const b = await signedIn(base, "bob");
		const { response, answer } = await register(b);
		expect(answer.status).toBe(200);
		expect(await postJson(b, verify, { response })).toMatchObject({
			status: 400,
			body: { error: "challenge_invalid" },
		});
	});

	it("refuses a credential id another account registered, and leaves it that account's", async () => {
		const owner = await signedIn(base, "carol");
		const first = await register(owner);
		expect(first.answer.status).toBe(200);
		const copied = await register(await signedIn(base, "dave"), {
			twist: { credentialId: first.response.id },
		});
		expect(copied.answer).toMatchObject({ status: 400, body: { error: "credential_id_conflict" } });
		const next = await offeredTo(owner);
		expect(next.excludeCredentials.map((c) => c.id)).toEqual([first.response.id]);
	});

	it("refuses a ceremony framed by any page, with no frame listed", async () => {
		const { answer } = await register(await signedIn(base, "erin"), {
			client: framedBy("https://shell.example"),
		});
		expect(answer).toMatchObject({ status: 400, body: { error: "top_origin_mismatch" } });
	});

	it.skipIf(areaTarget().differs("passkey-framed-without-top-origin"))(
		"refuses a framed ceremony whose browser names no top origin, with no frame listed",
		async () => {
			const framed = { ...at, crossOrigin: true };
			const { answer } = await register(await signedIn(base, "erin"), { client: framed });
			expect(answer).toMatchObject({ status: 400, body: { error: "top_origin_mismatch" } });
		},
	);
});

describe("H. passkey registration framed by listed pages", () => {
	const s = running(sceneFor(["fay"], { passkey: { topOrigins: ["https://shell.example"] } }));

	it("registers from a listed frame, and refuses one not listed", async () => {
		const b = await signedIn(() => s.at.base, "fay");
		const listed = await register(b, { client: framedBy("https://shell.example") });
		expect(listed.answer.status).toBe(200);
		const other = await register(b, { client: framedBy("https://evil.example") });
		expect(other.answer).toMatchObject({ status: 400, body: { error: "top_origin_mismatch" } });
	});
});

describe("H. passkey registration when user verification is required", () => {
	const s = running(sceneFor(["ivy"], { passkey: { userVerification: "required" } }));

	it("registers a passkey whose user was verified, and refuses one whose user was not", async () => {
		const b = await signedIn(() => s.at.base, "ivy");
		expect((await register(b)).answer.status).toBe(200);
		// A browser stops an authenticator that cannot verify; only a client that overlooks it answers.
		const unverified = await register(b, {
			authenticator: softwareAuthenticator({ userVerified: false }),
			twist: { overlook: true },
		});
		expect(unverified.answer.status).toBe(400);
		if (!areaTarget().differs("passkey-user-verification-unknown")) {
			expect(unverified.answer.body.error).toBe("user_verification_required");
		}
	});
});

describe("H. passkey registration: a challenge past its lifetime", () => {
	const s = running(sceneFor(["jo"], { passkey: { challengeSeconds: 10 } }));

	it("refuses an answer that comes after the challenge's lifetime", async () => {
		const b = await signedIn(() => s.at.base, "jo");
		const offered = await offeredTo(b);
		await new Promise((resolve) => setTimeout(resolve, 11_000));
		const response = softwareAuthenticator().create(offered, at);
		expect(await postJson(b, verify, { response })).toMatchObject({
			status: 400,
			body: { error: "challenge_invalid" },
		});
	});
});

describe.runIf(areaTarget().can("passkey-credential-limit"))(
	"H. passkey registration: the limit of passkeys per user",
	() => {
		const s = running(sceneFor(["kay"], { passkey: { maxCredentials: 1 } }));

		it("keeps a user's passkeys up to the limit, and refuses the next", async () => {
			const b = await signedIn(() => s.at.base, "kay");
			expect((await register(b)).answer.status).toBe(200);
			const next = await register(b);
			expect(next.answer).toMatchObject({ status: 400, body: { error: "credential_limit" } });
		});
	},
);

describe("H. passkey registration asks a recent second factor", () => {
	const s = running(sceneFor(["gail"], { more: [secondFactorArea.part({ mode: "optional" })] }));

	it("answers 403 step_up_required to a session signed in before its user bound a second factor", async () => {
		const b = await signedIn(() => s.at.base, "gail");
		const other = await signedIn(() => s.at.base, "gail");
		const begun = await beginBinding(b, { kind: "totp" }, s.mail());
		const done = await b.send("POST", "/session/mfa/enrollment/complete", {
			transaction_id: String(begun.body.transaction),
			proof: totp(String(begun.body.secret)),
		});
		expect(done.status).toBe(200);
		// A binding after a binding proof raises its own session, so the one signed in beside it is asked.
		const before = begun.proved ? other : b;
		expect(await postJson(before, options)).toMatchObject({
			status: 403,
			body: { error: "step_up_required" },
		});
	});
});

describe.runIf(areaTarget().can("store-fault:passkeys"))(
	"H. passkey registration: the store failing",
	() => {
		const faulty = faultyTarget(sceneFor(["hana"]));

		it("answers 503 while the store is unreachable, never a refusal", async () => {
			const b = await signedIn(() => faulty.base(), "hana");
			const answer = await faulty.whileDown(() => postJson(b, options));
			// The per-source limit, counted in the same store, answers before the route.
			expect(answer).toMatchObject({ status: 503, body: { error: "service_unavailable" } });
		});

		it("answers 503 when the store fails as an answer is verified, and leaves the credential free", async () => {
			const b = await signedIn(() => faulty.base(), "hana");
			const response = softwareAuthenticator().create(await offeredTo(b), at);
			const failed = await faulty.whileDown(() => postJson(b, verify, { response }));
			expect(failed).toMatchObject({ status: 503, body: { error: "service_unavailable" } });
			const again = await register(b, { twist: { credentialId: response.id } });
			expect(again.answer.status).toBe(200);
		});
	},
);
