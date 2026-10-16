import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { ceremoniesFor, challengeOf } from "../src/ceremony/ceremony.ts";
import type { Credential, Verification } from "../src/contract.ts";
import {
	type CreationOptions,
	type RequestOptions,
	softwareAuthenticator,
	testOrigin,
} from "../src/testing.ts";

const rp = {
	id: "rp.example",
	name: "RP",
	origins: [testOrigin],
	topOrigins: ["https://shell.example"],
	timeoutMs: 120_000,
};
const start = 1_000_000;
let now = start;
const random = (n: number) => new Uint8Array(randomBytes(n));
const ceremonies = ceremoniesFor(rp, random, () => now);
const handle = randomBytes(32).toString("base64url");
const at = { origin: testOrigin };
const evil = { origin: "https://evil.example" };

/** Creation options for `handle`, as the browser receives them, and their challenge and its end. */
function creation(v: Verification = "preferred", c = ceremonies) {
	const { options, challenge, until } = c.creation({ handle, name: "sam" }, [], v);
	return { options: options as CreationOptions, challenge, until };
}

/** Request options listing no credential, as the browser receives them, and their challenge and its end. */
function request(v: Verification = "preferred") {
	const { options, challenge, until } = ceremonies.request([], v);
	return { options: options as RequestOptions, challenge, until };
}

/** A credential made by `authenticator`, as attested. */
async function made(authenticator = softwareAuthenticator()) {
	const { options, challenge } = creation();
	const attested = await ceremonies.attest(
		authenticator.create(options, at),
		challenge,
		handle,
		"preferred",
	);
	if (attested.kind !== "attested") throw new Error(attested.reason);
	return { authenticator, credential: attested.credential };
}

const reasonOf = (answer: { kind: string; reason?: string }) => answer.reason ?? answer.kind;

describe("creation and attestation", () => {
	it("offers 32 random bytes to sign, the three algorithms, the subject's credentials to exclude, and asks for a discoverable credential", () => {
		const { options, challenge } = ceremonies.creation(
			{ handle, name: "sam" },
			["AAAA"],
			"required",
		);
		expect(Buffer.from(challenge, "base64url")).toHaveLength(32);
		expect(options).toMatchObject({
			rp: { id: "rp.example", name: "RP" },
			user: { id: handle, name: "sam" },
			challenge,
			pubKeyCredParams: [-8, -7, -257].map((alg) => ({ alg, type: "public-key" })),
			excludeCredentials: [{ id: "AAAA", type: "public-key" }],
			authenticatorSelection: {
				residentKey: "required",
				requireResidentKey: true,
				userVerification: "required",
			},
		});
	});

	it("asks for a credential that need not be discoverable when told", async () => {
		const { options } = ceremonies.creation({ handle, name: "sam" }, [], "preferred", {
			discoverable: false,
		});
		expect(options).toMatchObject({
			authenticatorSelection: {
				residentKey: "discouraged",
				requireResidentKey: false,
				userVerification: "preferred",
			},
		});
	});

	it("attests a credential for the handle, keeping its key, count and backup eligibility", async () => {
		const { credential } = await made(softwareAuthenticator({ backupEligible: true }));
		expect(credential).toMatchObject({
			signCount: 0,
			userHandle: handle,
			backupEligible: true,
			backedUp: true,
			transports: ["internal"],
		});
		expect(Buffer.from(credential.id, "base64url").toString("base64url")).toBe(credential.id);
	});

	it("keeps the transports the client lists only as a short list of short strings, else none", async () => {
		const cases: Record<string, unknown> = {
			"an object": {},
			"a number": 5,
			"one string": "usb",
			"a list with a number": ["usb", 1],
			"nine of them": Array(9).fill("usb"),
			"one too long": ["u".repeat(33)],
		};
		for (const [name, transports] of Object.entries(cases)) {
			const { options, challenge } = creation();
			const response = softwareAuthenticator().create(options, at);
			(response as { response: { transports?: unknown } }).response.transports = transports;
			const attested = await ceremonies.attest(response, challenge, handle, "preferred");
			expect(attested, name).toMatchObject({ kind: "attested" });
			expect((attested as { credential: object }).credential, name).not.toHaveProperty(
				"transports",
			);
		}
	});

	it("attests a credential id longer than 255 bytes", async () => {
		const { options, challenge } = creation();
		const credentialId = randomBytes(300).toString("base64url");
		const response = softwareAuthenticator().create(options, at, { credentialId });
		const attested = await ceremonies.attest(response, challenge, handle, "preferred");
		expect(attested).toMatchObject({ kind: "attested", credential: { id: credentialId } });
	});

	it("refuses another origin, challenge, relying party, algorithm, and an unverified user when required", async () => {
		const { options, challenge } = creation("required");
		// Each of these a browser would stop; only a client that overlooks it sends one.
		const overlook = { overlook: true };
		const attest = (
			response: unknown,
			v: "required" | "preferred" = "preferred",
			expected = challenge,
		) => ceremonies.attest(response, expected, handle, v).then(reasonOf);
		const plain = softwareAuthenticator();
		expect(await attest(plain.create(options, evil, overlook))).toBe("origin");
		expect(await attest(plain.create(options, at), "preferred", "other")).toBe("challenge");
		expect(await attest(plain.create(options, at, { rpId: "evil.example" }))).toBe("rp");
		const es384 = softwareAuthenticator({ algorithm: "ES384" });
		expect(await attest(es384.create(options, at, overlook))).toBe("algorithm");
		const unverified = softwareAuthenticator({ userVerified: false });
		expect(await attest(unverified.create(options, at, overlook), "required")).toBe(
			"user-verification",
		);
	});

	it("attests an unverified user unless verification is required", async () => {
		const { options, challenge } = creation();
		const response = softwareAuthenticator({ userVerified: false }).create(options, at);
		const attested = await ceremonies.attest(response, challenge, handle, "preferred");
		expect(reasonOf(attested)).toBe("attested");
	});

	it("refuses a response whose client data cannot be read", async () => {
		const { challenge } = creation();
		for (const response of [{ response: { clientDataJSON: 5 } }, "not a response"]) {
			const attested = await ceremonies.attest(response, challenge, handle, "preferred");
			expect(reasonOf(attested)).toBe("malformed");
		}
	});

	it("refuses a framed ceremony from a page not listed, or one that says it is not framed", async () => {
		const { options, challenge } = creation();
		const a = softwareAuthenticator();
		// A browser never says a page is not framed while naming its top origin.
		const framed = (topOrigin: string, crossOrigin = true) =>
			ceremonies
				.attest(
					a.create(options, { ...at, crossOrigin, topOrigin }, { overlook: !crossOrigin }),
					challenge,
					handle,
					"preferred",
				)
				.then(reasonOf);
		expect(await framed("https://evil.example")).toBe("top-origin");
		expect(await framed("https://shell.example", false)).toBe("top-origin");
		expect(await framed("https://shell.example")).toBe("attested");
	});

	it("refuses any framed ceremony when no page may frame one, whether or not a top origin is reported", async () => {
		const unframed = ceremoniesFor({ ...rp, topOrigins: [] }, random, () => now);
		const a = softwareAuthenticator();
		for (const client of [
			{ ...at, crossOrigin: true },
			{ ...at, crossOrigin: true, topOrigin: "https://shell.example" },
		]) {
			const { options, challenge } = creation("preferred", unframed);
			const attested = await unframed.attest(
				a.create(options, client),
				challenge,
				handle,
				"preferred",
			);
			expect(reasonOf(attested)).toBe("top-origin");
			const { authenticator, credential } = await made();
			const asserted = await unframed.assert(
				authenticator.get({ challenge, rpId: "rp.example" }, client),
				challenge,
				credential,
				"preferred",
			);
			expect(reasonOf(asserted)).toBe("top-origin");
		}
	});

	it("leaves a frame whose page is not reported to the list of pages that may frame one", async () => {
		const { authenticator, credential } = await made();
		const { options, challenge } = request();
		const framed = { ...at, crossOrigin: true };
		const asserted = await ceremonies.assert(
			authenticator.get(options, framed),
			challenge,
			credential,
			"preferred",
		);
		expect(reasonOf(asserted)).toBe("asserted");
	});

	it("reads the challenge as the library verifies it, never as another decoder would", async () => {
		const challenge = "fixed-challenge-@@@-@@@";
		let otherRead = "";
		// '/' is not base64url: the library reads it as 'A', a lenient decoder as 63.
		const twisted = (json: string) => {
			const plain = Buffer.from(json).toString("base64url");
			for (const [i, char] of [...plain].entries()) {
				if (char !== "A") continue;
				const text = `${plain.slice(0, i)}/${plain.slice(i + 1)}`;
				try {
					const read = JSON.parse(Buffer.from(text, "base64url").toString()).challenge;
					if (typeof read === "string" && read !== challenge) {
						otherRead = read;
						return text;
					}
				} catch {}
			}
			throw new Error("no spelling read otherwise");
		};
		const response = softwareAuthenticator().create({ ...creation().options, challenge }, at, {
			clientDataJSON: twisted,
		});
		expect(challengeOf(response)).toBe(challenge);
		expect(otherRead).not.toBe("");
		expect(reasonOf(await ceremonies.attest(response, otherRead, handle, "preferred"))).toBe(
			"challenge",
		);
		expect(reasonOf(await ceremonies.attest(response, challenge, handle, "preferred"))).toBe(
			"attested",
		);
	});
});

describe("request and assertion", () => {
	const assert = (
		response: unknown,
		challenge: string,
		credential: Credential,
		v: "required" | "preferred" = "preferred",
	) => ceremonies.assert(response, challenge, credential, v);

	it("asks for any of the allowed credentials, and asserts one, moving its count on", async () => {
		const { authenticator, credential } = await made();
		const { options, challenge } = ceremonies.request([credential], "preferred");
		expect(options).toMatchObject({
			challenge,
			rpId: "rp.example",
			allowCredentials: [{ id: credential.id, type: "public-key", transports: ["internal"] }],
		});
		const response = authenticator.get(options as RequestOptions, at);
		const asserted = await assert(response, challenge, credential);
		expect(asserted).toEqual({
			kind: "asserted",
			credential: { ...credential, signCount: 1 },
			userVerified: true,
		});
	});

	it("judges the count only once the signature verified, and lets 0 follow 0", async () => {
		const { authenticator, credential } = await made();
		const { credential: other } = await made();
		const { options, challenge } = request();
		const regressed = { ...credential, signCount: 9 };
		const forged = { ...regressed, publicKey: other.publicKey };
		expect(reasonOf(await assert(authenticator.get(options, at), challenge, forged))).toBe(
			"signature",
		);
		expect(reasonOf(await assert(authenticator.get(options, at), challenge, regressed))).toBe(
			"sign-count",
		);
		const countless = await made(softwareAuthenticator({ countless: true }));
		const first = await assert(
			countless.authenticator.get(options, at),
			challenge,
			countless.credential,
		);
		expect(first).toMatchObject({ kind: "asserted", credential: { signCount: 0 } });
		// A count that stayed where it was, and 0 after a count, did not go up.
		const fresh = await made();
		const same = { ...fresh.credential, signCount: 1 };
		expect(reasonOf(await assert(fresh.authenticator.get(options, at), challenge, same))).toBe(
			"sign-count",
		);
		const later = { ...countless.credential, signCount: 5 };
		expect(reasonOf(await assert(countless.authenticator.get(options, at), challenge, later))).toBe(
			"sign-count",
		);
	});

	it("asserts without a handle, which a credential that is not discoverable may leave out", async () => {
		const { authenticator, credential } = await made();
		const { options, challenge } = request();
		const response = authenticator.get(options, at, { userHandle: null });
		expect(reasonOf(await assert(response, challenge, credential))).toBe("asserted");
	});

	it("refuses another handle, a changed backup eligibility, and an unverified user when required", async () => {
		const { authenticator, credential } = await made();
		const { options, challenge } = request("required");
		const get = (twist = {}) => authenticator.get(options, at, twist);
		expect(reasonOf(await assert(get({ userHandle: "other" }), challenge, credential))).toBe(
			"user-handle",
		);
		const eligible = { ...credential, backupEligible: true };
		expect(reasonOf(await assert(get(), challenge, eligible))).toBe("backup-eligibility");
		const unverified = await made(softwareAuthenticator({ userVerified: false }));
		const response = unverified.authenticator.get(options, at, { overlook: true });
		expect(reasonOf(await assert(response, challenge, unverified.credential, "required"))).toBe(
			"user-verification",
		);
	});

	it("refuses another origin, relying party, challenge, credential, or a frame not listed", async () => {
		const { authenticator, credential } = await made();
		const { credential: other } = await made();
		const { options, challenge } = request();
		const judge = (response: unknown, expected = challenge, by = credential) =>
			assert(response, expected, by).then(reasonOf);
		expect(await judge(authenticator.get(options, evil, { overlook: true }))).toBe("origin");
		expect(await judge(authenticator.get(options, at, { rpId: "evil.example" }))).toBe("rp");
		expect(await judge(authenticator.get(options, at), "other")).toBe("challenge");
		expect(await judge(authenticator.get(options, at), challenge, other)).toBe("malformed");
		const framed = { ...at, crossOrigin: true, topOrigin: "https://evil.example" };
		expect(await judge(authenticator.get(options, framed))).toBe("top-origin");
		const listed = { ...at, crossOrigin: true, topOrigin: "https://shell.example" };
		expect(await judge(authenticator.get(options, listed))).toBe("asserted");
	});
});

describe("the challenge's end", () => {
	afterEach(() => {
		now = start;
	});

	it("answers when a challenge ends, its lifetime after it was made, on the clock", () => {
		expect(ceremonies.creation({ handle, name: "sam" }, [], "preferred").until).toBe(now + 120_000);
		expect(ceremonies.request([], "preferred").until).toBe(now + 120_000);
	});

	it("refuses an answer at or past the end it is given as `challenge`, and takes one before it", async () => {
		const { authenticator, credential } = await made();
		const asked = request();
		const creating = creation();
		const assertAt = (moment: number) => {
			now = moment;
			const response = authenticator.get(asked.options, at);
			return ceremonies
				.assert(response, asked.challenge, credential, "preferred", asked.until)
				.then(reasonOf);
		};
		const attestAt = (moment: number) => {
			now = moment;
			const response = softwareAuthenticator().create(creating.options, at);
			return ceremonies
				.attest(response, creating.challenge, handle, "preferred", creating.until)
				.then(reasonOf);
		};
		expect(await assertAt(asked.until)).toBe("challenge");
		expect(await assertAt(asked.until + 1)).toBe("challenge");
		expect(await attestAt(creating.until)).toBe("challenge");
		expect(await assertAt(asked.until - 1)).toBe("asserted");
		expect(await attestAt(creating.until - 1)).toBe("attested");
	});

	it("judges no end when none is given, leaving the lifetime to the caller", async () => {
		const { authenticator, credential } = await made();
		const { options, challenge } = request();
		now += 3_600_000;
		const asserted = await ceremonies.assert(
			authenticator.get(options, at),
			challenge,
			credential,
			"preferred",
		);
		expect(reasonOf(asserted)).toBe("asserted");
	});
});
