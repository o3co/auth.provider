import { randomBytes } from "node:crypto";
import { decodeAttestationObject, isoBase64URL, isoCBOR } from "@simplewebauthn/server/helpers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { algorithmNames, ceremoniesFor } from "../src/ceremony/ceremony.ts";
import {
	type CreationOptions,
	softwareAuthenticator,
	statingCertificate,
	testOrigin,
} from "../src/testing.ts";

const rp = {
	id: "rp.example",
	name: "RP",
	origins: [testOrigin],
	topOrigins: [],
	timeoutMs: 120_000,
	algorithms: algorithmNames,
};
const ceremonies = ceremoniesFor(rp, (n) => new Uint8Array(randomBytes(n)), Date.now);
const handle = randomBytes(32).toString("base64url");
const at = { origin: testOrigin };

/** Whatever a statement names, nothing is fetched. */
const fetched: string[] = [];
beforeEach(() => {
	fetched.length = 0;
	vi.stubGlobal("fetch", async (url: unknown) => {
		fetched.push(String(url));
		throw new Error("nothing is fetched at an attestation");
	});
});
afterEach(() => {
	vi.unstubAllGlobals();
	expect(fetched).toEqual([]);
});

/** The formats the library knows, and one it does not. */
const formats = [
	"none",
	"packed",
	"fido-u2f",
	"android-key",
	"android-safetynet",
	"tpm",
	"apple",
	"made-up",
];

/** An authenticator's response to fresh options, and the challenge they carry. */
function answered(v: "required" | "preferred" = "preferred") {
	const { options, challenge } = ceremonies.creation({ handle, name: "sam" }, [], v);
	const response = softwareAuthenticator().create(options as CreationOptions, at);
	return { response, challenge };
}
type Answered = ReturnType<typeof answered>["response"];

/** The response with its attestation object made anew from its authenticator data. */
function remade(response: Answered, object: (authData: Uint8Array) => Uint8Array): Answered {
	const decoded = decodeAttestationObject(
		isoBase64URL.toBuffer(response.response.attestationObject),
	);
	const attestationObject = isoBase64URL.fromBuffer(
		new Uint8Array(object(decoded.get("authData"))),
	);
	return { ...response, response: { ...response.response, attestationObject } };
}
const attest = (response: unknown, challenge: string) =>
	ceremonies.attest(response, challenge, handle, "preferred");

const malformed = { kind: "refused", reason: "malformed" };

describe("the statement a registration response sends", () => {
	it.each(formats)("is dropped for %s with a certificate, attesting with no fetch", async (fmt) => {
		const { response, challenge } = answered();
		expect(await attest(remade(response, statingCertificate(fmt)), challenge)).toMatchObject({
			kind: "attested",
		});
	});

	it.each(formats)("leaves the authenticator data's credential unchanged for %s", async (fmt) => {
		const { response, challenge } = answered();
		const plain = await attest(response, challenge);
		expect(plain.kind).toBe("attested");
		expect(await attest(remade(response, statingCertificate(fmt)), challenge)).toEqual(plain);
	});

	it("is no way past what the authenticator data and the client data must meet", async () => {
		const stated = { attestationObject: statingCertificate("apple") };
		const options = () => ceremonies.creation({ handle, name: "sam" }, [], "required");
		const { options: asked, challenge: first } = options();
		const otherParty = softwareAuthenticator().create(asked as CreationOptions, at, {
			...stated,
			rpId: "other.example",
		});
		expect(await ceremonies.attest(otherParty, first, handle, "required")).toEqual({
			kind: "refused",
			reason: "rp",
		});
		expect(await ceremonies.attest(otherParty, options().challenge, handle, "required")).toEqual({
			kind: "refused",
			reason: "challenge",
		});
		const { options: unasked, challenge } = options();
		const unverified = softwareAuthenticator({ userVerified: false }).create(
			unasked as CreationOptions,
			at,
			{ ...stated, overlook: true },
		);
		expect(await ceremonies.attest(unverified, challenge, handle, "required")).toEqual({
			kind: "refused",
			reason: "user-verification",
		});
		const { options: elsewhere, challenge: its } = options();
		const fromElsewhere = softwareAuthenticator().create(
			elsewhere as CreationOptions,
			{ origin: "https://evil.example" },
			{ ...stated, overlook: true },
		);
		expect(await ceremonies.attest(fromElsewhere, its, handle, "required")).toEqual({
			kind: "refused",
			reason: "origin",
		});
	});

	it("takes an object with no format and no statement, as neither is read", async () => {
		const { response, challenge } = answered();
		const bare = remade(response, (authData) => isoCBOR.encode(new Map([["authData", authData]])));
		expect(await attest(bare, challenge)).toEqual(await attest(response, challenge));
	});
});

describe("the attestation object, as it was read before", () => {
	/** Its bytes as the library decodes them: a map of `fmt`, `attStmt` and `authData`, its head written here. */
	const mapOf = (pairs: readonly (readonly [string, Uint8Array])[]) =>
		Buffer.concat([
			Buffer.from([0xa0 | pairs.length]),
			...pairs.flatMap(([key, value]) => [isoCBOR.encode(key), value]),
		]);
	const bytes = (authData: Uint8Array) => isoCBOR.encode(authData);

	it("refuses a duplicate key as malformed, at the top and within the statement", async () => {
		const { response, challenge } = answered();
		const top = remade(response, (authData) =>
			mapOf([
				["fmt", isoCBOR.encode("none")],
				["fmt", isoCBOR.encode("packed")],
				["attStmt", isoCBOR.encode(new Map())],
				["authData", bytes(authData)],
			]),
		);
		expect(await attest(top, challenge)).toEqual(malformed);
		const within = remade(response, (authData) =>
			mapOf([
				["fmt", isoCBOR.encode("packed")],
				[
					"attStmt",
					Buffer.concat([
						Buffer.from([0xa2]),
						isoCBOR.encode("alg"),
						isoCBOR.encode(1),
						isoCBOR.encode("alg"),
						isoCBOR.encode(2),
					]),
				],
				["authData", bytes(authData)],
			]),
		);
		expect(await attest(within, challenge)).toEqual(malformed);
	});

	it("refuses a statement nested past what the decoder can follow as malformed", async () => {
		const { response, challenge } = answered();
		// One list inside another for as many levels as a request's 64 KiB can hold.
		const deep = Buffer.concat([Buffer.alloc(60_000, 0x81), Buffer.from([0x00])]);
		const nested = remade(response, (authData) =>
			mapOf([
				["fmt", isoCBOR.encode("packed")],
				["attStmt", deep],
				["authData", bytes(authData)],
			]),
		);
		expect(await attest(nested, challenge)).toEqual(malformed);
	});

	it("reads only the first item, leaving trailing bytes unread", async () => {
		const { response, challenge } = answered();
		const trailing = remade(response, (authData) =>
			Buffer.concat([
				isoCBOR.encode(
					new Map<string, Uint8Array | string | Map<string, string>>([
						["fmt", "none"],
						["attStmt", new Map()],
						["authData", authData],
					]),
				),
				Buffer.from([0xff, 0xff]),
			]),
		);
		expect(await attest(trailing, challenge)).toEqual(await attest(response, challenge));
	});

	it("refuses an object that is not a map as malformed", async () => {
		const { response, challenge } = answered();
		const sent: Record<string, Uint8Array> = {
			"a number": isoCBOR.encode(5),
			"a text": isoCBOR.encode("fmt"),
			bytes: isoCBOR.encode(new Uint8Array(40)),
			"a list": isoCBOR.encode([new Map([["authData", new Uint8Array(40)]])]),
			nothing: isoCBOR.encode(null),
			empty: new Uint8Array(),
			"a broken head": Buffer.from([0xa3, 0x61]),
		};
		for (const [name, object] of Object.entries(sent)) {
			expect(
				await attest(
					remade(response, () => object),
					challenge,
				),
				name,
			).toEqual(malformed);
		}
	});

	it("refuses authenticator data that is missing, short or not bytes as malformed", async () => {
		const { response, challenge } = answered();
		const sent: Record<string, unknown> = {
			short: new Uint8Array(36),
			"a text": "x".repeat(64),
			"a number": 5,
			"a map": new Map([["a", 1]]),
		};
		for (const [name, authData] of Object.entries(sent)) {
			const object = isoCBOR.encode(new Map([["authData", authData as Uint8Array]]));
			expect(
				await attest(
					remade(response, () => object),
					challenge,
				),
				name,
			).toEqual(malformed);
		}
		const none = isoCBOR.encode(new Map([["fmt", "none"]]));
		expect(
			await attest(
				remade(response, () => none),
				challenge,
			),
		).toEqual(malformed);
	});

	it("refuses an attestation object that is not a string as malformed", async () => {
		const { response, challenge } = answered();
		for (const attestationObject of [5, null, undefined, {}, ["a"]]) {
			const sent = { ...response, response: { ...response.response, attestationObject } };
			expect(await attest(sent, challenge), String(attestationObject)).toEqual(malformed);
		}
	});
});
