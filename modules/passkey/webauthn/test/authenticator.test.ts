import { createHash, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	type CreationOptions,
	type RequestOptions,
	softwareAuthenticator,
} from "../src/testing.ts";

const at = { origin: "https://login.rp.example" };
const handle = randomBytes(32).toString("base64url");
const creation = (more: Partial<CreationOptions> = {}): CreationOptions => ({
	rp: { id: "rp.example" },
	user: { id: handle },
	challenge: "c1",
	pubKeyCredParams: [-8, -7, -257].map((alg) => ({ alg, type: "public-key" })),
	authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
	...more,
});
const request = (more: Partial<RequestOptions> = {}): RequestOptions => ({
	challenge: "c2",
	rpId: "rp.example",
	...more,
});
const authData = (encoded: string) => Buffer.from(encoded, "base64url");
const nameOf = (call: () => unknown) => {
	try {
		call();
		return "answered";
	} catch (error) {
		return (error as Error).name;
	}
};

describe("creation, as a browser runs it", () => {
	it("makes a credential for the relying party, user and challenge the options name", () => {
		const made = softwareAuthenticator().create(creation(), at);
		const data = JSON.parse(Buffer.from(made.response.clientDataJSON, "base64url").toString());
		expect(data).toEqual({
			type: "webauthn.create",
			challenge: "c1",
			origin: at.origin,
			crossOrigin: false,
		});
		const rpHash = createHash("sha256").update("rp.example").digest();
		const attested = authData(made.response.attestationObject);
		expect(attested.includes(rpHash)).toBe(true);
	});

	it("refuses what a browser refuses", () => {
		const a = softwareAuthenticator({ userVerified: false, discoverable: false });
		const plain = softwareAuthenticator();
		const made = plain.create(creation(), at);
		expect(nameOf(() => plain.create(creation({ rp: { id: "evil.example" } }), at))).toBe(
			"SecurityError",
		);
		expect(nameOf(() => plain.create(creation({ rp: { id: "example" } }), at))).toBe(
			"SecurityError",
		);
		expect(nameOf(() => plain.create(creation({ user: { id: "" } }), at))).toBe("TypeError");
		const long = Buffer.alloc(65).toString("base64url");
		expect(nameOf(() => plain.create(creation({ user: { id: long } }), at))).toBe("TypeError");
		const others = [-8, -257].map((alg) => ({ alg, type: "public-key" }));
		expect(nameOf(() => plain.create(creation({ pubKeyCredParams: others }), at))).toBe(
			"NotSupportedError",
		);
		const excluded = creation({ excludeCredentials: [{ id: made.id, type: "public-key" }] });
		expect(nameOf(() => plain.create(excluded, at))).toBe("InvalidStateError");
		const required = { residentKey: "preferred", userVerification: "required" };
		expect(nameOf(() => a.create(creation({ authenticatorSelection: required }), at))).toBe(
			"NotAllowedError",
		);
		expect(nameOf(() => a.create(creation(), at))).toBe("NotAllowedError");
		expect(nameOf(() => a.create(creation(), at, { overlook: true }))).toBe("answered");
	});

	it("writes a credential id of more than 255 bytes with its full length", () => {
		const id = randomBytes(300).toString("base64url");
		const made = softwareAuthenticator().create(creation(), at, { credentialId: id });
		const attested = authData(made.response.attestationObject);
		const at0 = attested.indexOf(Buffer.from(id, "base64url"));
		expect(attested.readUInt16BE(at0 - 2)).toBe(300);
	});
});

describe("assertion, as a browser runs it", () => {
	it("answers with a discoverable credential when none is listed, and with a listed one otherwise", () => {
		const a = softwareAuthenticator();
		const first = a.create(creation(), at);
		const second = a.create(creation(), at);
		const found = a.get(request(), at);
		expect([found.id, found.response.userHandle]).toEqual([second.id, handle]);
		const listed = a.get(request({ allowCredentials: [{ id: first.id, type: "public-key" }] }), at);
		expect(listed.id).toBe(first.id);
		const count = authData(listed.response.authenticatorData).readUInt32BE(33);
		expect(count).toBe(1);
	});

	it("keeps no count when told, and carries the twists a refusal asks for", () => {
		const a = softwareAuthenticator({ countless: true });
		const made = a.create(creation(), at, { credentialId: "AAAA" });
		expect(made.id).toBe("AAAA");
		const plain = a.get(request(), at, { userHandle: null });
		expect(authData(plain.response.authenticatorData).readUInt32BE(33)).toBe(0);
		expect(plain.response).not.toHaveProperty("userHandle");
		const counted = a.get(request(), at, { counter: 7 });
		expect(authData(counted.response.authenticatorData).readUInt32BE(33)).toBe(7);
		const framed = a.get(request(), {
			...at,
			crossOrigin: true,
			topOrigin: "https://shell.example",
		});
		const data = JSON.parse(Buffer.from(framed.response.clientDataJSON, "base64url").toString());
		expect(data).toMatchObject({ crossOrigin: true, topOrigin: "https://shell.example" });
	});

	it("finds a credential that is not discoverable only when listed, and answers it with no user handle", () => {
		const key = softwareAuthenticator({ discoverable: false });
		const discouraged = { residentKey: "discouraged", userVerification: "preferred" };
		const made = key.create(creation({ authenticatorSelection: discouraged }), at);
		expect(nameOf(() => key.get(request(), at))).toBe("NotAllowedError");
		const listed = key.get(
			request({ allowCredentials: [{ id: made.id, type: "public-key" }] }),
			at,
		);
		expect(listed.response).not.toHaveProperty("userHandle");
	});

	it("refuses another relying party, or user verification it cannot give, unless told to overlook it", () => {
		const a = softwareAuthenticator({ userVerified: false });
		a.create(creation({ authenticatorSelection: { residentKey: "required" } }), at);
		expect(nameOf(() => a.get(request({ rpId: "evil.example" }), at))).toBe("SecurityError");
		expect(nameOf(() => a.get(request({ rpId: "login.rp.example" }), at))).toBe("NotAllowedError");
		expect(nameOf(() => a.get(request({ userVerification: "required" }), at))).toBe(
			"NotAllowedError",
		);
		const overlooked = a.get(request({ userVerification: "required" }), at, { overlook: true });
		expect(authData(overlooked.response.authenticatorData).readUInt8(32) & 4).toBe(0);
	});
});

describe("what the options and the page ask of the authenticator", () => {
	const flagsOf = (encoded: string) => authData(encoded).readUInt8(32);
	const uv = 4;

	it("verifies the user when asked or preferred, and not when discouraged", () => {
		const a = softwareAuthenticator();
		const asked = (userVerification: string) =>
			creation({ authenticatorSelection: { residentKey: "required", userVerification } });
		a.create(asked("preferred"), at);
		expect(
			flagsOf(a.get(request({ userVerification: "required" }), at).response.authenticatorData) & uv,
		).toBe(uv);
		expect(
			flagsOf(a.get(request({ userVerification: "discouraged" }), at).response.authenticatorData) &
				uv,
		).toBe(0);
		expect(flagsOf(a.get(request(), at).response.authenticatorData) & uv).toBe(uv);
	});

	it("names a top origin only in a cross-origin frame, which may also name none", () => {
		const a = softwareAuthenticator();
		a.create(creation(), at);
		const shell = "https://shell.example";
		expect(nameOf(() => a.get(request(), { ...at, topOrigin: shell }))).toBe("Error");
		expect(nameOf(() => a.get(request(), { ...at, crossOrigin: true, topOrigin: shell }))).toBe(
			"answered",
		);
		expect(nameOf(() => a.get(request(), { ...at, crossOrigin: true }))).toBe("answered");
		const told = a.get(request(), { ...at, topOrigin: shell }, { overlook: true });
		const data = JSON.parse(Buffer.from(told.response.clientDataJSON, "base64url").toString());
		expect(data).toMatchObject({ crossOrigin: false, topOrigin: shell });
	});
});
