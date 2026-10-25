import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { type FactorKind, factorKinds } from "@mod/mfa-extensions";
import { expect, it } from "vitest";
import totpModule from "../src/module.ts";
import { base32, codeAt } from "../src/totp.ts";

/** The last millisecond of its step, so a step rounded instead of floored would be the next one. */
const now = 1_800_000_029_999;
const step = 60_000_000;
/** Every random byte is `a`, so an enrolled secret is known in advance. */
const runtime = quietRuntime({
	clock: { now: () => now },
	random: { bytes: (length) => new Uint8Array(length).fill(0x61) },
});
const kinds = contract<readonly FactorKind[]>("kinds");
const secret = base32(Buffer.alloc(20, 0x61));

const composition = (
	site: Parameters<typeof httpConfig>[0] = { "public-origin": "https://as.example" },
) => ({
	modules: [
		http,
		totpModule,
		defineModule({ name: "reader", takes: [factorKinds] }, (m) => [
			m.provide(kinds).by((c) => c.collect(factorKinds)),
		]),
	],
	config: { ...kernelConfig(), ...httpConfig(site) },
	runtime,
});

async function boot(
	site: Parameters<typeof httpConfig>[0] = { "public-origin": "https://as.example" },
) {
	const app = await assemble(composition(site));
	return app.get(kinds)[0] as FactorKind;
}

it("matches RFC 6238's SHA-1 test vectors", () => {
	const rfc = base32(Buffer.from("12345678901234567890"));
	expect(codeAt(rfc, Math.floor(59 / 30))).toBe("287082");
	expect(codeAt(rfc, Math.floor(1111111109 / 30))).toBe("081804");
	expect(codeAt(rfc, Math.floor(2000000000 / 30))).toBe("279037");
});

it("writes base32 as RFC 4648 does, without padding", () => {
	expect(base32(Buffer.from(""))).toBe("");
	expect(base32(Buffer.from("f"))).toBe("MY");
	expect(base32(Buffer.from("fo"))).toBe("MZXQ");
	expect(base32(Buffer.from("foo"))).toBe("MZXW6");
	expect(base32(Buffer.from("foob"))).toBe("MZXW6YQ");
	expect(base32(Buffer.from("fooba"))).toBe("MZXW6YTB");
	expect(base32(Buffer.from("foobar"))).toBe("MZXW6YTBOI");
});

it("contributes the totp kind, which adds a second factor, can be guessed and counts", async () => {
	expect(await boot()).toMatchObject({
		kind: "totp",
		amr: ["otp"],
		addsSecondFactor: true,
		guessable: true,
		counts: true,
	});
});

it("enrols a 20-byte random secret and shows it with its otpauth URI", async () => {
	const enrolled = await (await boot()).enroll("alice", []);
	expect(enrolled).toEqual({
		secret,
		show: {
			secret,
			otpauth_uri: `otpauth://totp/as.example%3Aalice?secret=${secret}&issuer=as.example&algorithm=SHA1&digits=6&period=30`,
			algorithm: "SHA1",
			digits: 6,
			period: 30,
		},
	});
});

it("names the issuer by the public origin's host, port included", async () => {
	const enrolled = await (await boot({ "public-origin": "https://as.example:8443" })).enroll(
		"alice",
		[],
	);
	expect((enrolled as { show: { otpauth_uri: string } }).show.otpauth_uri).toBe(
		`otpauth://totp/as.example%3A8443%3Aalice?secret=${secret}&issuer=as.example%3A8443&algorithm=SHA1&digits=6&period=30`,
	);
});

it("names the issuer `auth` without a public origin", async () => {
	const enrolled = await (await boot({})).enroll("alice", []);
	expect((enrolled as { show: { otpauth_uri: string } }).show.otpauth_uri).toBe(
		`otpauth://totp/auth%3Aalice?secret=${secret}&issuer=auth&algorithm=SHA1&digits=6&period=30`,
	);
});

it("accepts the current step's code and keeps its step as the state", async () => {
	const totp = await boot();
	expect(await totp.verify(secret, null, codeAt(secret, step))).toEqual({
		kind: "valid",
		state: step,
	});
});

it("accepts the code of one step before or after", async () => {
	const totp = await boot();
	expect(await totp.verify(secret, null, codeAt(secret, step - 1))).toEqual({
		kind: "valid",
		state: step - 1,
	});
	expect(await totp.verify(secret, null, codeAt(secret, step + 1))).toEqual({
		kind: "valid",
		state: step + 1,
	});
});

it("refuses the code of two steps before or after as invalid", async () => {
	const totp = await boot();
	expect(await totp.verify(secret, null, codeAt(secret, step - 2))).toEqual({ kind: "invalid" });
	expect(await totp.verify(secret, null, codeAt(secret, step + 2))).toEqual({ kind: "invalid" });
});

it("refuses another secret's code, and a proof not of six digits, as invalid", async () => {
	const totp = await boot();
	const other = base32(Buffer.alloc(20, 0x62));
	expect(await totp.verify(secret, null, codeAt(other, step))).toEqual({ kind: "invalid" });
	expect(await totp.verify(secret, null, codeAt(secret, step).slice(1))).toEqual({
		kind: "invalid",
	});
	expect(await totp.verify(secret, null, `${codeAt(secret, step)}0`)).toEqual({ kind: "invalid" });
});

it("refuses a used step as replayed when it comes again", async () => {
	const totp = await boot();
	const first = await totp.verify(secret, null, codeAt(secret, step));
	if (first.kind !== "valid") throw new Error("the first use was refused");
	expect(await totp.verify(secret, first.state, codeAt(secret, step))).toEqual({
		kind: "replayed",
	});
});

it("refuses a step older than the last used as replayed", async () => {
	const totp = await boot();
	expect(await totp.verify(secret, step, codeAt(secret, step - 1))).toEqual({ kind: "replayed" });
});

it("accepts a step later than the last used", async () => {
	const totp = await boot();
	expect(await totp.verify(secret, step, codeAt(secret, step + 1))).toEqual({
		kind: "valid",
		state: step + 1,
	});
});

it("judges a wrong code as invalid, not replayed, whatever step was used", async () => {
	const totp = await boot();
	expect(await totp.verify(secret, step + 1, codeAt(secret, step + 2))).toEqual({
		kind: "invalid",
	});
});

it("takes all it names", async () => {
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused(composition()))["mfa-totp"]).toBeUndefined();
});
