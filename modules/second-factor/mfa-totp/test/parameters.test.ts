import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { assemble, contract, defineModule, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type FactorKind, factorKinds } from "@mod/mfa-extensions";
import { describe, expect, it } from "vitest";
import totpModule from "../src/module.ts";
import { section } from "../src/section.ts";
import { base32, codeAt, type Parameters, readSecret, unmarked } from "../src/totp.ts";

const now = 1_800_000_029_999;
const runtime = quietRuntime({
	clock: { now: () => now },
	random: { bytes: (length) => new Uint8Array(length).fill(0x61) },
});
const kinds = contract<readonly FactorKind[]>("kinds");

/** The totp kind under the section given. */
async function totpUnder(settings: Record<string, unknown> = {}) {
	const app = await assemble({
		modules: [
			http,
			totpModule,
			defineModule({ name: "reader", replicaSafe: true, takes: [factorKinds] }, (m) => [
				m.provide(kinds).by((c) => c.collect(factorKinds)),
			]),
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": "https://as.example" }),
			"mfa-totp": settings,
		},
		runtime,
	});
	return app.get(kinds)[0] as FactorKind;
}
const stepOf = (p: Parameters) => Math.floor(now / 1000 / p.periodSeconds);
/** What enrolling `subject` gives: a secret kept and what is shown. */
const enrol = async (totp: FactorKind, subject: string) => {
	const enrolled = await totp.enroll(subject, []);
	if ("kind" in enrolled) throw new Error("enrolment limited");
	return enrolled;
};

describe("a factor's parameters", () => {
	it("match RFC 6238's SHA-256 and SHA-512 test vectors, eight digits", () => {
		const sha256 = base32(Buffer.from("12345678901234567890123456789012"));
		const sha512 = base32(
			Buffer.from("1234567890123456789012345678901234567890123456789012345678901234"),
		);
		const at = (algorithm: Parameters["algorithm"]) => ({
			algorithm,
			digits: 8,
			periodSeconds: 30,
		});
		expect(codeAt(at("SHA256"), sha256, Math.floor(59 / 30))).toBe("46119246");
		expect(codeAt(at("SHA512"), sha512, Math.floor(59 / 30))).toBe("90693936");
		expect(codeAt(at("SHA256"), sha256, Math.floor(1111111109 / 30))).toBe("68084774");
		expect(codeAt(at("SHA512"), sha512, Math.floor(1111111109 / 30))).toBe("25091201");
	});

	it("keep a factor enrolled under the defaults as 0.19 kept it: no mark, 20 bytes", async () => {
		const enrolled = await enrol(await totpUnder(), "alice");
		expect(enrolled.secret).toBe(base32(Buffer.alloc(20, 0x61)));
		expect(enrolled.show).toMatchObject({ algorithm: "SHA1", digits: 6, period: 30 });
	});

	it("mark a secret enrolled under other parameters, as long as its HMAC's output, and take only its own codes", async () => {
		const totp = await totpUnder({ algorithm: "SHA256", digits: 8, period: "60s" });
		const enrolled = await enrol(totp, "alice");
		const plain = base32(Buffer.alloc(32, 0x61));
		expect(enrolled.secret).toBe(`SHA256:8:60:${plain}`);
		const uri = new URL(String((enrolled.show as { otpauth_uri: string }).otpauth_uri));
		expect(["secret", "algorithm", "digits", "period"].map((k) => uri.searchParams.get(k))).toEqual(
			[plain, "SHA256", "8", "60"],
		);
		const own: Parameters = { algorithm: "SHA256", digits: 8, periodSeconds: 60 };
		const step = stepOf(own);
		expect(await totp.verify(enrolled.secret, null, codeAt(own, plain, step))).toEqual({
			kind: "valid",
			state: step,
		});
		const sha1 = { ...unmarked, digits: 8 };
		expect(await totp.verify(enrolled.secret, null, codeAt(sha1, plain, step))).toEqual({
			kind: "invalid",
		});
		expect(await totp.verify(enrolled.secret, null, codeAt(own, plain, step).slice(2))).toEqual({
			kind: "invalid",
		});
		const sha512 = await enrol(await totpUnder({ algorithm: "SHA512" }), "bob");
		expect(sha512.secret).toBe(`SHA512:6:30:${base32(Buffer.alloc(64, 0x61))}`);
	});

	it("read an unmarked secret with 0.19's parameters, whatever the section says now", async () => {
		const totp = await totpUnder({ algorithm: "SHA512", digits: 8, period: "60s" });
		const secret = base32(Buffer.alloc(20, 0x61));
		const step = stepOf(unmarked);
		expect(await totp.verify(secret, null, codeAt(unmarked, secret, step))).toEqual({
			kind: "valid",
			state: step,
		});
	});

	it("answer unavailable for a mark that does not read, spending no attempt, never a verdict", async () => {
		const totp = await totpUnder();
		for (const kept of [
			"MD5:6:30:AAAA",
			"SHA1:9:30:AAAA",
			"SHA1:6:45:AAAA",
			"SHA1:6:30:",
			"a:b",
			"aaaa",
		]) {
			expect(readSecret(kept), kept).toBeUndefined();
			await expect(totp.verify(kept, null, "000000"), kept).rejects.toBeInstanceOf(Unavailable);
		}
	});

	it("take a code for the current step alone with drift-steps 0, and one either side with 1", async () => {
		const secret = base32(Buffer.alloc(20, 0x61));
		const step = stepOf(unmarked);
		const before = codeAt(unmarked, secret, step - 1);
		expect((await (await totpUnder({ "drift-steps": 0 })).verify(secret, null, before)).kind).toBe(
			"invalid",
		);
		expect((await (await totpUnder()).verify(secret, null, before)).kind).toBe("valid");
	});
});

it("reads the section as 0.19's values where unset, and takes each within its range alone", () => {
	expect(section.parse({})).toEqual({ algorithm: "SHA1", digits: 6, period: 30, "drift-steps": 1 });
	const takes = (settings: unknown) => section.safeParse(settings).success;
	for (const [settings, taken] of [
		[{ algorithm: "SHA256" }, true],
		[{ algorithm: "MD5" }, false],
		[{ digits: 8 }, true],
		[{ digits: 5 }, false],
		[{ digits: 9 }, false],
		[{ period: "60s" }, true],
		[{ period: "45s" }, false],
		[{ period: 30 }, false],
		[{ "drift-steps": 2 }, false],
	] as const) {
		expect(takes(settings), JSON.stringify(settings)).toBe(taken);
	}
});
