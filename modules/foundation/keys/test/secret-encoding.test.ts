import { createHmac, randomBytes } from "node:crypto";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { assemble, BootRefused, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { describe, expect, it } from "vitest";
import { keys } from "../src/contract.ts";
import keysModule from "../src/module.ts";
import { section } from "../src/signing/section.ts";

const runtime = quietRuntime();
const signing = (secret: string, encoding?: string) => ({
	signing: {
		kid: "h",
		alg: "HS256",
		secret,
		...(encoding === undefined ? {} : { "secret-encoding": encoding }),
	},
});

/** The key the provider signs with, as the bytes whose HMAC its signature is. */
async function signsWith(secret: string, encoding?: string): Promise<(key: Buffer) => boolean> {
	const app = await assemble({
		modules: [http, keysModule],
		config: { ...kernelConfig(), ...httpConfig(), keys: signing(secret, encoding) },
		runtime,
	});
	const token = await app.get(keys).sign({ sub: "a" }, "JWT");
	const [header, payload, signature] = token.split(".");
	return (key) =>
		createHmac("sha256", key).update(`${header}.${payload}`).digest("base64url") === signature;
}

/** Why the section refuses the secret under the encoding, at its path, or nothing. */
const refusal = (secret: string, encoding?: string) => {
	const read = section.safeParse(signing(secret, encoding));
	return read.success ? undefined : read.error.issues.map((i) => i.message).join("; ");
};

describe("keys.signing.secret-encoding", () => {
	// 64 hex digits: whole bytes of hex, strict base64 and text alike, so each reading differs.
	const secret = randomBytes(32).toString("hex");

	it("reads one value as hex, base64 or its own UTF-8 bytes, as named, and as today where none is", async () => {
		const asHex = Buffer.from(secret, "hex");
		const asBase64 = Buffer.from(secret, "base64");
		const asText = Buffer.from(secret, "utf8");
		expect((await signsWith(secret, "hex"))(asHex)).toBe(true);
		expect((await signsWith(secret, "base64"))(asBase64)).toBe(true);
		const text = await signsWith(secret, "utf8");
		expect([text(asText), text(asHex)]).toEqual([true, false]);
		// None named: hex where the value is whole bytes of hex, as before.
		expect((await signsWith(secret))(asHex)).toBe(true);
	});

	it("takes text as its own UTF-8 bytes, as 0.17 and policy-verifier read it", async () => {
		const phrase = "correct horse battery staple, and a little more for 32";
		expect((await signsWith(phrase, "utf8"))(Buffer.from(phrase, "utf8"))).toBe(true);
	});

	it("takes no other reading than the one named", () => {
		expect(refusal(randomBytes(32).toString("base64"), "hex")).toBe("not hex");
		expect(refusal(`${randomBytes(32).toString("base64")}!`, "base64")).toBe("not base64");
		expect(refusal("correct horse battery staple, and a little more", "base64")).toBe("not base64");
	});

	it("holds every reading to the same strength, on the bytes it reads, never naming the value", () => {
		for (const [value, encoding] of [
			["short but varied text", "utf8"],
			["a".repeat(40), "utf8"],
			["ab".repeat(32), "hex"],
			[randomBytes(31).toString("base64"), "base64"],
			["REPLACE-HMAC-SECRET-32-BYTES-OR-MORE-PLEASE", "utf8"],
		] as const) {
			const said = refusal(value, encoding);
			expect(said, `${encoding} ${value}`).toBeDefined();
			expect(said, value).not.toContain(value);
		}
		expect(refusal("correct horse battery staple, and a little more", "utf8")).toBeUndefined();
	});

	it("refuses a reading it does not know, at its key", async () => {
		expect(refusal(secret, "latin1")).toBeDefined();
		const refused = await assemble({
			modules: [http, keysModule],
			config: { ...kernelConfig(), ...httpConfig(), keys: signing(secret, "utf16") },
			runtime,
		}).catch((error: unknown) => error);
		expect(refused).toBeInstanceOf(BootRefused);
		expect((refused as BootRefused).refusals.map((r) => r.where)).toEqual([
			"keys.signing.secret-encoding",
		]);
	});
});
