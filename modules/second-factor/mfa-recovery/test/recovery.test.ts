import { assemble, contract, defineModule, kernelConfig, type Random } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type FactorKind, factorKinds } from "@mod/mfa-extensions";
import { expect, it } from "vitest";
import recoveryModule from "../src/module.ts";

const kinds = contract<readonly FactorKind[]>("kinds");

async function boot(random?: Random) {
	const app = await assemble({
		modules: [
			recoveryModule,
			defineModule({ name: "reader" }, (m) => [m.provide(kinds).by((c) => c.collect(factorKinds))]),
		],
		config: kernelConfig(),
		runtime: quietRuntime({ clock: { now: () => 0 }, ...(random ? { random } : {}) }),
	});
	return app.get(kinds)[0] as FactorKind;
}

async function enrolled(recovery: FactorKind) {
	const set = await recovery.enroll("s", []);
	if (!("secret" in set)) throw new Error("no secret enrolled");
	return { secret: set.secret, codes: set.show as string[] };
}

/** Verifies on a fresh boot: the kind keeps nothing between calls but the secret and state it is given. */
async function verify(secret: string, state: unknown, proof: string) {
	return (await boot()).verify(secret, state, proof);
}

it("is a way back: it adds mfa with amr recovery, cannot be guessed and does not count", async () => {
	expect(await boot()).toEqual(
		expect.objectContaining({
			kind: "recovery_code",
			amr: ["recovery"],
			addsSecondFactor: true,
			guessable: false,
			counts: false,
		}),
	);
});

it("issues ten codes of four groups of four", async () => {
	const { codes } = await enrolled(await boot());
	expect(codes).toHaveLength(10);
	for (const code of codes) expect(code).toMatch(/^[0-9A-Z]{4}(-[0-9A-Z]{4}){3}$/);
	expect(new Set(codes).size).toBe(10);
});

it("draws each character from five random bits of Crockford's base32", async () => {
	const bytes = Uint8Array.from({ length: 16 }, (_, i) => 16 + i);
	const { codes } = await enrolled(await boot({ bytes: () => bytes }));
	expect(codes[0]).toBe("GHJK-MNPQ-RSTV-WXYZ");
	// The high bits of a byte are dropped: 0xe0 reads as 0.
	const { codes: low } = await enrolled(await boot({ bytes: () => new Uint8Array(16).fill(0xe0) }));
	expect(low[0]).toBe("0000-0000-0000-0000");
});

it("keeps only the codes' digests", async () => {
	const { secret, codes } = await enrolled(await boot());
	for (const code of codes) expect(secret).not.toContain(code.replaceAll("-", ""));
});

it("reads a set as stored, so codes issued before an upgrade still work", async () => {
	// SHA-256 of the code without hyphens, base64url without padding, in a JSON array.
	const stored = JSON.stringify(["u-tJlJiZQAy_vAOcotImgMt-tOGjAbpAxmfRmJkGLwE"]);
	expect((await verify(stored, null, "GHJK-MNPQ-RSTV-WXYZ")).kind).toBe("valid");
});

it("issues a new set whatever the subject already holds", async () => {
	const recovery = await boot();
	const old = await enrolled(recovery);
	const held = [
		{ secret: old.secret, state: null },
		{ secret: "not a set", state: "broken" },
	];
	const next = await recovery.enroll("s", held);
	expect(next).toHaveProperty("secret");
	expect((next as { show: string[] }).show).not.toEqual(old.codes);
});

it("reads a code whatever its case and hyphens", async () => {
	const { secret, codes } = await enrolled(await boot());
	const code = codes[0] ?? "";
	expect((await verify(secret, null, code.toLowerCase().replaceAll("-", ""))).kind).toBe("valid");
	expect((await verify(secret, null, code.toLowerCase())).kind).toBe("valid");
});

it("accepts each code once, and refuses one used before as replayed", async () => {
	const { secret, codes } = await enrolled(await boot());
	const first = await verify(secret, null, codes[0] ?? "");
	if (first.kind !== "valid") throw new Error("first use refused");
	const second = await verify(secret, first.state, codes[1] ?? "");
	if (second.kind !== "valid") throw new Error("second use refused");
	expect(await verify(secret, first.state, codes[0] ?? "")).toEqual({ kind: "replayed" });
	expect(await verify(secret, second.state, codes[0] ?? "")).toEqual({ kind: "replayed" });
	expect(await verify(secret, second.state, codes[1] ?? "")).toEqual({ kind: "replayed" });
	expect((await verify(secret, second.state, codes[2] ?? "")).kind).toBe("valid");
});

it("tells how many codes are left after each use", async () => {
	const { secret, codes } = await enrolled(await boot());
	const first = await verify(secret, null, codes[0] ?? "");
	expect(first).toMatchObject({ kind: "valid", remaining: 9 });
	if (first.kind !== "valid") return;
	expect(await verify(secret, first.state, codes[1] ?? "")).toMatchObject({ remaining: 8 });
});

it("refuses a code not in the set as invalid, used ones included", async () => {
	const recovery = await boot();
	const { secret, codes } = await enrolled(recovery);
	const other = await enrolled(recovery);
	expect(await recovery.verify(secret, null, "0000-0000-0000-0000")).toEqual({ kind: "invalid" });
	expect(await recovery.verify(secret, null, other.codes[0] ?? "")).toEqual({ kind: "invalid" });
	const first = await recovery.verify(secret, null, codes[0] ?? "");
	const state = first.kind === "valid" ? first.state : null;
	expect(await recovery.verify(other.secret, state, codes[0] ?? "")).toEqual({ kind: "invalid" });
});
