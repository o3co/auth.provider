import { randomBytes } from "node:crypto";
import { assemble, BootRefused, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { seal } from "../src/contract.ts";
import sealModule from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 0 } });
const key = () => randomBytes(32).toString("base64");
const boot = async (keys: unknown) =>
	(
		await assemble({
			modules: [sealModule],
			config: { ...kernelConfig(), seal: { keys } },
			runtime,
		})
	).get(seal);

/** The text with its first character changed; a last one may hold only bits that decode to nothing. */
const altered = (text: string) => `${text.startsWith("A") ? "B" : "A"}${text.slice(1)}`;

it("opens what it sealed, only in the same context, and refuses anything altered", async () => {
	const s = await boot([{ id: "a", key: key() }]);
	expect(Object.isFrozen(s)).toBe(true);
	const sealed = s.seal("secret", "a/1");
	expect(sealed).not.toContain("secret");
	expect(s.seal("secret", "a/1")).not.toBe(sealed);
	expect(s.open(sealed, "a/1")).toEqual({ kind: "opened", plain: "secret" });
	expect(s.open(sealed, "b/1")).toEqual({ kind: "refused" });
	const [id = "", iv = "", body = "", tag = ""] = sealed.split(".");
	const spoiled = {
		body: `${id}.${iv}.${altered(body)}.${tag}`,
		iv: `${id}.${altered(iv)}.${body}.${tag}`,
		tag: `${id}.${iv}.${body}.${altered(tag)}`,
		"a short tag": `${id}.${iv}.${body}.${tag.slice(0, 16)}`,
		"a short iv": `${id}.${iv.slice(0, 12)}.${body}.${tag}`,
		"no seal": "not sealed",
	};
	for (const [name, value] of Object.entries(spoiled)) {
		expect(s.open(value, "a/1"), name).toEqual({ kind: "refused" });
	}
});

it("refuses a sealed value not written in its one form", async () => {
	const s = await boot([{ id: "a", key: key() }]);
	const sealed = s.seal("secret", "a/1");
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	// The tag's last character holds bits a decoder drops: the same tag, another string.
	const variant = `${sealed.slice(0, -1)}${alphabet[alphabet.indexOf(sealed.at(-1) as string) ^ 1]}`;
	expect(s.open(variant, "a/1")).toEqual({ kind: "refused" });
});

it("binds the key's id in, so a value moved under another id with the same key is refused", async () => {
	const bytes = key();
	const s = await boot([
		{ id: "a", key: bytes },
		{ id: "b", key: bytes },
	]);
	const sealed = s.seal("secret", "c");
	expect(s.open(sealed.replace(/^a\./, "b."), "c")).toEqual({ kind: "refused" });
});

it("seals with the first key, opens with any in the ring, and is unavailable for a key it lost", async () => {
	const old = { id: "old", key: key() };
	const fresh = { id: "new", key: key() };
	const sealedOld = (await boot([old])).seal("v", "c");
	const rotated = await boot([fresh, old]);
	expect(rotated.open(sealedOld, "c")).toEqual({ kind: "opened", plain: "v" });
	expect(rotated.seal("v", "c").startsWith("new.")).toBe(true);
	const withoutOld = await boot([fresh]);
	const thrown = (() => {
		try {
			withoutOld.open(sealedOld, "c");
		} catch (error) {
			return error;
		}
	})();
	expect(thrown).toBeInstanceOf(Unavailable);
	expect(JSON.stringify(thrown) + String(thrown)).not.toContain(sealedOld.split(".")[2]);
});

it("refuses to start without a key, with a key it cannot take, or with two keys named alike", async () => {
	const refused = {
		"no key": [],
		"a key of the wrong size": [{ id: "a", key: randomBytes(16).toString("base64") }],
		// Read leniently, this would still give 32 bytes.
		"a key that is no base64": [{ id: "a", key: key().replace(/^(.{10})/, "$1!") }],
		"an id with a dot": [{ id: "a.b", key: key() }],
		"an empty id": [{ id: "", key: key() }],
		"an id over 32 characters": [{ id: "a".repeat(33), key: key() }],
		"a key with more than an id and a key": [{ id: "a", key: key(), use: "x" }],
		"two keys named alike": [
			{ id: "a", key: key() },
			{ id: "a", key: key() },
		],
	};
	for (const [name, keys] of Object.entries(refused)) {
		await expect(boot(keys), name).rejects.toThrow(BootRefused);
	}
	await expect(boot([{ id: "a".repeat(32), key: key() }])).resolves.toBeDefined();
});

it("refuses to start with a key of all one byte, or of fewer than 8 byte values, wherever it sits in the ring", async () => {
	const bytes = (values: readonly number[]) =>
		Buffer.from(Array.from({ length: 32 }, (_, i) => values[i % values.length] ?? 0)).toString(
			"base64",
		);
	const weak = {
		"all zero": bytes([0]),
		"all one other byte": bytes([7]),
		"two byte values": bytes([0x5a, 0xa5]),
		"seven byte values": bytes([1, 2, 3, 4, 5, 6, 7]),
	};
	for (const [name, weakKey] of Object.entries(weak)) {
		await expect(boot([{ id: "a", key: weakKey }]), name).rejects.toThrow(BootRefused);
		const past = [
			{ id: "a", key: key() },
			{ id: "b", key: weakKey },
		];
		await expect(boot(past), `${name}, past`).rejects.toThrow(BootRefused);
	}
	await expect(boot([{ id: "a", key: bytes([1, 2, 3, 4, 5, 6, 7, 8]) }])).resolves.toBeDefined();
});
