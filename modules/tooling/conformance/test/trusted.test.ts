import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { trustedEnv } from "../src/drivers/app.ts";

const pem = (name: string) =>
	`-----BEGIN CERTIFICATE-----\n${Buffer.from(name).toString("base64")}\n-----END CERTIFICATE-----`;

describe("the certificates a started app trusts besides the system's", () => {
	it("gives the app nothing where none are named", async () => {
		const dir = await mkdtemp(join(tmpdir(), "trusted-"));
		expect(await trustedEnv(undefined, dir)).toEqual({});
		expect(await trustedEnv([], dir)).toEqual({});
	});

	it("gives every named file to the app as one bundle, by NODE_EXTRA_CA_CERTS alone", async () => {
		const dir = await mkdtemp(join(tmpdir(), "trusted-"));
		const suite = join(dir, "suite.pem");
		const proxy = join(dir, "proxy.pem");
		// A file with no newline at its end still leaves the next certificate on a line of its own.
		await writeFile(suite, pem("suite"));
		await writeFile(proxy, `${pem("proxy")}\n`);
		const env = await trustedEnv([suite, proxy], dir);
		expect(Object.keys(env)).toEqual(["NODE_EXTRA_CA_CERTS"]);
		const bundle = await readFile(env.NODE_EXTRA_CA_CERTS as string, "utf8");
		expect(bundle).toBe(`${pem("suite")}\n${pem("proxy")}\n`);
	});

	it("refuses a file it cannot read, naming it, before the app starts", async () => {
		const dir = await mkdtemp(join(tmpdir(), "trusted-"));
		const missing = join(dir, "missing.pem");
		await expect(trustedEnv([missing], dir)).rejects.toThrow(missing);
	});

	it("refuses a file that holds no certificate", async () => {
		const dir = await mkdtemp(join(tmpdir(), "trusted-"));
		const empty = join(dir, "empty.pem");
		await writeFile(empty, "not a certificate\n");
		await expect(trustedEnv([empty], dir)).rejects.toThrow(empty);
	});
});
