import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { sceneOf } from "../src/areas.ts";
import { started, trustedEnv } from "../src/drivers/app.ts";

/** Two self-signed certificates, made for these tests alone. */
const fixture = (name: string) => join(import.meta.dirname, "fixtures", `${name}.pem`);
const scratch = () => mkdtemp(join(tmpdir(), "trusted-"));

describe("the certificates a started app trusts besides the system's", () => {
	it("gives the app nothing where none are named", async () => {
		const dir = await scratch();
		expect(await trustedEnv(undefined, dir)).toEqual({});
		expect(await trustedEnv([], dir)).toEqual({});
	});

	it("gives every named file to the app as one bundle, by NODE_EXTRA_CA_CERTS alone", async () => {
		const dir = await scratch();
		const suite = (await readFile(fixture("suite"), "utf8")).trimEnd();
		const proxy = await readFile(fixture("proxy"), "utf8");
		// A file with no newline at its end still leaves the next certificate on a line of its own.
		const unterminated = join(dir, "suite.pem");
		await writeFile(unterminated, suite);
		const env = await trustedEnv([unterminated, fixture("proxy")], dir);
		expect(Object.keys(env)).toEqual(["NODE_EXTRA_CA_CERTS"]);
		const bundle = await readFile(env.NODE_EXTRA_CA_CERTS as string, "utf8");
		expect(bundle).toBe(`${suite}\n${proxy}`);
	});

	it("takes a file holding several certificates", async () => {
		const dir = await scratch();
		const both = join(dir, "both.pem");
		await writeFile(
			both,
			`${await readFile(fixture("suite"), "utf8")}${await readFile(fixture("proxy"), "utf8")}`,
		);
		expect(Object.keys(await trustedEnv([both], dir))).toEqual(["NODE_EXTRA_CA_CERTS"]);
	});

	it("refuses a file it cannot read, naming it, before the app starts", async () => {
		const dir = await scratch();
		const missing = join(dir, "missing.pem");
		await expect(trustedEnv([missing], dir)).rejects.toThrow(missing);
	});

	it("refuses a file that holds no certificate, or a PEM block that is no X.509 certificate", async () => {
		const dir = await scratch();
		const none = join(dir, "none.pem");
		await writeFile(none, "not a certificate\n");
		const malformed = join(dir, "malformed.pem");
		await writeFile(
			malformed,
			"-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n",
		);
		// One good certificate does not carry a broken one beside it.
		const mixed = join(dir, "mixed.pem");
		await writeFile(
			mixed,
			`${await readFile(fixture("suite"), "utf8")}${await readFile(malformed, "utf8")}`,
		);
		for (const file of [none, malformed, mixed]) {
			await expect(trustedEnv([file], dir)).rejects.toThrow(file);
		}
	});

	it("stops the parties started for the app when its certificates are refused", async () => {
		let stopped = 0;
		const party = { base: "http://127.0.0.1:1", config: {}, stop: async () => void stopped++ };
		await expect(
			started(
				await scratch(),
				{},
				sceneOf(),
				undefined,
				{ leave: [], parties: [party, party] },
				[],
				{ trustedCertificates: [join(await scratch(), "missing.pem")] },
			),
		).rejects.toThrow("missing.pem");
		expect(stopped).toBe(2);
	});
});
