import { mkdtemp, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { selfSigned } from "@mod/conformance-front";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { converse } from "../../dialog/dialog.ts";
import { libraryNamed } from "../libraries.ts";

let server: Server;
let origin = "";
let theirs = { key: "", cert: "" };
let other = "";
let otherFile = "";

beforeAll(async () => {
	const dir = await mkdtemp(join(tmpdir(), "interop-trust-"));
	theirs = await selfSigned("127.0.0.1", join(dir, "server"));
	other = (await selfSigned("127.0.0.1", join(dir, "other"))).cert;
	otherFile = join(dir, "server-cert.pem");
	await writeFile(otherFile, theirs.cert);
	server = createServer({ key: theirs.key, cert: theirs.cert }, (_, res) => {
		res.writeHead(404);
		res.end();
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	origin = `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(async () => {
	await new Promise((resolve) => server?.close(resolve));
});

/** The adapter's error on a sign-in at the server, trusting `ca` as its instruction says. */
async function errorTrusting(ca: string) {
	const library = libraryNamed("openid-client");
	const command = library.adapter();
	// The process's environment adds the server's certificate: the adapter must not take it from there.
	const dialog = await converse(
		{ ...command, env: { ...command.env, NODE_EXTRA_CA_CERTS: otherFile } },
		{
			flow: "login",
			issuer: origin,
			ca,
			client: { id: "c", method: "none" },
			redirectUri: "https://rp.example/cb",
		},
		async () => ({}),
		30_000,
	);
	return dialog.outcome.kind === "error" ? dialog.outcome.message : "";
}

describe("the openid-client adapter's trust", () => {
	it("refuses a server whose certificate the instruction does not name, whatever else would trust it", async () => {
		expect(await errorTrusting(other)).toMatch(/certificate|self.signed|unable to verify/i);
	});

	it("reaches a server whose certificate the instruction names", async () => {
		const told = await errorTrusting(theirs.cert);
		expect(told).not.toMatch(/certificate|self.signed|unable to verify/i);
		expect(told).toMatch(/404/);
	});
});
