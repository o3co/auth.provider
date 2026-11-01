import { mkdtempSync, readdirSync } from "node:fs";
import { createServer } from "node:http";
import { type AddressInfo, connect, createServer as createListener } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AreaScene, Started } from "@mod/conformance";
import { describe, expect, it } from "vitest";
import { authorizationQuery, startWorld } from "./world.ts";

/** Whether anything listens at the port. */
const listening = (port: number) =>
	new Promise<boolean>((resolve) => {
		const socket = connect(port, "127.0.0.1");
		socket.once("connect", () => {
			socket.destroy();
			resolve(true);
		});
		socket.once("error", () => resolve(false));
	});

/** Whether a listener of another can take the port, as another test's port-0 listener on the runner might. */
const bindable = (port: number) =>
	new Promise<boolean>((resolve) => {
		const other = createListener();
		other.once("error", () => resolve(false));
		other.listen(port, "127.0.0.1", () => other.close(() => resolve(true)));
	});

/** An app that starts at once, serving nothing the world reaches. */
const running = async (): Promise<Started> => ({
	kind: "running",
	baseUrl: "http://127.0.0.1:9",
	stop: async () => {},
});

/** Runs `run` with the system's temporary directory at a fresh one, which it answers with. */
async function withTmpdir<T>(run: (tmp: string) => Promise<T>): Promise<T> {
	const tmp = mkdtempSync(join(tmpdir(), "interop-tmp-"));
	const before = process.env.TMPDIR;
	process.env.TMPDIR = tmp;
	try {
		return await run(tmp);
	} finally {
		if (before === undefined) delete process.env.TMPDIR;
		else process.env.TMPDIR = before;
	}
}

describe("the world", () => {
	it("closes its front and removes its files where the app does not start", async () => {
		const under = mkdtempSync(join(tmpdir(), "interop-world-"));
		let issuer = "";
		let backchannelPort = 0;
		const failing = async (scene: AreaScene) => {
			issuer = String((scene.parts.oauth as { issuer: string }).issuer);
			// The receiver the `backchannel` client is registered with.
			const [, port] = /http:\/\/127\.0\.0\.1:(\d+)\/backchannel/.exec(JSON.stringify(scene)) ?? [];
			backchannelPort = Number(port);
			throw new Error("the app could not be generated");
		};
		await withTmpdir(async (tmp) => {
			await expect(startWorld({ start: failing, under })).rejects.toThrow(
				"the app could not be generated",
			);
			// Nothing is left beside `under` either, such as the client certificate's files.
			expect(readdirSync(tmp)).toEqual([]);
		});
		expect(issuer).toMatch(/^https:\/\/127\.0\.0\.1:\d+$/);
		expect(await listening(Number(new URL(issuer).port))).toBe(false);
		expect(await listening(backchannelPort)).toBe(false);
		expect(readdirSync(under)).toEqual([]);
	});

	it("keeps no file but its front's and the metadata document's while it runs, and none once stopped", async () => {
		const under = mkdtempSync(join(tmpdir(), "interop-world-"));
		await withTmpdir(async (tmp) => {
			const world = await startWorld({ start: running, under });
			try {
				expect(readdirSync(tmp)).toEqual([]);
				expect(
					readdirSync(under)
						.map((d) => d.replace(/-[^-]+$/, ""))
						.sort(),
				).toEqual(["interop-clients", "interop-documents"]);
			} finally {
				await world.stop();
			}
			expect(readdirSync(tmp)).toEqual([]);
		});
		expect(readdirSync(under)).toEqual([]);
	});

	it("holds the back-channel receiver's port from its build to its stop, so nothing else binds it meanwhile", async () => {
		const world = await startWorld({ start: running });
		const { port } = world.backchannel;
		try {
			expect(await listening(port)).toBe(true);
			expect(await bindable(port)).toBe(false);
		} finally {
			await world.stop();
		}
		expect(await listening(port)).toBe(false);
	});

	it("relays a logout token the provider posts to the receiver an adapter names, on the path it is told", async () => {
		const world = await startWorld({ start: running });
		const posted: { path: string | undefined; type: string | undefined; body: string }[] = [];
		const adapter = createServer(async (req, res) => {
			const chunks: Buffer[] = [];
			for await (const chunk of req) chunks.push(chunk as Buffer);
			posted.push({
				path: req.url,
				type: req.headers["content-type"],
				body: Buffer.concat(chunks).toString(),
			});
			res.writeHead(200).end();
		});
		await new Promise<void>((resolve) => adapter.listen(0, "127.0.0.1", resolve));
		const at = `http://127.0.0.1:${(adapter.address() as AddressInfo).port}`;
		try {
			const { port, path } = world.backchannel;
			for (const wrong of [
				`https://127.0.0.1:1${path}`,
				`http://other.example:1${path}`,
				`${at}/elsewhere`,
				`${at}${path}?q=1`,
			])
				expect(() => world.backchannel.relayTo(wrong), wrong).toThrow("not a receiver at loopback");
			world.backchannel.relayTo(`${at}${path}`);
			const answer = await fetch(`http://127.0.0.1:${port}${path}`, {
				method: "POST",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				body: "logout_token=a.b.c",
			});
			expect(answer.status).toBe(200);
			expect(posted).toEqual([
				{ path, type: "application/x-www-form-urlencoded", body: "logout_token=a.b.c" },
			]);
		} finally {
			await world.stop();
			await new Promise((resolve) => adapter.close(resolve));
		}
	});

	it("follows an authorization URL only to the provider's authorization endpoint, giving its query", () => {
		const issuer = "https://127.0.0.1:8443";
		expect(authorizationQuery(`${issuer}/oauth/authorize?client_id=c&state=s`, issuer)).toBe(
			"client_id=c&state=s",
		);
		for (const wrong of [
			"http://127.0.0.1:8443/oauth/authorize?client_id=c",
			"https://127.0.0.1:9443/oauth/authorize?client_id=c",
			"https://other.example/oauth/authorize?client_id=c",
			`${issuer}/authorize?client_id=c`,
		])
			expect(() => authorizationQuery(wrong, issuer), wrong).toThrow(
				"not the provider's authorization endpoint",
			);
	});
});
