import { mkdtempSync, readdirSync } from "node:fs";
import { connect } from "node:net";
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
		const failing = async (scene: AreaScene) => {
			issuer = String((scene.parts.oauth as { issuer: string }).issuer);
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
		expect(readdirSync(under)).toEqual([]);
	});

	it("keeps no file but its front's while it runs, and none once stopped", async () => {
		const under = mkdtempSync(join(tmpdir(), "interop-world-"));
		const running = async (): Promise<Started> => ({
			kind: "running",
			baseUrl: "http://127.0.0.1:9",
			stop: async () => {},
		});
		await withTmpdir(async (tmp) => {
			const world = await startWorld({ start: running, under });
			try {
				expect(readdirSync(tmp)).toEqual([]);
				expect(readdirSync(under)).toHaveLength(1);
			} finally {
				await world.stop();
			}
			expect(readdirSync(tmp)).toEqual([]);
		});
		expect(readdirSync(under)).toEqual([]);
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
