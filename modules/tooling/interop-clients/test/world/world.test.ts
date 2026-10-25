import { mkdtempSync, readdirSync } from "node:fs";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AreaScene } from "@mod/conformance";
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

describe("the world", () => {
	it("closes its front and removes its files where the app does not start", async () => {
		const under = mkdtempSync(join(tmpdir(), "interop-world-"));
		let issuer = "";
		const failing = async (scene: AreaScene) => {
			issuer = String((scene.parts.oauth as { issuer: string }).issuer);
			throw new Error("the app could not be generated");
		};
		await expect(startWorld({ start: failing, under })).rejects.toThrow(
			"the app could not be generated",
		);
		expect(issuer).toMatch(/^https:\/\/127\.0\.0\.1:\d+$/);
		expect(await listening(Number(new URL(issuer).port))).toBe(false);
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
