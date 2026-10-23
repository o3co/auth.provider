import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { served } from "../serve.ts";

/** A directory holding one tarball of a package, as pnpm packs one. */
function tarballs(): string {
	const at = mkdtempSync(join(tmpdir(), "registry-"));
	mkdirSync(join(at, "package"));
	writeFileSync(
		join(at, "package", "package.json"),
		JSON.stringify({ name: "@x/held", version: "1.0.0" }),
	);
	const dir = join(at, "tarballs");
	mkdirSync(dir);
	execFileSync("tar", ["-czf", join(dir, "x-held-1.0.0.tgz"), "package"], { cwd: at });
	return dir;
}

it("serves its own packages, answers 502 where the upstream fails, and stays up", async () => {
	// No server listens on port 9 here: every upstream request fails.
	const registry = await served("http://127.0.0.1:9/", [tarballs()]);
	try {
		const own = await fetch(`${registry.origin}/@x%2fheld`);
		expect(own.status).toBe(200);
		expect(((await own.json()) as { versions: object }).versions).toHaveProperty("1.0.0");
		for (let i = 0; i < 2; i++) {
			expect((await fetch(`${registry.origin}/left-pad`)).status).toBe(502);
		}
		expect((await fetch(`${registry.origin}/@x%2fheld`)).status).toBe(200);
	} finally {
		await registry.stop();
	}
});

it("refuses to start where the registry cannot", async () => {
	await expect(served("http://127.0.0.1:9/", ["/no/such/directory"])).rejects.toThrow(
		/the registry exited/,
	);
});
