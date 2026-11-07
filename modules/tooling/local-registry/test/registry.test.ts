import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { localRegistry } from "../src/contract.ts";

/** A directory holding one tarball of a version of `@x/held`, as pnpm packs one. */
function tarballs(version = "1.0.0"): string {
	const at = mkdtempSync(join(tmpdir(), "registry-"));
	mkdirSync(join(at, "package"));
	writeFileSync(join(at, "package", "package.json"), JSON.stringify({ name: "@x/held", version }));
	const dir = join(at, "tarballs");
	mkdirSync(dir);
	execFileSync("tar", ["-czf", join(dir, `x-held-${version}.tgz`), "package"], { cwd: at });
	return dir;
}

/** One directory of tarballs, published now. */
const now = (dir: string) => [{ dir, at: new Date() }];

it("serves its own packages, answers 502 where the upstream fails, and stays up", async () => {
	// No server listens on port 9 here: every upstream request fails.
	const registry = await localRegistry({
		published: now(tarballs()),
		upstream: "http://127.0.0.1:9/",
	});
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

it("stamps each version with when its directory was published, the document with the earliest and latest", async () => {
	const earlier = new Date("2026-01-02T03:04:05.000Z");
	const later = new Date("2026-03-04T05:06:07.000Z");
	const registry = await localRegistry({
		published: [
			{ dir: tarballs("2.0.0"), at: later },
			{ dir: tarballs("1.0.0"), at: earlier },
		],
		upstream: "http://127.0.0.1:9/",
	});
	try {
		const answer = await fetch(`${registry.origin}/@x%2fheld`);
		const { time } = (await answer.json()) as { time: Record<string, string> };
		expect(time).toEqual({
			created: earlier.toISOString(),
			modified: later.toISOString(),
			"1.0.0": earlier.toISOString(),
			"2.0.0": later.toISOString(),
		});
	} finally {
		await registry.stop();
	}
});

/** An upstream of the test's own, listening on a free port: its origin and how to close it. */
async function upstreamOf(handle: Parameters<typeof createServer>[1]) {
	const server: Server = createServer(handle);
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const { port } = server.address() as { port: number };
	return {
		origin: `http://127.0.0.1:${port}/`,
		close: () => {
			server.closeAllConnections();
			return new Promise<void>((resolve) => server.close(() => resolve()));
		},
	};
}

it("answers 502 where the upstream's body breaks off or it answers too late, and stays up", async () => {
	const upstream = await upstreamOf((request, response) => {
		if (request.url === "/broken") {
			// The head is sent and the body promised, then the connection is cut.
			response.writeHead(200, { "content-type": "application/json", "content-length": "100" });
			response.write("{");
			response.socket?.destroy();
		}
		// Any other name is never answered.
	});
	const registry = await localRegistry({
		published: now(tarballs()),
		upstream: upstream.origin,
		limits: { upstreamMs: 500 },
	});
	try {
		expect((await fetch(`${registry.origin}/broken`)).status).toBe(502);
		expect((await fetch(`${registry.origin}/slow`)).status).toBe(502);
		expect((await fetch(`${registry.origin}/@x%2fheld`)).status).toBe(200);
	} finally {
		await registry.stop();
		await upstream.close();
	}
});

it("refuses to start where the registry cannot", async () => {
	await expect(
		localRegistry({ published: now("/no/such/directory"), upstream: "http://127.0.0.1:9/" }),
	).rejects.toThrow(/the registry exited/);
});

it("answers any other name from the upstream under its path, written with or without a trailing slash", async () => {
	const upstream = await upstreamOf((request, response) => {
		response.writeHead(request.url === "/npm/left-pad" ? 200 : 404, {
			"content-type": "application/json",
		});
		response.end(JSON.stringify({ name: "left-pad" }));
	});
	try {
		for (const address of [`${upstream.origin}npm/`, `${upstream.origin}npm`]) {
			const registry = await localRegistry({ published: now(tarballs()), upstream: address });
			try {
				const answer = await fetch(`${registry.origin}/left-pad`);
				expect(answer.status).toBe(200);
				expect(await answer.json()).toEqual({ name: "left-pad" });
			} finally {
				await registry.stop();
			}
		}
	} finally {
		await upstream.close();
	}
});
