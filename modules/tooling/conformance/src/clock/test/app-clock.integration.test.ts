import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { appClockEnv, appClockImage, appLibfaketimeIn } from "../clock.ts";

/** Serves one answer, reads its Date header, and times a one-second timer on the monotonic clock. */
const probe = `
import { createServer } from "node:http";
const server = createServer((_, res) => res.end()).listen(0, async () => {
	const res = await fetch("http://127.0.0.1:" + server.address().port + "/");
	const t0 = performance.now();
	await new Promise((resolve) => setTimeout(resolve, 1000));
	console.log(JSON.stringify({ now: Date.now(), header: Date.parse(res.headers.get("date")), timerMs: performance.now() - t0 }));
	server.close();
});`;

const image = appClockImage();
const library = appLibfaketimeIn(image);

/** The probe in a container, on a clock moved by `offset` (none for the real one), and the host's time around it. */
function run(offset?: string) {
	const env = offset
		? Object.entries(appClockEnv(offset, library)).flatMap(([k, v]) => ["-e", `${k}=${v}`])
		: [];
	const before = Date.now();
	const out = execFileSync("docker", [
		"run",
		"--rm",
		...env,
		image,
		"node",
		"--input-type=module",
		"-e",
		probe,
	]);
	const after = Date.now();
	return {
		before,
		after,
		...(JSON.parse(out.toString()) as { now: number; header: number; timerMs: number }),
	};
}

describe("an app on a moved clock (libfaketime on glibc Linux)", () => {
	it("moves Date and the Date header by the offset either way, its timers on real time", () => {
		for (const [offset, ms] of [
			["+2h", 7_200_000],
			["-30m", -1_800_000],
		] as const) {
			const r = run(offset);
			expect(r.now - ms, offset).toBeGreaterThanOrEqual(r.before);
			expect(r.now - ms, offset).toBeLessThanOrEqual(r.after);
			// The header has whole seconds, and Node caches it for up to a second.
			expect(r.header - ms, offset).toBeGreaterThanOrEqual(r.before - 2000);
			expect(r.header - ms, offset).toBeLessThanOrEqual(r.after + 2000);
			expect(r.timerMs, offset).toBeGreaterThanOrEqual(990);
			expect(r.timerMs, offset).toBeLessThan(1500);
		}
	});

	it("leaves the clock alone without the environment", () => {
		const r = run();
		expect(r.now).toBeGreaterThanOrEqual(r.before);
		expect(r.now).toBeLessThanOrEqual(r.after);
	});
});
