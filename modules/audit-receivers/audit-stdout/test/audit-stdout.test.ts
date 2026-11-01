import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Writable } from "node:stream";
import { audit } from "@mod/audit";
import auditModule from "@mod/audit/module";
import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { afterEach, expect, it, vi } from "vitest";
import auditStdout from "../src/module.ts";

const runtime = quietRuntime({
	clock: { now: () => 1234 },
	random: { bytes: (n) => new Uint8Array(n) },
});
const boot = async () =>
	(
		await assemble({
			modules: [auditModule, auditStdout],
			config: { ...kernelConfig(), audit: { receivers: ["stdout"] } },
			runtime,
		})
	).get(audit);
const settled = () => new Promise((resolve) => setTimeout(resolve, 0));
/** Replaces stdout's write, finishing each write as `outcome` says. */
const writes = (outcome: Error | null) => {
	const written: string[] = [];
	vi.spyOn(process.stdout, "write").mockImplementation(((chunk: string, done: unknown) => {
		written.push(chunk);
		if (typeof done === "function") queueMicrotask(() => done(outcome));
		return true;
	}) as typeof process.stdout.write);
	return written;
};
afterEach(() => {
	vi.restoreAllMocks();
});

it("writes each event as one JSON line on stdout", async () => {
	const written = writes(null);
	const a = await boot();
	a.record({ kind: "login.succeeded", subject: "s", attributes: { method: "password" } });
	a.record({ kind: "login.failed" });
	await settled();
	expect(written).toEqual([
		'{"kind":"login.succeeded","subject":"s","attributes":{"method":"password"},"at":1234}\n',
		'{"kind":"login.failed","at":1234}\n',
	]);
});

it("keeps a line break inside a value from starting another line", async () => {
	const written = writes(null);
	const a = await boot();
	a.record({ kind: "k", attributes: { note: 'x\n{"kind":"forged"}' } });
	await settled();
	expect(written).toHaveLength(1);
	expect(written[0]?.split("\n")).toHaveLength(2);
	expect(JSON.parse(written[0] ?? "").kind).toBe("k");
});

it("fails as a receiver when the write fails", async () => {
	writes(new Error("closed"));
	const a = await boot();
	a.record({ kind: "k" });
	await settled();
	expect(a.lost()).toEqual({ stdout: 1 });
});

it("counts each event lost once its reader goes away, never crashing on the stream's error, one listener however many start", async () => {
	// Standard output whose reader has gone: every write fails as EPIPE, and the stream emits 'error'.
	const out = new Writable({
		write: (_chunk, _encoding, done) =>
			done(Object.assign(new Error("write EPIPE"), { code: "EPIPE" })),
	});
	vi.spyOn(process, "stdout", "get").mockReturnValue(out as typeof process.stdout);
	const [a] = [await boot(), await boot()];
	a.record({ kind: "k" });
	await settled();
	expect(out.errored).toMatchObject({ code: "EPIPE" });
	expect(a.lost()).toEqual({ stdout: 1 });
	a.record({ kind: "k" });
	await settled();
	expect(a.lost()).toEqual({ stdout: 2 });
	expect(out.listenerCount("error")).toBe(1);
});

it("registers under the name its manifest declares (`registersAs`), the one `audit.receivers` names", async () => {
	const { registersAs } = JSON.parse(
		readFileSync(join(import.meta.dirname, "..", "package.json"), "utf8"),
	) as { registersAs: string };
	const booted = assemble({
		modules: [auditModule, auditStdout],
		config: { ...kernelConfig(), audit: { receivers: [registersAs] } },
		runtime,
	});
	await expect(booted).resolves.toBeDefined();
});
