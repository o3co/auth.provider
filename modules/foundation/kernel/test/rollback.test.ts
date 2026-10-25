import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
	assemble,
	type BuildContext,
	contract,
	defineModule,
	kernelConfig,
	type Module,
} from "../src/contract.ts";
import { quietRuntime, recordingLog } from "../src/testing.ts";
import { refusalsOf } from "./refusals.ts";

const single = kernelConfig();
const refusing = defineModule({ name: "refusing", takes: [] }, (m) => [
	m.provide(contract<void>("refused")).by((c) => c.refuse("refusing", "refused on purpose")),
]);
/** A module providing `name`, after its dependency where it has one, its stop hook as `stop`. */
const holding = (
	name: string,
	stop: (c: BuildContext<unknown>) => Promise<void> | void,
	after?: { readonly contract: ReturnType<typeof contract<void>> },
) => {
	const handle = contract<void>(name);
	const module = defineModule({ name, takes: after ? [after.contract] : [] }, (m) => [
		m.provide(handle).by(async (c) => {
			if (after) await c.get(after.contract);
			c.onStop(() => stop(c));
		}),
	]);
	return { module, contract: handle };
};

describe("an assembly refused after its builds", () => {
	it("runs the stop hooks registered, in reverse, then refuses with the refusals as they were", async () => {
		const order: string[] = [];
		const base = holding("base", () => {
			order.push("stop base");
		});
		const top = holding(
			"top",
			() => {
				order.push("stop top");
			},
			base,
		);
		const refusals = await refusalsOf(
			assemble({ modules: [top.module, base.module, refusing], config: single }),
		);
		expect(order).toEqual(["stop top", "stop base"]);
		expect(refusals).toEqual([{ where: "refusing", reason: "refused on purpose" }]);
	});

	it("runs the hook a build registered before refusing itself", async () => {
		let stopped = false;
		const own = defineModule({ name: "own", takes: [] }, (m) => [
			m.provide(contract<void>("own")).by((c) => {
				c.onStop(() => {
					stopped = true;
				});
				return c.refuse("own", "its resource did not start");
			}),
		]);
		expect(await refusalsOf(assemble({ modules: [own], config: single }))).toEqual([
			{ where: "own", reason: "its resource did not start" },
		]);
		expect(stopped).toBe(true);
	});

	it("keeps the refusals it took before the rollback, whatever a stop hook asks of its context", async () => {
		const missing = contract<void>("missing");
		const asking = holding("asking", async (c) => {
			await c.get(missing).catch(() => undefined);
		});
		expect(
			await refusalsOf(assemble({ modules: [asking.module, refusing], config: single })),
		).toEqual([{ where: "refusing", reason: "refused on purpose" }]);
	});

	it("runs no hook registered once its build settled", async () => {
		let later = false;
		const registering = holding("registering", (c) => {
			c.onStop(() => {
				later = true;
			});
		});
		await refusalsOf(assemble({ modules: [registering.module, refusing], config: single }));
		expect(later).toBe(false);
	});

	it("still refuses late references and readiness while it rolls back", async () => {
		const asked: string[] = [];
		const other = contract<void>("other");
		const lateTaker = defineModule({ name: "late-taker", takes: [] }, (m) => [
			m.provide(other).by(() => {}),
			m.provide(contract<void>("late-taker")).by((c) => {
				const later = c.late(other);
				c.onStop(async () => {
					try {
						later();
					} catch {
						asked.push("late refused");
					}
					await c.readinessReport(100).catch(() => asked.push("readiness refused"));
				});
			}),
		]);
		await refusalsOf(assemble({ modules: [lateTaker, refusing], config: single }));
		expect(asked).toEqual(["late refused", "readiness refused"]);
	});

	it("warns of a hook that fails, its refusal kept", async () => {
		const recorded = recordingLog();
		const failing = holding("failing", () => {
			throw new TypeError("boom");
		});
		const refusals = await refusalsOf(
			assemble({
				modules: [failing.module, refusing],
				config: single,
				runtime: quietRuntime({ log: recorded.log }),
			}),
		);
		expect(refusals).toEqual([{ where: "refusing", reason: "refused on purpose" }]);
		expect(recorded.lines().filter((l) => l.event === "kernel.stop_failed")).toEqual([
			{
				level: "warn",
				event: "kernel.stop_failed",
				fields: { module: "failing", outcome: "failed", kind: "TypeError", during: "refusal" },
			},
		]);
	});

	it("refuses as it took, every hook run, though a hook throws a value whose very type cannot be read", async () => {
		const recorded = recordingLog();
		const ran: string[] = [];
		const revoked = Proxy.revocable({}, {});
		revoked.revoke();
		const nameless = Object.defineProperty(new Error("x"), "name", {
			get() {
				throw new Error("no name");
			},
		});
		const first = holding("first", () => {
			ran.push("first");
		});
		const proxied = holding("proxied", () => {
			ran.push("proxied");
			throw revoked.proxy;
		});
		const unnamed = holding("unnamed", () => {
			ran.push("unnamed");
			throw nameless;
		});
		const refusals = await refusalsOf(
			assemble({
				modules: [first.module, proxied.module, unnamed.module, refusing],
				config: single,
				runtime: quietRuntime({ log: recorded.log }),
			}),
		);
		expect(refusals).toEqual([{ where: "refusing", reason: "refused on purpose" }]);
		expect(ran).toEqual(["unnamed", "proxied", "first"]);
		expect(
			recorded
				.lines()
				.filter((l) => l.event === "kernel.stop_failed")
				.map((l) => l.fields),
		).toEqual([
			{ module: "unnamed", outcome: "failed", kind: "unknown", during: "refusal" },
			{ module: "proxied", outcome: "failed", kind: "unknown", during: "refusal" },
		]);
	});

	it("gives a hook until the stop deadline, its signal aborted then, warned of as late; a hook after it is called aborted, unwarned", async () => {
		const recorded = recordingLog();
		let sawAbort = false;
		let calledAborted: boolean | undefined;
		// Registered first, so called last: after the deadline.
		const after = defineModule({ name: "after", takes: [] }, (m) => [
			m.provide(contract<void>("after")).by((c) => {
				c.onStop((signal) => {
					calledAborted = signal.aborted;
				});
			}),
		]);
		const hanging = defineModule({ name: "hanging", takes: [] }, (m) => [
			m.provide(contract<void>("hanging")).by((c) => {
				c.onStop((signal) => {
					signal.addEventListener("abort", () => {
						sawAbort = true;
					});
					return new Promise<void>(() => {});
				});
			}),
		]);
		const began = performance.now();
		await refusalsOf(
			assemble({
				modules: [after, hanging, refusing],
				config: kernelConfig({ "stop-deadline": "1s" }),
				runtime: quietRuntime({ log: recorded.log }),
			}),
		);
		expect(performance.now() - began).toBeGreaterThanOrEqual(950);
		expect([sawAbort, calledAborted]).toEqual([true, true]);
		expect(recorded.lines().filter((l) => l.event === "kernel.stop_failed")).toEqual([
			{
				level: "warn",
				event: "kernel.stop_failed",
				fields: { module: "hanging", outcome: "late", during: "refusal" },
			},
		]);
	});

	it("keeps its process alive until the refusal is thrown, so the host's own exit is reached", () => {
		const ran = spawnSync(
			process.execPath,
			[join(import.meta.dirname, "fixtures", "refused-rollback.ts")],
			{
				encoding: "utf8",
				timeout: 30_000,
			},
		);
		expect(ran.status).toBe(78);
	});
});

describe("an assembly refused before it builds", () => {
	const stopping = (name: string, stopped: string[]): Module =>
		defineModule({ name, replicaSafe: false, takes: [] }, (m) => [
			m.provide(contract<void>(name)).by((c) => {
				c.onStop(() => {
					stopped.push(name);
				});
			}),
		]);

	it("runs nothing, as nothing was built: neither for its sections nor for two providers", async () => {
		const stopped: string[] = [];
		await refusalsOf(
			assemble({
				modules: [stopping("unsafe", stopped)],
				config: kernelConfig({ deployment: "multi" }),
			}),
		);
		const shared = contract<void>("shared");
		const twice = (name: string) =>
			defineModule({ name, takes: [] }, (m) => [
				m.provide(shared).by((c) => {
					c.onStop(() => {
						stopped.push(name);
					});
				}),
			]);
		await refusalsOf(assemble({ modules: [twice("one"), twice("two")], config: single }));
		expect(stopped).toEqual([]);
	});
});

describe("a stop of an assembly", () => {
	it("warns of a failed hook without naming a refusal", async () => {
		const recorded = recordingLog();
		const failing = holding("failing", () => {
			throw new TypeError("boom");
		});
		const app = await assemble({
			modules: [failing.module],
			config: single,
			runtime: quietRuntime({ log: recorded.log }),
		});
		await app.stop(1000);
		expect(recorded.lines().filter((l) => l.event === "kernel.stop_failed")).toEqual([
			{
				level: "warn",
				event: "kernel.stop_failed",
				fields: { module: "failing", outcome: "failed", kind: "TypeError" },
			},
		]);
	});
});
