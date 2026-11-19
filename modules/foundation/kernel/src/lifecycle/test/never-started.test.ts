import { expect, it } from "vitest";
import { assemble, contract, defineModule, kernelConfig } from "../../contract.ts";
import { quietRuntime } from "../../testing.ts";

/** A module noting what runs, and what its build context says of never starting. */
function noting(seen: string[], told: boolean[]) {
	return defineModule({ name: "noting", replicaSafe: false, takes: [] }, (m) => [
		m.provide(contract<object>("noting")).by((c) => {
			told.push(c.neverStarted);
			c.onStart(() => {
				seen.push("start");
			});
			c.every(1, async () => {
				seen.push("periodic");
			});
			c.onStop(() => {
				seen.push("stop");
			});
			return {};
		}),
	]);
}

it("rejects start with a TypeError, no start hook or periodic run, and still stops, where the assembly is never started", async () => {
	const [seen, told]: [string[], boolean[]] = [[], []];
	const app = await assemble({
		modules: [noting(seen, told)],
		config: kernelConfig(),
		runtime: quietRuntime(),
		neverStarted: true,
	});
	expect(told).toEqual([true]);
	const started = app.start();
	await expect(started).rejects.toBeInstanceOf(TypeError);
	await expect(started).rejects.toThrow("this assembly is never started");
	await new Promise((resolve) => setTimeout(resolve, 20));
	expect(seen).toEqual([]);
	await app.stop(1000);
	expect(seen).toEqual(["stop"]);
});

it("tells every build context the assembly may start, where it is not set", async () => {
	const [seen, told]: [string[], boolean[]] = [[], []];
	const app = await assemble({
		modules: [noting(seen, told)],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	expect(told).toEqual([false]);
	await app.start();
	await app.stop(1000);
	expect(seen[0]).toBe("start");
	expect(seen.at(-1)).toBe("stop");
});

it("gives a factory a never-started word it cannot change", async () => {
	const outcome = contract<readonly unknown[]>("outcome");
	const changer = defineModule({ name: "changer", replicaSafe: false, takes: [] }, (m) => [
		m
			.provide(outcome)
			.by((c) => [
				Reflect.set(c, "neverStarted", false),
				Reflect.defineProperty(c, "neverStarted", { value: false }),
				c.neverStarted,
			]),
	]);
	const app = await assemble({
		modules: [changer],
		config: kernelConfig(),
		runtime: quietRuntime(),
		neverStarted: true,
	});
	expect(app.get(outcome)).toEqual([false, false, true]);
	await app.stop(1000);
});
