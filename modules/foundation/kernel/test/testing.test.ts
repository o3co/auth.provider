import { afterEach, describe, expect, it, vi } from "vitest";
import { assemble, contract, defineModule, isUnavailable, kernelConfig } from "../src/contract.ts";
import {
	quietLog,
	quietRuntime,
	recordingLog,
	switchedModule,
	unavailableSwitch,
} from "../src/testing.ts";

interface Store {
	readonly size: number;
	save(value: string): Promise<number>;
	read(): Promise<readonly string[]>;
	label(): string;
}

class Recording implements Store {
	readonly saved: string[] = [];
	get size() {
		return this.saved.length;
	}
	async save(value: string) {
		this.saved.push(value);
		return this.saved.length;
	}
	async read() {
		return [...this.saved];
	}
	label() {
		return "kept";
	}
}

describe("unavailableSwitch", () => {
	it("passes calls through and reads values through, also after the implementation changes them", async () => {
		const kept = new Recording();
		const store = unavailableSwitch<Store>().wrap(kept);
		expect(Object.isFrozen(store)).toBe(true);
		expect(await store.save("a")).toBe(1);
		expect(await store.read()).toEqual(["a"]);
		expect(store.label()).toBe("kept");
		await kept.save("b");
		expect(store.size).toBe(2);
	});

	it("fails exactly the next calls of a method, which never reach the implementation", async () => {
		const kept = new Recording();
		const down = unavailableSwitch<Store>("store");
		const store = down.wrap(kept);
		down.failNext("save");
		down.failNext("save");
		await expect(store.save("a")).rejects.toSatisfy(
			(error: unknown) => isUnavailable(error) && error.what === "store",
		);
		await expect(store.save("b")).rejects.toSatisfy(isUnavailable);
		expect(await store.read()).toEqual([]);
		expect(await store.save("c")).toBe(1);
		expect(kept.saved).toEqual(["c"]);
	});

	it("fails every call of the named methods until restored; other methods answer", async () => {
		const kept = new Recording();
		const down = unavailableSwitch<Store>();
		const store = down.wrap(kept);
		down.unavailable("read");
		down.failNext("save");
		await expect(store.read()).rejects.toSatisfy(isUnavailable);
		await expect(store.read()).rejects.toSatisfy(isUnavailable);
		down.restore();
		expect(await store.read()).toEqual([]);
		expect(await store.save("a")).toBe(1);
	});

	it("shares its state among the implementations it wraps", async () => {
		const down = unavailableSwitch<Store>();
		const one = down.wrap(new Recording());
		const two = down.wrap(new Recording());
		down.unavailable("save");
		await expect(one.save("a")).rejects.toSatisfy(isUnavailable);
		await expect(two.save("a")).rejects.toSatisfy(isUnavailable);
	});

	it("names only async methods", () => {
		const down = unavailableSwitch<Store>();
		// @ts-expect-error a sync method is not switchable
		down.failNext("label");
		// @ts-expect-error a value is not switchable
		down.unavailable("size");
	});
});

describe("switchedModule", () => {
	const store = contract<Store>("store");
	const other = contract<Store>("other");
	const m = defineModule({ name: "m" }, (m) => [
		m.provide(store).by(() => new Recording()),
		m.provide(other).by(() => new Recording()),
	]);

	it("wraps only that provision", async () => {
		const down = unavailableSwitch<Store>();
		const app = await assemble({
			modules: [switchedModule(m, store, down)],
			config: kernelConfig(),
		});
		down.unavailable("save");
		await expect(app.get(store).save("a")).rejects.toSatisfy(isUnavailable);
		expect(await app.get(other).save("a")).toBe(1);
	});

	it("throws for a module that does not provide the contract", () => {
		const bare = defineModule({ name: "bare" });
		expect(() => switchedModule(bare, store, unavailableSwitch<Store>())).toThrow(TypeError);
	});
});

describe("test runtime", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("writes nothing through the quiet log", () => {
		const write = vi.spyOn(process.stdout, "write");
		for (const level of ["trace", "debug", "info", "warn", "error", "fatal"] as const) {
			quietLog[level](level, { n: 1 });
		}
		expect(write).not.toHaveBeenCalled();
		expect(Object.isFrozen(quietLog)).toBe(true);
	});

	it("takes the system clock and randomness and the quiet log, unless the test sets one", () => {
		const runtime = quietRuntime();
		expect(runtime.log).toBe(quietLog);
		expect(Math.abs(runtime.clock.now() - Date.now())).toBeLessThan(1000);
		expect(runtime.random.bytes(16)).not.toEqual(runtime.random.bytes(16));
		const clock = { now: () => 7 };
		const set = quietRuntime({ clock });
		expect([set.clock, set.log]).toEqual([clock, quietLog]);
	});

	it("records each line with its level, in order, fields empty when none were given", () => {
		const recorded = recordingLog();
		recorded.log.warn("w", { n: 1 });
		recorded.log.info("i");
		const before = recorded.lines();
		recorded.log.error("e", { ok: true });
		recorded.log.trace("t");
		recorded.log.debug("d");
		recorded.log.fatal("f");
		expect(before).toHaveLength(2);
		expect(recorded.lines()).toEqual([
			{ level: "warn", event: "w", fields: { n: 1 } },
			{ level: "info", event: "i", fields: {} },
			{ level: "error", event: "e", fields: { ok: true } },
			{ level: "trace", event: "t", fields: {} },
			{ level: "debug", event: "d", fields: {} },
			{ level: "fatal", event: "f", fields: {} },
		]);
	});
});
