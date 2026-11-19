import { quietRuntime } from "@mod/kernel/testing";
import type { Space } from "@mod/store";
import type { Redis } from "ioredis";
import { expect, it } from "vitest";
import { keysUnder } from "../../keys.ts";
import { scriptsOn, serverOf } from "../../redis-store.ts";
import { redisUpkeepWith } from "../upkeep.ts";

const space: Space = { name: "kept", guarantees: [], subjectData: "none" };
const page = { kind: "page", cursor: "7", live: 1, endless: 0, latest: "-1", generation: "g" };

/**
 * The upkeep over a client whose kept walk's pages wait, each in turn, for the test to release them
 * (`release`); confirmation fails while `failing` holds.
 */
function walking() {
	const waiting: (() => void)[] = [];
	const state = { failing: false };
	const client = {
		eval: async (_script: string, numkeys: number, ...rest: (string | number)[]) => {
			const argv = rest.slice(numkeys).map(String);
			if (argv[0] === "keep") return `abc\n{"kind":"kept"}`;
			await new Promise<void>((resolve) => waiting.push(resolve));
			return `abc\n${JSON.stringify(page)}`;
		},
	} as unknown as Redis;
	const { upkeep } = redisUpkeepWith({
		run: scriptsOn(client),
		serverOf,
		confirmed: async () => {
			if (state.failing) throw Object.assign(new Error("store"), { name: "Unavailable" });
			return "abc";
		},
		keys: keysUnder("t"),
		declared: [],
		taken: { epoch: "", keyed: false },
		random: quietRuntime().random,
		honours: async () => ({ kind: "verified", witness: "w" }),
	});
	const walk = (at?: string) =>
		(upkeep.sweepKept as NonNullable<typeof upkeep.sweepKept>)(space.name, at);
	/** Releases the page waiting at `index` once that many and one wait, the first by default. */
	const release = async (index = 0) => {
		while (waiting.length <= index) await new Promise((resolve) => setTimeout(resolve, 1));
		waiting.splice(index, 1)[0]?.();
	};
	return { walk, release, state };
}

it("keeps a replaced walk replaced when its page answers after a new walk of the space began", async () => {
	const { walk, release } = walking();
	const started = walk();
	await release();
	const earlier = ((await started) as { cursor: string }).cursor;
	const continued = walk(earlier);
	const replacing = walk();
	// The new walk's page answers first; the earlier walk's continuation answers after it.
	await release(1);
	await replacing;
	await release();
	await continued;
	await expect(walk(earlier)).rejects.toThrow(TypeError);
	const next = ((await replacing) as { cursor: string }).cursor;
	const on = walk(next);
	await release();
	expect((await on).kind).toBe("page");
});

it("refuses a cursor whose walk a new walk of the space replaced while the store got ready", async () => {
	const { walk, release } = walking();
	const started = walk();
	await release();
	const earlier = ((await started) as { cursor: string }).cursor;
	const replacing = walk();
	const late = walk(earlier);
	await expect(late).rejects.toThrow(/no walk of this space that this process holds/);
	await release();
	expect((await replacing).kind).toBe("page");
});

it("drops the earlier walk when a new one's page fails its confirmation, and the new one with it", async () => {
	const { walk, release, state } = walking();
	const started = walk();
	await release();
	const earlier = ((await started) as { cursor: string }).cursor;
	state.failing = true;
	const failed = walk();
	await release();
	await expect(failed).rejects.toMatchObject({ name: "Unavailable" });
	await expect(walk(earlier)).rejects.toThrow(TypeError);
});
