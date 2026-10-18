import { describe, expect, it } from "vitest";
import type { SpentAssertions } from "./store.ts";

/** A place that keeps spent assertions, as one implementation of the store interface offers it. */
export interface SpentPlace {
	readonly spent: SpentAssertions;
	/** Moves the place's clock on, so lifetimes run out. */
	advance(ms: number): void;
	/** Where answers can be lost: the next write takes effect, but its answer is lost. */
	readonly loseNextAnswer?: () => void;
	/** Where the place replicates: a replica takes over, keeping only what was confirmed. */
	readonly failover?: () => Promise<void>;
	/** Where the place can restart: it does, keeping only what it holds durably. */
	readonly restart?: () => Promise<void>;
	/** Where memory can run short: it does, keeping only what is kept from eviction. */
	readonly pressMemory?: () => Promise<void>;
}

/** What jwt-bearer needs from any implementation: a name kept once, for exactly its lifetime, through faults. */
export function spentAssertionsContract(name: string, open: () => Promise<SpentPlace>): void {
	let n = 0;
	const fresh = () => `j-${++n}-${Math.random().toString(36).slice(2)}`;
	describe(`jwt-bearer's store interface: ${name}`, () => {
		it("keeps a name once, for exactly its lifetime", async () => {
			const place = await open();
			const used = fresh();
			expect(await place.spent.save(used, 1000)).toBe("created");
			expect(await place.spent.save(used, 1000)).toBe("exists");
			place.advance(999);
			expect(await place.spent.save(used, 1000)).toBe("exists");
			place.advance(1);
			expect(await place.spent.save(used, 1000)).toBe("created");
		});

		it("keeps names through restarts, memory pressure, lost answers and failovers", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover, restart, pressMemory } = place;
			if (!lose || !failover || !restart || !pressMemory) return context.skip();
			const [kept, settled] = [fresh(), fresh()];
			await place.spent.save(kept, 60_000);
			lose();
			expect(await place.spent.save(settled, 60_000)).toBe("created");
			await failover();
			await restart();
			await pressMemory();
			expect(await place.spent.save(kept, 60_000)).toBe("exists");
			expect(await place.spent.save(settled, 60_000)).toBe("exists");
		});
	});
}
