import { describe, expect, it } from "vitest";
import type { RevokedTokens } from "./contract.ts";

/** A place that keeps revoked tokens, as one implementation of the store interface offers it. */
export interface RevokedPlace {
	readonly revoked: RevokedTokens;
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

/** What the denylist needs from any implementation: an id kept once, for exactly its lifetime, through faults. */
export function revokedTokensContract(name: string, open: () => Promise<RevokedPlace>): void {
	let n = 0;
	const fresh = () => `t-${++n}-${Math.random().toString(36).slice(2)}`;
	describe(`token-denylist's store interface: ${name}`, () => {
		it("keeps an id once, for exactly its lifetime", async () => {
			const place = await open();
			const id = fresh();
			expect(await place.revoked.holds(id)).toBe(false);
			expect(await place.revoked.save(id, 1000)).toBe("created");
			expect(await place.revoked.save(id, 1000)).toBe("exists");
			place.advance(999);
			expect(await place.revoked.holds(id)).toBe(true);
			place.advance(1);
			expect(await place.revoked.holds(id)).toBe(false);
		});

		it("keeps ids through restarts, memory pressure, lost answers and failovers", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover, restart, pressMemory } = place;
			if (!lose || !failover || !restart || !pressMemory) return context.skip();
			const [kept, settled] = [fresh(), fresh()];
			await place.revoked.save(kept, 60_000);
			lose();
			expect(await place.revoked.save(settled, 60_000)).toBe("created");
			await failover();
			await restart();
			await pressMemory();
			expect(await place.revoked.holds(kept)).toBe(true);
			expect(await place.revoked.holds(settled)).toBe(true);
		});
	});
}
