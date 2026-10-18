import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { UsedIdTokens } from "./store.ts";

export type { Issuer, Issuers } from "./issuers.ts";
export { fixedIssuers } from "./issuers.ts";
/** For tests' compositions only: the module over issuers whose keys a test holds. */
export { exchangeIdTokensOver } from "./module.ts";

/** A place that keeps the id_tokens taken, as one implementation of the store interface offers it. */
export interface UsedIdTokensPlace {
	readonly used: UsedIdTokens;
	/** Moves the place's clock on. */
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

/** What exchange-id-tokens needs from any implementation of its store interface: each name taken once while held, through faults. */
export function usedIdTokensContract(name: string, open: () => Promise<UsedIdTokensPlace>): void {
	const fresh = () => `name-${randomUUID()}`;

	describe(`exchange-id-tokens' store interface: ${name}`, () => {
		it("takes a name once under its kind, and apart under another kind", async () => {
			const { used } = await open();
			const token = fresh();
			expect(await used.save("apple", token, 60_000)).toBe("created");
			expect(await used.save("apple", token, 60_000)).toBe("exists");
			expect(await used.save("google", token, 60_000)).toBe("created");
		});

		it("holds a name for its lifetime, and no longer", async () => {
			const place = await open();
			const token = fresh();
			await place.used.save("apple", token, 60_000);
			place.advance(59_000);
			expect(await place.used.save("apple", token, 60_000)).toBe("exists");
			place.advance(2_000);
			expect(await place.used.save("apple", token, 60_000)).toBe("created");
		});

		it("keeps what it took through a lost answer, a failover, a restart and memory pressure", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover, restart, pressMemory } = place;
			if (!lose || !failover || !restart || !pressMemory) return context.skip();
			const token = fresh();
			lose();
			expect(await place.used.save("apple", token, 600_000)).toBe("created");
			await failover();
			await restart();
			await pressMemory();
			expect(await place.used.save("apple", token, 600_000)).toBe("exists");
		});
	});
}
