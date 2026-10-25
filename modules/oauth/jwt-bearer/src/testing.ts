import { describe, expect, it } from "vitest";
import type { JtiLedger } from "./contract.ts";
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

/** A ledger as one implementation of `jtiLedgers` offers it, with the faults it can show. */
export interface LedgerPlace {
	readonly ledger: JtiLedger;
	/** Moves the ledger's clock on. */
	advance(ms: number): void;
	/** Where answers can be lost: the next spend takes effect, but its answer is lost. */
	readonly loseNextAnswer?: () => void;
	/** Where the ledger replicates: a replica takes over, keeping only what was confirmed. */
	readonly failover?: () => Promise<void>;
	/** Where the ledger can restart: it does, keeping only what it holds durably. */
	readonly restart?: () => Promise<void>;
	/** Where its memory can run short: it does, keeping only what is kept from eviction. */
	readonly pressMemory?: () => Promise<void>;
}

/** What jwt-bearer needs from any ledger: a jti used once, while it must stay used, through faults. */
export function jtiLedgerContract(name: string, open: () => Promise<LedgerPlace>): void {
	let n = 0;
	const fresh = (keepUntil = 60_000) => ({
		sentIssuer: "https://idp.example",
		jti: `j-${++n}-${Math.random().toString(36).slice(2)}`,
		expiresAt: keepUntil - 1000,
		keepUntil,
	});
	describe(`jwt-bearer's jti ledger: ${name}`, () => {
		it("uses a jti up once: first, then replayed, another jti first", async () => {
			const { ledger } = await open();
			const used = fresh();
			expect(await ledger.spend(used)).toBe("first");
			expect(await ledger.spend(used)).toBe("replayed");
			expect(await ledger.spend(fresh())).toBe("first");
		});

		it("answers first to one of two spends of a jti at once", async () => {
			const { ledger } = await open();
			const used = fresh();
			const told = await Promise.all([ledger.spend(used), ledger.spend(used)]);
			expect([...told].sort()).toEqual(["first", "replayed"]);
		});

		it("keeps a jti used until its keepUntil, by its own clock", async () => {
			const place = await open();
			const used = fresh(60_000);
			expect(await place.ledger.spend(used)).toBe("first");
			place.advance(59_999);
			expect(await place.ledger.spend(used)).toBe("replayed");
		});

		it("keeps a jti used through a lost answer, restarts, failovers and memory pressure", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover, restart, pressMemory } = place;
			if (!lose || !failover || !restart || !pressMemory) return context.skip();
			const [kept, lost] = [fresh(), fresh()];
			expect(await place.ledger.spend(kept)).toBe("first");
			lose();
			await place.ledger.spend(lost).catch(() => undefined);
			await failover();
			await restart();
			await pressMemory();
			expect(await place.ledger.spend(kept)).toBe("replayed");
			expect(await place.ledger.spend(lost)).toBe("replayed");
		});
	});
}

/** A ledger in memory for `issuer`, judging keepUntil by `now`: what a test composes in place of a real one. */
export function memoryJtiLedger(issuer: string, now: () => number): JtiLedger {
	const used = new Map<string, number>();
	return {
		issuer,
		spend: async ({ jti, keepUntil }) => {
			const until = used.get(jti);
			if (until !== undefined && now() < until) return "replayed";
			used.set(jti, keepUntil);
			return "first";
		},
	};
}
