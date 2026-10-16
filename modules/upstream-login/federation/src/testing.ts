import { defineModule, Unavailable } from "@mod/kernel";
import {
	type AuthorizationStart,
	type CodeExchange,
	idpType,
	idpTypes,
	type Upstream,
	type UpstreamLogin,
	UpstreamRefused,
} from "@mod/upstreams";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import type { section } from "./section.ts";
import type { StoredTransaction, TransactionStore } from "./store.ts";

export type FederationSettings = z.input<typeof section>;

export function federationConfig(settings: Partial<FederationSettings> = {}) {
	return { federation: settings };
}

/**
 * An IdP type for tests, "test": its upstream at `issuer` answers a code with the login the
 * test gave it (or fails as `unreachable` or `broken` says), refuses any other code, and keeps
 * what it was asked; it offers what `more` gives.
 */
export function testIdpType(
	answers: Map<string, UpstreamLogin | "unreachable" | "broken">,
	more: Pick<Upstream, "refresh" | "endSession" | "delegation"> = {},
) {
	const asked = { starts: [] as AuthorizationStart[], exchanges: [] as CodeExchange[] };
	const module = defineModule({ name: "test-idp-type" }, (m) => [
		m.contribute(idpTypes).by(() =>
			idpType({
				type: "test",
				settings: z.strictObject({
					issuer: z.url(),
					path: z.string().default("/authorize"),
					mode: z.enum(["query", "form_post"]).default("query"),
					"skew-ms": z.number().default(30_000),
				}),
				open: async (read) => {
					const { issuer, path, mode } = read;
					if (issuer.includes("mismatch")) throw new Error("not this upstream");
					return {
						...more,
						responseMode: mode,
						clockSkewMs: read["skew-ms"],
						authorizationUrl: (start) => {
							asked.starts.push(start);
							const url = new URL(`${issuer}${path}`);
							url.searchParams.set("state", start.state);
							return url.href;
						},
						exchange: async (exchange) => {
							asked.exchanges.push(exchange);
							const found = answers.get(exchange.code);
							if (found === "unreachable") throw new Unavailable("test upstream");
							if (found === "broken") throw new Error("test upstream");
							if (!found) throw new UpstreamRefused();
							return found;
						},
					};
				},
			}),
		),
	]);
	return { module, asked };
}

/** A place that keeps federation's transactions, as one implementation of its store interface offers it. */
export interface TransactionPlace {
	readonly transactions: TransactionStore;
	/** Moves the place's clock on, so lifetimes run out. */
	advance(ms: number): void;
	/** Before the next update of `name` writes, another writer changes its record as given. */
	raceNextUpdate(name: string, change: (record: StoredTransaction) => StoredTransaction): void;
	/** Where answers can be lost: the next write takes effect, but its answer is lost. */
	readonly loseNextAnswer?: () => void;
	/** Where the place replicates: a replica takes over, keeping only what was confirmed. */
	readonly failover?: () => Promise<void>;
	/** Where what the place was given can be searched: whether any of it carried `text`. */
	readonly holds?: (text: string) => boolean;
}

/**
 * What federation needs from any implementation of its store interface: records kept whole and
 * once, changed only from what they hold, ended at exactly their lifetime, and a change once
 * answered kept through a failover.
 */
export function transactionStoreContract(
	name: string,
	open: () => Promise<TransactionPlace>,
): void {
	let n = 0;
	const fresh = () => `t-${++n}-${Math.random().toString(36).slice(2)}`;
	/** A value as the store keeps it, whatever its shape. */
	const asStored = (value: object) => value as unknown as StoredTransaction;
	const counted = (record: StoredTransaction) => (record as unknown as { n: number }).n;
	const plus = (record: StoredTransaction) => ({ value: asStored({ n: counted(record) + 1 }) });
	const read = async (transactions: TransactionStore, key: string) =>
		(await transactions.update(key, () => undefined))?.after;

	describe(`federation's store interface: ${name}`, () => {
		it("removes a record, so its name is free again", async () => {
			const place = await open();
			const [key, other] = [fresh(), fresh()];
			await place.transactions.save(key, asStored({ n: 1 }), 60_000);
			await place.transactions.save(other, asStored({ n: 2 }), 60_000);
			await place.transactions.remove(key);
			await place.transactions.remove(fresh());
			expect(await read(place.transactions, key)).toBeUndefined();
			expect(await read(place.transactions, other)).toEqual(asStored({ n: 2 }));
			expect(await place.transactions.save(key, asStored({ n: 3 }), 60_000)).toBe("created");
		});

		it("keeps a record whole and once per name, and changes it only from what it holds", async () => {
			const place = await open();
			const key = fresh();
			const odd = asStored({ state: "unheard-of", nested: { list: [1, "two"] } });
			expect(await place.transactions.save(key, odd, 60_000)).toBe("created");
			expect(await place.transactions.save(key, asStored({ n: 1 }), 60_000)).toBe("exists");
			expect(await read(place.transactions, key)).toEqual(odd);
			expect(await place.transactions.update(fresh(), plus)).toBeUndefined();
			const counting = fresh();
			await place.transactions.save(counting, asStored({ n: 1 }), 60_000);
			place.raceNextUpdate(counting, (record) => asStored({ n: counted(record) * 10 }));
			expect(await place.transactions.update(counting, plus)).toEqual({
				before: asStored({ n: 10 }),
				after: asStored({ n: 11 }),
			});
		});

		it("ends a record at exactly its lifetime", async () => {
			const place = await open();
			const key = fresh();
			await place.transactions.save(key, asStored({ n: 1 }), 1000);
			place.advance(999);
			expect(await read(place.transactions, key)).toBeDefined();
			place.advance(1);
			expect(await read(place.transactions, key)).toBeUndefined();
		});

		it("never gives a transaction's cookie to what the place holds, in clear", async (context) => {
			const place = await open();
			const { holds } = place;
			if (!holds) return context.skip();
			const [cookie, kept] = [fresh(), fresh()];
			await place.transactions.save(cookie, asStored({ kept }), 60_000);
			await place.transactions.update(cookie, (record) => ({ value: record }));
			expect([holds(kept), holds(cookie)]).toEqual([true, false]);
		});

		it("keeps a change whose answer was lost, through a failover", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover } = place;
			if (!lose || !failover) return context.skip();
			const key = fresh();
			await place.transactions.save(key, asStored({ n: 1 }), 60_000);
			lose();
			expect((await place.transactions.update(key, plus))?.after).toEqual(asStored({ n: 2 }));
			await failover();
			expect(await read(place.transactions, key)).toEqual(asStored({ n: 2 }));
		});
	});
}
