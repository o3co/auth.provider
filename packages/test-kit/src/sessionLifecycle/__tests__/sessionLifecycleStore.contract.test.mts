/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * `sessionLifecycleStoreContract` run over core's in-process store, on a
 * fake clock and on the real one, and the proof that its cases are not
 * vacuous: core's store with one fault each, refused by the case that names
 * it.
 */

import {
	createInMemorySessionLifecycleStore,
	newStoreGeneration,
	type SessionLifecycleRecord,
	type SessionLifecycleStore,
	type Versioned,
} from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import {
	type SessionLifecycleStoreContractInput,
	type SessionLifecycleStoreHarness,
	sessionLifecycleStoreContract,
} from "#/index.mjs";

/** Two years: past every retention a store may set from a clock read before it. */
const PAST_EVERY_RETENTION_MS = 2 * 366 * 24 * 60 * 60 * 1000;

/** A clock the harness moves by hand. */
const fakeClock = () => {
	let now = Date.parse("2026-10-05T00:00:00.000Z");
	return {
		now: () => now,
		advance: (ms: number) => {
			now += ms;
		},
	};
};

/** A store whose every member rejects, as one that cannot reach its backend. */
const unreachableStore = (): SessionLifecycleStore => {
	const down = async (): Promise<never> => {
		throw new Error("backend down");
	};
	return {
		kind: "unreachable",
		open: down,
		join: down,
		beginClose: down,
		completeIf: down,
		read: down,
		listClosing: down,
	};
};

type Fault = (
	store: SessionLifecycleStore,
	harness: SessionLifecycleStoreHarness,
) => SessionLifecycleStore;

/** Core's store on a fake clock with every hook, its store passed through `fault`. */
const memoryHarness = (fault?: Fault) => async (): Promise<SessionLifecycleStoreHarness> => {
	const clock = fakeClock();
	const store = createInMemorySessionLifecycleStore({ now: clock.now });
	const harness: SessionLifecycleStoreHarness = {
		store,
		clock,
		forceExpire: async () => clock.advance(PAST_EVERY_RETENTION_MS),
		unreachable: unreachableStore,
	};
	return fault === undefined ? harness : { ...harness, store: fault(store, harness) };
};

const ALL = { clock: true, forceExpire: true, unreachable: true } as const;

const run = (name: string, input: SessionLifecycleStoreContractInput): void => {
	describe(name, () => {
		for (const contractCase of sessionLifecycleStoreContract(input)) {
			it(contractCase.name, contractCase.run);
		}
	});
};

run("sessionLifecycleStoreContract over core's in-process store on a fake clock", {
	build: memoryHarness(),
	supports: ALL,
});

run("sessionLifecycleStoreContract over core's in-process store on the real clock", {
	build: async () => ({ store: createInMemorySessionLifecycleStore() }),
});

/** The names of the cases that refuse the store `fault` makes of core's, one per case. */
async function refusedBy(
	fault: Fault,
	supports: SessionLifecycleStoreContractInput["supports"] = ALL,
): Promise<string[]> {
	const refused: string[] = [];
	for (const contractCase of sessionLifecycleStoreContract({
		build: memoryHarness(fault),
		supports,
	})) {
		try {
			await contractCase.run();
		} catch {
			refused.push(contractCase.name);
		}
	}
	return refused;
}

const names = sessionLifecycleStoreContract({ build: memoryHarness(), supports: ALL }).map(
	(c) => c.name,
);

/** The one case whose name starts with `prefix`. */
const named = (prefix: string): string => {
	const found = names.filter((name) => name.startsWith(prefix));
	if (found.length !== 1) throw new Error(`${found.length} cases start with ${prefix}`);
	return found[0] as string;
};

const CASE = {
	absent: named("read answers null"),
	opened: named("an opened record is read back"),
	reopen: named("a repeated open"),
	lateOpen: named("an open whose expiresAt"),
	join: named("a join while active"),
	missing: named("a join, a close or a completion of a sid with no record"),
	close: named("a close moves the record to closing in one commit"),
	afterClose: named("no join lands once the close has committed"),
	race: named("a join racing a close"),
	idempotent: named("a close is idempotent"),
	resumable: named("a close is resumable"),
	complete: named("completeIf at the current generation"),
	completeRace: named("of concurrent completions"),
	closed: named("the record is closed in the step"),
	monotonic: named("states only move forward"),
	listing: named("a closing record is listed"),
	readers: named("every answer is one core's readers accept"),
	copies: named("the store keeps its own copies"),
	apart: named("one sid's writes"),
	expiredJoin: named("a join or a repeated open from the session's expiresAt on"),
	retention: named("a closing record is kept until"),
	lapse: named("retention lapses together"),
	outage: named("an outage rejects"),
} as const;

/** Waits one macrotask: a write in flight with a real store would interleave here. */
const yieldTurn = () => new Promise<void>((resolve) => setImmediate(resolve));

describe("sessionLifecycleStoreContract refuses a broken store", () => {
	it("passes core's store, and names every case it leaves out", async () => {
		expect(await refusedBy((store) => store)).toEqual([]);
		const bare = sessionLifecycleStoreContract({
			build: async () => ({ store: createInMemorySessionLifecycleStore() }),
		}).map((c) => c.name);
		expect(bare).toContain("not run: the clock cases (supports.clock not declared)");
		expect(bare).toContain("not run: the retention case (supports.forceExpire not declared)");
		expect(bare).toContain("not run: the outage case (supports.unreachable not declared)");
	});

	it("fails a declared hook the harness does not give", async () => {
		const cases = sessionLifecycleStoreContract({
			build: async () => ({ store: createInMemorySessionLifecycleStore() }),
			supports: ALL,
		});
		for (const name of [CASE.expiredJoin, CASE.retention, CASE.lapse, CASE.outage]) {
			const contractCase = cases.find((c) => c.name === name);
			await expect(contractCase?.run()).rejects.toThrow(/is declared/);
		}
	});

	it("refuses a store that answers a record never opened", async () => {
		const refused = await refusedBy((store) => ({
			...store,
			read: async (sid) =>
				(await store.read(sid)) ??
				({
					value: {
						sub: "ghost",
						state: "active",
						expiresAt: new Date(),
						participants: [],
						close: undefined,
					},
					generation: newStoreGeneration(),
				} satisfies Versioned<SessionLifecycleRecord>),
		}));
		expect(refused).toContain(CASE.absent);
	});

	it("refuses a store that drops a participant's data or keeps a second copy of one joined again", async () => {
		const drops = await refusedBy((store) => ({
			...store,
			join: (sid, participant) => store.join(sid, { ...participant, data: "" }),
		}));
		expect(drops).toContain(CASE.join);
		const repeats = await refusedBy((store) => ({
			...store,
			read: async (sid) => {
				const read = await store.read(sid);
				if (read === null || read.value.participants.length === 0) return read;
				const [first] = read.value.participants;
				return {
					...read,
					value: { ...read.value, participants: [...read.value.participants, first as never] },
				};
			},
		}));
		expect(repeats).toContain(CASE.join);
	});

	it("refuses an open that answers opened over another record, or for an end already past", async () => {
		const overwrites = await refusedBy((store) => ({
			...store,
			open: async (sid, sub, expiresAt) => {
				await store.open(sid, sub, expiresAt);
				return { outcome: "opened" };
			},
		}));
		expect(overwrites).toContain(CASE.reopen);
		expect(overwrites).toContain(CASE.lateOpen);
		expect(overwrites).toContain(CASE.monotonic);
		expect(overwrites).toContain(CASE.lapse);
	});

	it("refuses a join or a close that creates a record for a sid with none", async () => {
		const refused = await refusedBy((store, harness) => ({
			...store,
			join: async (sid, participant) => {
				const now = harness.clock?.now() ?? Date.now();
				if ((await store.read(sid)) === null)
					await store.open(sid, "adopted", new Date(now + 60_000));
				return store.join(sid, participant);
			},
		}));
		expect(refused).toContain(CASE.missing);
	});

	it("refuses a close that leaves out the participants' work, or the snapshot", async () => {
		const noWork = await refusedBy((store) => ({
			...store,
			beginClose: (sid, request) => store.beginClose(sid, { ...request, perParticipant: [] }),
		}));
		expect(noWork).toContain(CASE.close);
		const noSnapshot = await refusedBy((store) => ({
			...store,
			beginClose: async (sid, request) => {
				const answer = await store.beginClose(sid, request);
				return answer.outcome === "missing"
					? answer
					: { ...answer, record: { ...answer.record, participants: [] } };
			},
		}));
		expect(noSnapshot).toContain(CASE.close);
	});

	it("refuses a join that answers joined after the close committed", async () => {
		const refused = await refusedBy((store) => ({
			...store,
			join: async (sid, participant) => {
				const answer = await store.join(sid, participant);
				return answer.outcome === "closed" ? { outcome: "joined" } : answer;
			},
		}));
		expect(refused).toContain(CASE.afterClose);
		expect(refused).toContain(CASE.race);
	});

	it("refuses a join that checks the state, then writes in a later step", async () => {
		const refused = await refusedBy((store) => ({
			...store,
			join: async (sid, participant) => {
				const before = await store.read(sid);
				if (before === null) return { outcome: "missing" };
				if (before.value.state !== "active") return { outcome: "closed" };
				await yieldTurn();
				await store.join(sid, participant);
				return { outcome: "joined" };
			},
		}));
		expect(refused).toContain(CASE.race);
	});

	it("refuses a repeated close that commits again, or starts the work over", async () => {
		const recommits = await refusedBy((store) => ({
			...store,
			beginClose: async (sid, request) => {
				const answer = await store.beginClose(sid, request);
				return answer.outcome === "missing"
					? answer
					: { ...answer, generation: newStoreGeneration() };
			},
		}));
		expect(recommits).toContain(CASE.idempotent);
		const startsOver = await refusedBy((store) => {
			const first = new Map<string, Awaited<ReturnType<SessionLifecycleStore["beginClose"]>>>();
			return {
				...store,
				beginClose: async (sid, request) => {
					const answer = await store.beginClose(sid, request);
					if (answer.outcome !== "closing") return answer;
					const saved = first.get(sid);
					if (saved === undefined) {
						first.set(sid, answer);
						return answer;
					}
					return saved.outcome === "missing" ? answer : { ...answer, record: saved.record };
				},
			};
		});
		expect(startsOver).toContain(CASE.resumable);
	});

	it("refuses a completion that ignores the generation", async () => {
		const refused = await refusedBy((store) => ({
			...store,
			completeIf: async (sid, _expected, item) => {
				const now = await store.read(sid);
				if (now === null) return { outcome: "missing" };
				return store.completeIf(sid, now.generation, item);
			},
		}));
		expect(refused).toContain(CASE.complete);
	});

	it("refuses a completion that answers updated for a race it lost", async () => {
		const refused = await refusedBy((store) => ({
			...store,
			completeIf: async (sid, expected, item) => {
				const answer = await store.completeIf(sid, expected, item);
				if (answer.outcome !== "conflict") return answer;
				const now = await store.read(sid);
				return now !== null && !now.value.close?.pending.includes(item)
					? { outcome: "updated", generation: now.generation }
					: answer;
			},
		}));
		expect(refused).toContain(CASE.completeRace);
	});

	it("refuses a record that stays closing with nothing pending", async () => {
		const refused = await refusedBy((store) => ({
			...store,
			beginClose: async (sid, request) => {
				const answer = await store.beginClose(sid, request);
				if (answer.outcome !== "closed") return answer;
				return { ...answer, outcome: "closing", record: { ...answer.record, state: "closing" } };
			},
		}));
		expect(refused).toContain(CASE.closed);
	});

	it("refuses a store that answers a closed record as active", async () => {
		const refused = await refusedBy((store) => ({
			...store,
			read: async (sid) => {
				const read = await store.read(sid);
				if (read === null || read.value.state !== "closed") return read;
				return { ...read, value: { ...read.value, state: "active", close: undefined } };
			},
		}));
		expect(refused).toContain(CASE.monotonic);
	});

	it("refuses a listing that names a record not closing, or more than its limit", async () => {
		const every = await refusedBy((store) => {
			const seen = new Set<string>();
			return {
				...store,
				open: async (sid, sub, expiresAt) => {
					seen.add(sid);
					return store.open(sid, sub, expiresAt);
				},
				listClosing: async () => [...seen],
			};
		});
		expect(every).toContain(CASE.listing);
		const unbounded = await refusedBy((store) => ({
			...store,
			listClosing: () => store.listClosing(1000),
		}));
		expect(unbounded).toContain(CASE.listing);
	});

	it("refuses a listing that ignores its cursor", async () => {
		const refused = await refusedBy((store) => ({
			...store,
			listClosing: (limit) => store.listClosing(limit),
		}));
		expect(refused).toContain(CASE.listing);
	});

	it("refuses a record answered with its close left out, a field of its own, or as a class instance", async () => {
		const reshape =
			(change: (record: SessionLifecycleRecord) => SessionLifecycleRecord): Fault =>
			(store) => ({
				...store,
				read: async (sid) => {
					const read = await store.read(sid);
					return read === null ? null : { ...read, value: change(read.value) };
				},
				beginClose: async (sid, request) => {
					const answer = await store.beginClose(sid, request);
					return answer.outcome === "missing"
						? answer
						: { ...answer, record: change(answer.record) };
				},
			});
		class Record {}
		for (const change of [
			(record: SessionLifecycleRecord) => {
				if (record.close !== undefined) return record;
				const { close: _left, ...rest } = record;
				return rest as SessionLifecycleRecord;
			},
			(record: SessionLifecycleRecord) => ({ ...record, extra: true }),
			(record: SessionLifecycleRecord) => ({
				...record,
				participants: record.participants.map((p) => ({ ...p, joinedAt: 0 })),
			}),
			(record: SessionLifecycleRecord) => Object.assign(new Record(), record),
		]) {
			const refused = await refusedBy(reshape(change));
			expect(refused).toContain(CASE.join);
		}
		const closeOnly = await refusedBy(
			reshape((record) =>
				record.close === undefined ? record : { ...record, close: { ...record.close, extra: 1 } },
			),
		);
		expect(closeOnly).toContain(CASE.close);
	});

	it("refuses a repeated open answered opened from the session's end on", async () => {
		const refused = await refusedBy((store) => ({
			...store,
			open: async (sid, sub, expiresAt) => {
				const answer = await store.open(sid, sub, expiresAt);
				const read = await store.read(sid);
				return answer.outcome === "refused" &&
					read?.value.state === "active" &&
					read.value.sub === sub &&
					read.value.expiresAt.getTime() === expiresAt.getTime()
					? { outcome: "opened" }
					: answer;
			},
		}));
		expect(refused).toContain(CASE.expiredJoin);
	});

	it("refuses malformed answers", async () => {
		const generation = await refusedBy((store) => ({
			...store,
			read: async (sid) => {
				const read = await store.read(sid);
				return read === null ? null : { ...read, generation: "" as never };
			},
		}));
		expect(generation).toContain(CASE.readers);
		const outcome = await refusedBy((store) => ({
			...store,
			join: async (sid, participant) => {
				const answer = await store.join(sid, participant);
				return (answer.outcome === "joined" ? { outcome: "ok" } : answer) as never;
			},
		}));
		expect(outcome).toContain(CASE.readers);
	});

	it("refuses a store that hands out the record it holds", async () => {
		const refused = await refusedBy((store) => {
			const held = new Map<string, Versioned<SessionLifecycleRecord>>();
			return {
				...store,
				read: async (sid) => {
					const read = await store.read(sid);
					if (read === null) return null;
					const kept = held.get(sid);
					if (kept !== undefined && kept.generation === read.generation) return kept;
					held.set(sid, read);
					return read;
				},
			};
		});
		expect(refused).toContain(CASE.copies);
	});

	it("refuses a close that reaches another sid", async () => {
		const refused = await refusedBy((store) => {
			const seen = new Set<string>();
			return {
				...store,
				open: async (sid, sub, expiresAt) => {
					seen.add(sid);
					return store.open(sid, sub, expiresAt);
				},
				beginClose: async (sid, request) => {
					for (const other of seen) if (other !== sid) await store.beginClose(other, request);
					return store.beginClose(sid, request);
				},
			};
		});
		expect(refused).toContain(CASE.apart);
	});

	it("refuses a join that ignores the session's end", async () => {
		const refused = await refusedBy((store) => ({
			...store,
			join: async (sid, participant) => {
				const answer = await store.join(sid, participant);
				const read = await store.read(sid);
				return answer.outcome === "closed" && read?.value.state === "active"
					? { outcome: "joined" }
					: answer;
			},
		}));
		expect(refused).toContain(CASE.expiredJoin);
	});

	it("refuses a closing record that lapses with the session rather than with its work", async () => {
		const refused = await refusedBy((store, harness) => ({
			...store,
			read: async (sid) => {
				const read = await store.read(sid);
				const now = harness.clock?.now() ?? Date.now();
				return read !== null && read.value.expiresAt.getTime() + 300_000 <= now ? null : read;
			},
		}));
		expect(refused).toContain(CASE.retention);
	});

	it("refuses a store whose record outlives its retention in part", async () => {
		const refused = await refusedBy((store) => {
			const last = new Map<string, Versioned<SessionLifecycleRecord>>();
			return {
				...store,
				read: async (sid) => {
					const read = await store.read(sid);
					if (read !== null) last.set(sid, read);
					return read ?? last.get(sid) ?? null;
				},
			};
		});
		expect(refused).toContain(CASE.lapse);
	});

	it("refuses an outage answered as missing, null or closed", async () => {
		const refused = await refusedBy((store) => store, ALL);
		expect(refused).not.toContain(CASE.outage);
		const cases = sessionLifecycleStoreContract({
			build: async () => ({
				...(await memoryHarness()()),
				unreachable: () => ({
					kind: "quiet",
					open: async () => ({ outcome: "refused" }),
					join: async () => ({ outcome: "missing" }),
					beginClose: async () => ({ outcome: "missing" }),
					completeIf: async () => ({ outcome: "missing" }),
					read: async () => null,
					listClosing: async () => [],
				}),
			}),
			supports: ALL,
		});
		await expect(cases.find((c) => c.name === CASE.outage)?.run()).rejects.toThrow();
	});
});
