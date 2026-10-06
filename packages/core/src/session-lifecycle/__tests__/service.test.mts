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
 * The session lifecycle service over core's in-process stores: what a join
 * writes and refuses, what a close runs and in which order, what it answers
 * once its closing commit has landed, how a later close and the sweep resume
 * a close left pending, what each cause runs, and what liveness reads.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
	createInMemorySessionFamilyIndex,
	createInMemorySessionFederationIndex,
	createInMemorySessionLifecycleStore,
	createInMemorySessionRPRegistry,
	createInMemorySubjectSessionIndex,
	createInMemoryUserSessionStore,
	createSessionLifecycle,
	DEFAULT_CLOCK_SKEW_MS,
	type FederationTokenStore,
	type RefreshTokenFamilyRevocation,
	type RegisteredRP,
	readVersionedSessionLifecycle,
	SESSION_CLOSE_CAUSES,
	type SessionCloseNotice,
	type SessionCloseNotifier,
	type SessionLifecycleStore,
	type SessionOpenAnswer,
	type UserSessionStore,
} from "#/index.mjs";

const SID = "sid-1";
const SUB = "user-1";
const DAY = 24 * 60 * 60 * 1000;

const relyingParty = (clientId: string): RegisteredRP => ({
	clientId,
	backchannelLogoutUri: `https://${clientId}.example/logout`,
	backchannelLogoutSessionRequired: true,
	frontchannelLogoutUri: undefined,
	frontchannelLogoutSessionRequired: undefined,
	registeredAt: new Date(),
});

/** Every work call the service made, in order, by the name of what it did. */
type Calls = string[];

interface HarnessOptions {
	readonly notifier?: boolean;
	/** How the service reads the recording notifier; `() => notifier` by default. */
	readonly notifierOf?: (notifier: SessionCloseNotifier) => () => SessionCloseNotifier | undefined;
	readonly subjectSessionIndex?: boolean;
	readonly store?: (inner: SessionLifecycleStore) => SessionLifecycleStore;
	/** A family index without the session-end capability: it keeps no end mark. */
	readonly familyIndexWithoutEnd?: boolean;
	/** The lifecycle store's options. */
	readonly lifecycleStore?: { readonly maxParticipants?: number; readonly now?: () => number };
	/** Awaited before a revocation or a notice does its work, by the name of the call. */
	readonly slow?: (call: string) => Promise<void> | undefined;
}

function harness(options: HarnessOptions = {}) {
	const calls: Calls = [];
	/** Every line the service logged, by level, as `[fields, event]`. */
	const lines: { warn: [unknown, string][]; error: [unknown, string][] } = { warn: [], error: [] };
	/** Work call name → how many more times it fails (Infinity: always). */
	const failing = new Map<string, number>();
	const failIfAsked = (call: string): void => {
		const left = failing.get(call) ?? 0;
		if (left > 0) {
			failing.set(call, left - 1);
			throw new Error(`${call} is down`);
		}
	};
	const record = (call: string): void => {
		failIfAsked(call);
		calls.push(call);
	};

	const inner = createInMemorySessionLifecycleStore(options.lifecycleStore ?? {});
	const store = options.store === undefined ? inner : options.store(inner);
	const sessions = createInMemoryUserSessionStore();
	const userSessionStore: UserSessionStore = {
		kind: sessions.kind,
		create: (input) => sessions.create(input),
		get: (sid) => sessions.get(sid),
		async delete(sid) {
			record("delete_user_session");
			await sessions.delete(sid);
		},
	};
	const sessionRPRegistry = createInMemorySessionRPRegistry();
	const sessionFamilyIndex = createInMemorySessionFamilyIndex();
	const sessionFederationIndex = createInMemorySessionFederationIndex();
	const subjects = createInMemorySubjectSessionIndex();
	const revoked = new Set<string>();
	const refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation = {
		async revokeFamily(familyId) {
			await options.slow?.(`revoke_family:${familyId}`);
			record(`revoke_family:${familyId}`);
			revoked.add(familyId);
		},
		async isFamilyRevoked(familyId) {
			return revoked.has(familyId);
		},
	};
	const federationTokenStore = {
		async removeBySid(sid: string) {
			record(`remove_federation_tokens:${sid}`);
		},
		async delete(sid: string, federation: string) {
			record(`delete_federation_tokens:${sid}:${federation}`);
		},
	} as unknown as FederationTokenStore;
	const notices: SessionCloseNotice[] = [];
	const notifier: SessionCloseNotifier = {
		async notify(notice) {
			await options.slow?.(`notify:${notice.clientId}`);
			record(`notify:${notice.clientId}`);
			notices.push(notice);
		},
	};
	const subjectSessionIndex = {
		...subjects,
		async removeSid(subject: string, sid: string) {
			record(`remove_subject_session:${sid}`);
			await subjects.removeSid(subject, sid);
		},
	};

	const lifecycle = createSessionLifecycle({
		store,
		userSessionStore,
		refreshTokenFamilyRevocation,
		federationTokenStore,
		...(options.subjectSessionIndex === false ? {} : { subjectSessionIndex }),
		...(options.notifier === false
			? {}
			: { notifier: options.notifierOf?.(notifier) ?? (() => notifier) }),
		sessionRPRegistry,
		sessionFamilyIndex: options.familyIndexWithoutEnd
			? {
					kind: sessionFamilyIndex.kind,
					addFamilyId: (sid, familyId, expiresAt) =>
						sessionFamilyIndex.addFamilyId(sid, familyId, expiresAt),
					listFamilyIds: (sid) => sessionFamilyIndex.listFamilyIds(sid),
					removeBySid: (sid) => sessionFamilyIndex.removeBySid(sid),
				}
			: sessionFamilyIndex,
		sessionFederationIndex,
		retainMs: DAY,
		logger: {
			warn: (fields: unknown, event: string) => {
				lines.warn.push([fields, event]);
			},
			error: (fields: unknown, event: string) => {
				lines.error.push([fields, event]);
			},
		},
	});

	/** A live session `sid`, in the subject index, with its lifecycle record unless `open` is false. */
	const establish = async (sid = SID, { open = true } = {}): Promise<Date> => {
		const expiresAt = new Date(Date.now() + DAY);
		await sessions.create({
			sid,
			sub: SUB,
			authTime: new Date(),
			expiresAt,
			claims: {},
			amr: ["pwd"],
			authentication: undefined,
		});
		await subjects.addSid(SUB, sid, expiresAt);
		if (open) expect((await inner.open(sid, SUB, expiresAt)).outcome).toBe("opened");
		return expiresAt;
	};

	const read = async (sid = SID) => readVersionedSessionLifecycle(await inner.read(sid));

	return {
		lifecycle,
		inner,
		lines,
		calls,
		failing,
		notices,
		revoked,
		sessions,
		subjects,
		sessionRPRegistry,
		sessionFamilyIndex,
		sessionFederationIndex,
		establish,
		read,
	};
}

type Harness = ReturnType<typeof harness>;

/** The service said nothing of an outage: its caller logs it, once, with the error. */
const expectSilentOutage = (h: Harness): void => {
	expect(h.lines.warn).toEqual([]);
	expect(h.lines.error).toEqual([]);
};

/** Sids the lifecycle port cannot hold, by why. */
const UNHOLDABLE_SIDS: readonly (readonly [string, string])[] = [
	["empty", ""],
	["513 characters", "s".repeat(513)],
	["a lone surrogate", "sid-\ud800"],
];

/** A lifecycle store whose every read fails the test: a read of a sid it cannot hold reaches no store. */
const unreadStore = (inner: SessionLifecycleStore): SessionLifecycleStore => ({
	...inner,
	read: async (sid) => {
		throw new Error(`the lifecycle store was read for ${JSON.stringify(sid)}`);
	},
});

/** `sid` joined by relying party `a`, family `f1` and federation `google`. */
const joinAll = async (h: Harness, sid = SID): Promise<void> => {
	expect(
		await h.lifecycle.join(sid, {
			rp: relyingParty("a"),
			familyId: "f1",
			federation: "google",
		}),
	).toEqual({ outcome: "joined" });
};

describe("createSessionLifecycle", () => {
	it("refuses a retainMs that is no whole number of milliseconds within a year", () => {
		const h = harness();
		for (const retainMs of [-1, 1.5, Number.NaN, 366 * DAY]) {
			expect(() =>
				createSessionLifecycle({
					store: h.inner,
					userSessionStore: h.sessions,
					refreshTokenFamilyRevocation: {
						revokeFamily: async () => {},
						isFamilyRevoked: async () => false,
					},
					federationTokenStore: {} as FederationTokenStore,
					sessionRPRegistry: h.sessionRPRegistry,
					sessionFamilyIndex: h.sessionFamilyIndex,
					sessionFederationIndex: h.sessionFederationIndex,
					retainMs,
				}),
			).toThrow(RangeError);
		}
	});
});

describe("join", () => {
	it("joins a relying party, its family and a federation, and writes the old stores beside them", async () => {
		const h = harness();
		await h.establish();
		await joinAll(h);
		const record = await h.read();
		expect(record?.value.state).toBe("active");
		expect(record?.value.participants.map((p) => `${p.kind}:${p.id}`)).toEqual([
			"rp:a",
			"family:f1",
			"federation:google",
		]);
		expect((await h.sessionRPRegistry.listRPs(SID)).map((rp) => rp.clientId)).toEqual(["a"]);
		expect(await h.sessionFamilyIndex.listFamilyIds(SID)).toEqual(["f1"]);
		expect(await h.sessionFederationIndex.listFederations(SID)).toEqual(["google"]);
	});

	it("refuses once the close has committed, and revokes the family and removes the federation tokens it was handed", async () => {
		const h = harness();
		await h.establish();
		h.failing.set("notify:a", Number.POSITIVE_INFINITY);
		await joinAll(h);
		expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("pending");
		h.calls.length = 0;
		expect(
			await h.lifecycle.join(SID, { rp: relyingParty("b"), familyId: "f2", federation: "github" }),
		).toEqual({ outcome: "refused" });
		expect(h.calls).toEqual(["revoke_family:f2", "delete_federation_tokens:sid-1:github"]);
		expect((await h.read())?.value.participants.map((p) => p.id)).not.toContain("f2");
	});

	it("refuses a session whose user session is gone", async () => {
		const h = harness();
		await h.establish();
		await h.sessions.delete(SID);
		expect(await h.lifecycle.join(SID, { rp: relyingParty("a"), familyId: "f1" })).toEqual({
			outcome: "refused",
		});
		expect(h.revoked.has("f1")).toBe(true);
	});

	it("adopts an absent record when a family joins and no old end mark is present", async () => {
		const h = harness();
		await h.establish(SID, { open: false });
		expect(await h.lifecycle.join(SID, { rp: relyingParty("a"), familyId: "f1" })).toEqual({
			outcome: "joined",
		});
		const record = await h.read();
		expect(record?.value.state).toBe("active");
		expect(record?.value.sub).toBe(SUB);
		expect(record?.value.participants.map((p) => `${p.kind}:${p.id}`)).toEqual([
			"rp:a",
			"family:f1",
		]);
	});

	it("adopts nothing once an old end mark is present", async () => {
		const h = harness();
		const expiresAt = await h.establish(SID, { open: false });
		await h.sessionFamilyIndex.endSession(SID, expiresAt);
		expect(await h.lifecycle.join(SID, { rp: relyingParty("a"), familyId: "f1" })).toEqual({
			outcome: "refused",
		});
		expect(await h.read()).toBeNull();
		expect(h.revoked.has("f1")).toBe(true);
	});

	it("adopts nothing for a join with no family, which cannot read the old end mark", async () => {
		const h = harness();
		await h.establish(SID, { open: false });
		expect(await h.lifecycle.join(SID, { federation: "google" })).toEqual({ outcome: "refused" });
		expect(await h.read()).toBeNull();
		expect(await h.sessionFederationIndex.listFederations(SID)).toEqual([]);
	});

	it("adopts an absent record for any join where the family index keeps no end mark", async () => {
		const h = harness({ familyIndexWithoutEnd: true });
		await h.establish(SID, { open: false });
		expect(await h.lifecycle.join(SID, { federation: "google" })).toEqual({ outcome: "joined" });
		expect((await h.read())?.value.participants.map((p) => p.id)).toEqual(["google"]);
	});

	it("lets two adopting joins at once both join, onto one record", async () => {
		const h = harness({ familyIndexWithoutEnd: true });
		await h.establish(SID, { open: false });
		const answers = await Promise.all([
			h.lifecycle.join(SID, { rp: relyingParty("a") }),
			h.lifecycle.join(SID, { rp: relyingParty("b") }),
		]);
		expect(answers).toEqual([{ outcome: "joined" }, { outcome: "joined" }]);
		const record = await h.read();
		expect(record?.value.state).toBe("active");
		expect(record?.value.participants.map((p) => p.id).sort()).toEqual(["a", "b"]);
	});

	it("refuses a join whose session a close ended, and whose closed record went, while it adopted the record", async () => {
		// The race: the join reads no record and a live user session; before
		// it opens the record, a close of the session completes and its closed
		// record leaves the store. The open then finds no record to refuse it.
		let current: SessionLifecycleStore | undefined;
		let closeDuringOpen: (() => Promise<void>) | undefined;
		const h = harness({
			familyIndexWithoutEnd: true,
			store: (inner) => {
				current = inner;
				const now = (): SessionLifecycleStore => current ?? inner;
				return {
					kind: inner.kind,
					open: async (sid, sub, expiresAt) => {
						const race = closeDuringOpen;
						closeDuringOpen = undefined;
						if (race !== undefined) await race();
						return now().open(sid, sub, expiresAt);
					},
					join: (sid, participant) => now().join(sid, participant),
					beginClose: (sid, request) => now().beginClose(sid, request),
					completeIf: (sid, expected, item) => now().completeIf(sid, expected, item),
					read: (sid) => now().read(sid),
					listClosing: (limit, after) => now().listClosing(limit, after),
				};
			},
		});
		await h.establish(SID, { open: false });
		closeDuringOpen = async () => {
			expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("done");
			current = createInMemorySessionLifecycleStore();
		};
		expect(await h.lifecycle.join(SID, { familyId: "f-late", federation: "google" })).toEqual({
			outcome: "refused",
		});
		expect(h.revoked.has("f-late")).toBe(true);
		// Once by the close, which lists it through the per-session index the
		// join wrote first, and once by the refused join's withdraw.
		expect(h.calls.filter((call) => call === "revoke_family:f-late")).toHaveLength(2);
		expect(h.calls).toContain(`delete_federation_tokens:${SID}:google`);
		expect(await h.lifecycle.liveness(SID)).toEqual({ outcome: "not_live" });
	});

	describe("a join that adopts, when the sid is closed and its session replaced meanwhile", () => {
		/** A harness whose store runs `race` once, inside the next `open`, then answers from `current`. */
		const racing = () => {
			const state: {
				current?: SessionLifecycleStore;
				race?: () => Promise<void>;
			} = {};
			const h = harness({
				familyIndexWithoutEnd: true,
				store: (inner) => {
					state.current = inner;
					const now = (): SessionLifecycleStore => state.current ?? inner;
					return {
						kind: inner.kind,
						open: async (sid, sub, expiresAt) => {
							const race = state.race;
							state.race = undefined;
							if (race !== undefined) await race();
							return now().open(sid, sub, expiresAt);
						},
						join: (sid, participant) => now().join(sid, participant),
						beginClose: (sid, request) => now().beginClose(sid, request),
						completeIf: (sid, expected, item) => now().completeIf(sid, expected, item),
						read: (sid) => now().read(sid),
						listClosing: (limit, after) => now().listClosing(limit, after),
					};
				},
			});
			return { h, state };
		};

		/** A new user session under `SID`, the closed one's record gone from the store. */
		const replace = async (
			h: Harness,
			state: { current?: SessionLifecycleStore },
			sub: string,
			expiresAt: Date,
			{ open }: { readonly open: boolean },
		): Promise<SessionLifecycleStore> => {
			expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("done");
			const fresh = createInMemorySessionLifecycleStore();
			state.current = fresh;
			await h.sessions.create({
				sid: SID,
				sub,
				authTime: new Date(),
				expiresAt,
				claims: {},
				amr: ["pwd"],
				authentication: undefined,
			});
			if (open) expect((await fresh.open(SID, sub, expiresAt)).outcome).toBe("opened");
			return fresh;
		};

		it("is refused and withdrawn when the replacement holds its record, which gets no participant", async () => {
			const { h, state } = racing();
			await h.establish(SID, { open: false });
			let fresh: SessionLifecycleStore | undefined;
			state.race = async () => {
				fresh = await replace(h, state, "someone-else", new Date(Date.now() + DAY), { open: true });
			};
			expect(await h.lifecycle.join(SID, { familyId: "f-stale" })).toEqual({ outcome: "refused" });
			expect(h.revoked.has("f-stale")).toBe(true);
			// Once by the close, which lists it through the per-session index the
			// join wrote first, and once by the refused join's withdraw.
			expect(h.calls.filter((call) => call === "revoke_family:f-stale")).toHaveLength(2);
			const record = readVersionedSessionLifecycle(
				await (fresh as SessionLifecycleStore).read(SID),
			);
			expect(record?.value.sub).toBe("someone-else");
			expect(record?.value.participants).toEqual([]);
		});

		it("is refused and withdrawn when the replacement has the same subject but another end", async () => {
			const { h, state } = racing();
			await h.establish(SID, { open: false });
			state.race = async () => {
				await replace(h, state, SUB, new Date(Date.now() + 2 * DAY), { open: false });
			};
			expect(await h.lifecycle.join(SID, { familyId: "f-stale" })).toEqual({ outcome: "refused" });
			expect(h.revoked.has("f-stale")).toBe(true);
			// Once by the close, which lists it through the per-session index the
			// join wrote first, and once by the refused join's withdraw.
			expect(h.calls.filter((call) => call === "revoke_family:f-stale")).toHaveLength(2);
		});
	});

	it("rejects with the store's own error when the lifecycle store cannot answer, saying nothing", async () => {
		const down = new Error("lifecycle store down");
		const h = harness({
			store: (inner) => ({
				...inner,
				join: async () => {
					throw down;
				},
			}),
		});
		await h.establish();
		await expect(h.lifecycle.join(SID, { rp: relyingParty("a"), familyId: "f1" })).rejects.toBe(
			down,
		);
		expectSilentOutage(h);
	});

	it("rejects with the per-session store's own error when the bridge cannot write the join, saying nothing", async () => {
		const down = new Error("relying-party registry down");
		const h = harness();
		await h.establish();
		h.sessionRPRegistry.registerRP = async () => {
			throw down;
		};
		await expect(h.lifecycle.join(SID, { rp: relyingParty("a"), familyId: "f1" })).rejects.toBe(
			down,
		);
		expectSilentOutage(h);
	});

	it("refuses a request that joins nothing with a RangeError", async () => {
		const h = harness();
		await expect(h.lifecycle.join(SID, {})).rejects.toThrow(RangeError);
	});
});

describe("open", () => {
	const inADay = (): Date => new Date(Date.now() + DAY);

	it("writes the record active for the subject and end, with no participant", async () => {
		const h = harness();
		const expiresAt = inADay();
		expect(await h.lifecycle.open(SID, { sub: SUB, expiresAt })).toEqual({ outcome: "opened" });
		const record = await h.read();
		expect(record?.value).toMatchObject({ sub: SUB, state: "active", participants: [] });
		expect(record?.value.expiresAt.getTime()).toBe(expiresAt.getTime());
	});

	it("lets a join with no family land on the opened session, which an absent record would refuse", async () => {
		const h = harness();
		const expiresAt = await h.establish(SID, { open: false });
		expect(await h.lifecycle.open(SID, { sub: SUB, expiresAt })).toEqual({ outcome: "opened" });
		expect(await h.lifecycle.join(SID, { federation: "google" })).toEqual({ outcome: "joined" });
	});

	it("is idempotent: a repeat for the same subject and end answers opened and keeps what joined", async () => {
		const h = harness();
		const expiresAt = await h.establish(SID, { open: false });
		expect(await h.lifecycle.open(SID, { sub: SUB, expiresAt })).toEqual({ outcome: "opened" });
		await joinAll(h);
		const before = await h.read();
		expect(
			await h.lifecycle.open(SID, { sub: SUB, expiresAt: new Date(expiresAt.getTime()) }),
		).toEqual({ outcome: "opened" });
		expect(await h.read()).toEqual(before);
	});

	it("refuses a sid holding another subject's record, or a closing one, and writes nothing", async () => {
		const h = harness();
		const expiresAt = await h.establish();
		const before = await h.read();
		expect(await h.lifecycle.open(SID, { sub: "user-2", expiresAt })).toEqual({
			outcome: "refused",
		});
		expect(await h.read()).toEqual(before);
		h.failing.set("delete_user_session", Number.POSITIVE_INFINITY);
		expect((await h.lifecycle.close(SID, "session_logout")).outcome).toBe("pending");
		const closing = await h.read();
		expect(await h.lifecycle.open(SID, { sub: SUB, expiresAt })).toEqual({ outcome: "refused" });
		expect(await h.read()).toEqual(closing);
	});

	it("refuses a repeat for the same subject with another end, and a closed record, writing nothing", async () => {
		const h = harness();
		const expiresAt = await h.establish();
		const before = await h.read();
		expect(
			await h.lifecycle.open(SID, { sub: SUB, expiresAt: new Date(expiresAt.getTime() + 1) }),
		).toEqual({ outcome: "refused" });
		expect(await h.read()).toEqual(before);
		expect((await h.lifecycle.close(SID, "session_logout")).outcome).toBe("done");
		const closed = await h.read();
		expect(closed?.value.state).toBe("closed");
		expect(await h.lifecycle.open(SID, { sub: SUB, expiresAt })).toEqual({ outcome: "refused" });
		expect(await h.read()).toEqual(closed);
	});

	it("refuses an end already past and writes nothing", async () => {
		const h = harness();
		expect(
			await h.lifecycle.open(SID, { sub: SUB, expiresAt: new Date(Date.now() - 1000) }),
		).toEqual({ outcome: "refused" });
		expect(await h.read()).toBeNull();
	});

	it("rejects with the store's own error when the lifecycle store cannot answer, or with the reader's when it answers outside the port, saying nothing", async () => {
		const error = new Error("lifecycle store down");
		const down = harness({
			store: (inner) => ({
				...inner,
				open: async () => {
					throw error;
				},
			}),
		});
		await expect(down.lifecycle.open(SID, { sub: SUB, expiresAt: inADay() })).rejects.toBe(error);
		expectSilentOutage(down);
		const malformed = harness({
			store: (inner) => ({
				...inner,
				open: async () => ({ outcome: "joined" }) as unknown as SessionOpenAnswer,
			}),
		});
		await expect(
			malformed.lifecycle.open(SID, { sub: SUB, expiresAt: inADay() }),
		).rejects.toThrow();
		expectSilentOutage(malformed);
	});

	it("refuses a sid, sub or end the port cannot hold with a RangeError, before the store is asked", async () => {
		let asked = 0;
		const h = harness({
			store: (inner) => ({
				...inner,
				open: (...args) => {
					asked += 1;
					return inner.open(...args);
				},
			}),
		});
		await expect(h.lifecycle.open("", { sub: SUB, expiresAt: inADay() })).rejects.toThrow(
			RangeError,
		);
		await expect(h.lifecycle.open(SID, { sub: "", expiresAt: inADay() })).rejects.toThrow(
			RangeError,
		);
		await expect(
			h.lifecycle.open(SID, { sub: SUB, expiresAt: new Date(Number.NaN) }),
		).rejects.toThrow(RangeError);
		expect(asked).toBe(0);
	});
});

describe("close", () => {
	it("runs every item, the subject's index entry last, and answers done with the relying parties and federations", async () => {
		const h = harness();
		await h.establish();
		await joinAll(h);
		h.calls.length = 0;
		expect(await h.lifecycle.close(SID, "rp_logout")).toEqual({
			outcome: "done",
			rps: ["a"],
			federations: ["google"],
		});
		expect([...h.calls].sort()).toEqual([
			"delete_user_session",
			"notify:a",
			"remove_federation_tokens:sid-1",
			"remove_subject_session:sid-1",
			"revoke_family:f1",
		]);
		// Revocations and removals first, then the relying parties, then the
		// user session, and the subject's index entry last.
		expect(h.calls.indexOf("notify:a")).toBeGreaterThan(h.calls.indexOf("revoke_family:f1"));
		expect(h.calls.at(-2)).toBe("delete_user_session");
		expect(h.calls.at(-1)).toBe("remove_subject_session:sid-1");
		expect(h.notices).toEqual([{ sid: SID, sub: SUB, clientId: "a", cause: "rp_logout" }]);
		expect((await h.read())?.value.state).toBe("closed");
		expect(await h.sessions.get(SID)).toBeNull();
		expect(await h.subjects.listSids(SUB)).toEqual([]);
		expect(await h.sessionRPRegistry.listRPs(SID)).toEqual([]);
		expect(await h.sessionFamilyIndex.listFamilyIds(SID)).toEqual([]);
		expect(await h.sessionFederationIndex.listFederations(SID)).toEqual([]);
	});

	it("writes the old end mark before it commits, so a join through the old stores after it is refused", async () => {
		const h = harness();
		const expiresAt = await h.establish();
		await h.lifecycle.close(SID, "session_logout");
		expect(await h.sessionFamilyIndex.addFamilyIdUnlessEnded(SID, "late", expiresAt)).toBe("ended");
	});

	it("answers pending when an item fails after the closing commit, keeping the record closing and the user session", async () => {
		const h = harness();
		await h.establish();
		await joinAll(h);
		h.failing.set("revoke_family:f1", 1);
		expect(await h.lifecycle.close(SID, "rp_logout")).toEqual({
			outcome: "pending",
			rps: ["a"],
			federations: ["google"],
		});
		const record = await h.read();
		expect(record?.value.state).toBe("closing");
		expect(record?.value.close?.pending).toEqual(
			expect.arrayContaining([
				"family:f1",
				"rp:a",
				"remove_session_indexes",
				"delete_user_session",
				"remove_subject_session",
			]),
		);
		// Nothing of a later phase runs over a revocation not yet recorded.
		expect(h.notices).toEqual([]);
		expect(await h.sessionFamilyIndex.listFamilyIds(SID)).toEqual(["f1"]);
		expect(await h.sessions.get(SID)).not.toBeNull();
		expect(h.calls).not.toContain("delete_user_session");
	});

	it.each([
		["a revocation", "revoke_family:f1"],
		["a notice", "notify:a"],
		["the user session's delete", "delete_user_session"],
	])(
		"keeps the sid in the subject's index while %s keeps the close pending, and a later close removes it",
		async (_, failing) => {
			const h = harness();
			await h.establish();
			await joinAll(h);
			h.failing.set(failing, 1);
			expect((await h.lifecycle.close(SID, "subject_revocation")).outcome).toBe("pending");
			expect(await h.subjects.listSids(SUB)).toEqual([SID]);
			expect((await h.read())?.value.close?.pending).toContain("remove_subject_session");
			expect((await h.lifecycle.close(SID, "subject_revocation")).outcome).toBe("done");
			expect(await h.subjects.listSids(SUB)).toEqual([]);
			expect(await h.sessions.get(SID)).toBeNull();
		},
	);

	it("keeps the sid listed when its own removal fails, with the user session deleted, and the sweep finishes it", async () => {
		const h = harness();
		await h.establish();
		await joinAll(h);
		h.failing.set(`remove_subject_session:${SID}`, 1);
		expect((await h.lifecycle.close(SID, "subject_revocation")).outcome).toBe("pending");
		expect(await h.sessions.get(SID)).toBeNull();
		expect(await h.subjects.listSids(SUB)).toEqual([SID]);
		expect((await h.read())?.value.close?.pending).toEqual(["remove_subject_session"]);
		expect(await h.lifecycle.resumePending()).toEqual({ done: 1, pending: 0, unavailable: 0 });
		expect(await h.subjects.listSids(SUB)).toEqual([]);
		expect((await h.read())?.value.state).toBe("closed");
	});

	it("resumes a half-ended close on a later close of the same sid, keeping the first cause", async () => {
		const h = harness();
		await h.establish();
		await joinAll(h);
		h.failing.set("revoke_family:f1", 1);
		expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("pending");
		expect((await h.lifecycle.close(SID, "session_logout")).outcome).toBe("done");
		expect(h.revoked.has("f1")).toBe(true);
		expect(await h.sessions.get(SID)).toBeNull();
		const record = await h.read();
		expect(record?.value.state).toBe("closed");
		expect(record?.value.close?.cause).toBe("rp_logout");
		expect(h.notices.map((n) => n.cause)).toEqual(["rp_logout"]);
	});

	it("keeps the record closing while an item keeps failing, and runs the others", async () => {
		const h = harness();
		await h.establish();
		await joinAll(h);
		h.failing.set("notify:a", Number.POSITIVE_INFINITY);
		expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("pending");
		expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("pending");
		expect(h.revoked.has("f1")).toBe(true);
		expect(await h.sessions.get(SID)).not.toBeNull();
		expect([...((await h.read())?.value.close?.pending ?? [])].sort()).toEqual([
			"delete_user_session",
			"remove_session_indexes",
			"remove_subject_session",
			"rp:a",
		]);
		expect((await h.sessionRPRegistry.listRPs(SID)).map((rp) => rp.clientId)).toEqual(["a"]);
	});

	it("rejects with the store's own error when the closing commit cannot land, having run nothing and said nothing", async () => {
		const down = new Error("lifecycle store down");
		const h = harness({
			store: (inner) => ({
				...inner,
				beginClose: async () => {
					throw down;
				},
			}),
		});
		await h.establish();
		await joinAll(h);
		h.calls.length = 0;
		await expect(h.lifecycle.close(SID, "rp_logout")).rejects.toBe(down);
		expectSilentOutage(h);
		expect(h.calls).toEqual([]);
		expect((await h.read())?.value.state).toBe("active");
	});

	it("answers done, running nothing, for a sid with neither a record nor a user session", async () => {
		const h = harness();
		expect(await h.lifecycle.close("unknown", "rp_logout")).toEqual({
			outcome: "done",
			rps: [],
			federations: [],
		});
		expect(h.calls).toEqual([]);
	});

	it("answers a closed session done again and runs nothing more", async () => {
		const h = harness();
		await h.establish();
		await joinAll(h);
		await h.lifecycle.close(SID, "rp_logout");
		h.calls.length = 0;
		expect(await h.lifecycle.close(SID, "rp_logout")).toEqual({
			outcome: "done",
			rps: ["a"],
			federations: ["google"],
		});
		expect(h.calls).toEqual([]);
	});

	it("adopts an absent record and closes what the old stores hold", async () => {
		const h = harness();
		const expiresAt = await h.establish(SID, { open: false });
		await h.sessionRPRegistry.registerRP(SID, relyingParty("old"), expiresAt);
		await h.sessionFamilyIndex.addFamilyIdUnlessEnded(SID, "f-old", expiresAt);
		await h.sessionFederationIndex.addFederation(SID, "github", expiresAt);
		expect(await h.lifecycle.close(SID, "rp_logout")).toEqual({
			outcome: "done",
			rps: ["old"],
			federations: ["github"],
		});
		expect(h.revoked.has("f-old")).toBe(true);
		expect(h.notices.map((n) => n.clientId)).toEqual(["old"]);
		expect(await h.sessions.get(SID)).toBeNull();
		expect((await h.read())?.value.state).toBe("closed");
	});

	it("closes a session whose last join the lifecycle store refused for capacity", async () => {
		const h = harness({ lifecycleStore: { maxParticipants: 1 } });
		await h.establish();
		expect(await h.lifecycle.join(SID, { familyId: "f1" })).toEqual({ outcome: "joined" });
		await expect(h.lifecycle.join(SID, { familyId: "f2" })).rejects.toThrow();
		expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("done");
		expect([...h.revoked].sort()).toEqual(["f1", "f2"]);
		expect((await h.read())?.value.state).toBe("closed");
	});

	it("runs the close work of a session that ended on the store's clock before its record could be opened", async () => {
		let now = Date.now();
		const h = harness({ lifecycleStore: { now: () => now } });
		const expiresAt = await h.establish(SID, { open: false });
		await h.sessionFamilyIndex.addFamilyIdUnlessEnded(SID, "f-old", expiresAt);
		await h.sessionRPRegistry.registerRP(SID, relyingParty("old-rp"), expiresAt);
		now = expiresAt.getTime() + 1;
		h.calls.length = 0;
		expect(await h.lifecycle.close(SID, "rp_logout")).toEqual({
			outcome: "done",
			rps: ["old-rp"],
			federations: [],
		});
		expect([...h.calls].sort()).toEqual([
			"delete_user_session",
			"notify:old-rp",
			"remove_federation_tokens:sid-1",
			"remove_subject_session:sid-1",
			"revoke_family:f-old",
		]);
		expect(h.calls.at(-1)).toBe("remove_subject_session:sid-1");
		expect(await h.sessions.get(SID)).toBeNull();
		expect(await h.lifecycle.liveness(SID)).toEqual({ outcome: "not_live" });
		expect(await h.read()).toBeNull();
	});

	it("answers done to two closes at once of a session that ended on the store's clock with no record", async () => {
		let now = Date.now();
		const h = harness({ lifecycleStore: { now: () => now } });
		const expiresAt = await h.establish(SID, { open: false });
		await h.sessionFamilyIndex.addFamilyIdUnlessEnded(SID, "f-old", expiresAt);
		now = expiresAt.getTime() + 1;
		const answers = await Promise.all([
			h.lifecycle.close(SID, "rp_logout"),
			h.lifecycle.close(SID, "session_logout"),
		]);
		expect(answers.map((a) => a.outcome)).toEqual(["done", "done"]);
		expect(h.revoked.has("f-old")).toBe(true);
		expect(await h.sessions.get(SID)).toBeNull();
		expect(await h.read()).toBeNull();
	});

	it("refuses a join racing the close of a session that ended on the store's clock with no record, and withdraws its family", async () => {
		let now = Date.now();
		const h = harness({ lifecycleStore: { now: () => now } });
		const expiresAt = await h.establish(SID, { open: false });
		now = expiresAt.getTime() + 1;
		const [closed, joined] = await Promise.all([
			h.lifecycle.close(SID, "rp_logout"),
			h.lifecycle.join(SID, { familyId: "f-late" }),
		]);
		expect(closed.outcome).toBe("done");
		expect(joined).toEqual({ outcome: "refused" });
		expect(h.revoked.has("f-late")).toBe(true);
		expect(await h.lifecycle.liveness(SID)).toEqual({ outcome: "not_live" });
	});

	it("runs the close work of a record that lapses between its read and the closing commit", async () => {
		let now = Date.now();
		let expiresAtMs = 0;
		const h = harness({
			lifecycleStore: { now: () => now },
			store: (inner) => ({
				...inner,
				beginClose: async (sid, request) => {
					now = expiresAtMs + DEFAULT_CLOCK_SKEW_MS + 1;
					return inner.beginClose(sid, request);
				},
			}),
		});
		expiresAtMs = (await h.establish()).getTime();
		await joinAll(h);
		h.calls.length = 0;
		expect(await h.lifecycle.close(SID, "rp_logout")).toEqual({
			outcome: "done",
			rps: ["a"],
			federations: ["google"],
		});
		expect([...h.calls].sort()).toEqual([
			"delete_user_session",
			"notify:a",
			"remove_federation_tokens:sid-1",
			"remove_subject_session:sid-1",
			"revoke_family:f1",
		]);
		expect(await h.sessions.get(SID)).toBeNull();
		expect(await h.read()).toBeNull();
	});

	it("rejects when the close work of a lapsed record fails, keeping the user session for a retry", async () => {
		let now = Date.now();
		const h = harness({ lifecycleStore: { now: () => now } });
		const expiresAt = await h.establish(SID, { open: false });
		await h.sessionFamilyIndex.addFamilyIdUnlessEnded(SID, "f-old", expiresAt);
		now = expiresAt.getTime() + 1;
		h.failing.set("revoke_family:f-old", 1);
		// Each failed item has its own close-work line; the rejection names them.
		await expect(h.lifecycle.close(SID, "rp_logout")).rejects.toThrow(
			"the close work of a session with no lifecycle record failed at revoke_bridged_families",
		);
		expect(h.lines.warn).toEqual([
			[
				{
					sid: SID,
					item: "revoke_bridged_families",
					err: expect.objectContaining({ name: "Error" }),
				},
				"session_close_item_failed",
			],
		]);
		expect(h.lines.error).toEqual([]);
		expect(h.calls).not.toContain("delete_user_session");
		expect(await h.sessions.get(SID)).not.toBeNull();
		expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("done");
		expect(h.revoked.has("f-old")).toBe(true);
		expect(await h.sessions.get(SID)).toBeNull();
	});

	it("revokes what joined through the old stores when the close comes after the session's end", async () => {
		let now = Date.now();
		const h = harness({ lifecycleStore: { now: () => now } });
		const expiresAt = await h.establish();
		await h.sessionFamilyIndex.addFamilyIdUnlessEnded(SID, "f-old-node", expiresAt);
		now = expiresAt.getTime() + 1;
		expect((await h.lifecycle.close(SID, "expiry")).outcome).toBe("done");
		expect(h.revoked.has("f-old-node")).toBe(true);
	});

	it("closes what joined through the old stores beside an existing record", async () => {
		const h = harness();
		const expiresAt = await h.establish();
		await joinAll(h);
		await h.sessionFamilyIndex.addFamilyIdUnlessEnded(SID, "f-old-node", expiresAt);
		expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("done");
		expect([...h.revoked].sort()).toEqual(["f-old-node", "f1"]);
	});

	describe("every item is safe to run more than once", () => {
		it("runs an item again when its completion was not recorded, and ends closed", async () => {
			let failNextCompletion = true;
			const h = harness({
				store: (inner) => ({
					...inner,
					completeIf: async (sid, expected, item) => {
						if (failNextCompletion && item === "family:f1") {
							failNextCompletion = false;
							throw new Error("lifecycle store down");
						}
						return inner.completeIf(sid, expected, item);
					},
				}),
			});
			await h.establish();
			await joinAll(h);
			h.calls.length = 0;
			expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("pending");
			expect(h.lines.warn).toEqual([
				[
					{ operation: "complete", sid: SID, err: expect.objectContaining({ name: "Error" }) },
					"session_lifecycle_unavailable",
				],
			]);
			expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("done");
			expect(h.calls.filter((call) => call === "revoke_family:f1")).toHaveLength(2);
			expect(h.revoked.has("f1")).toBe(true);
			expect((await h.read())?.value.state).toBe("closed");
		});

		it("goes on with the other items when one completion cannot be recorded", async () => {
			const h = harness({
				store: (inner) => ({
					...inner,
					completeIf: async (sid, expected, item) => {
						if (item === "family:f1") throw new Error("lifecycle store down");
						return inner.completeIf(sid, expected, item);
					},
				}),
			});
			await h.establish();
			await joinAll(h);
			expect(await h.lifecycle.join(SID, { familyId: "f2" })).toEqual({ outcome: "joined" });
			expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("pending");
			expect(h.revoked.has("f2")).toBe(true);
			expect((await h.read())?.value.close?.pending).not.toContain("family:f2");
		});

		it("lets two closes run at once, each recording what the other has not", async () => {
			const h = harness();
			await h.establish();
			await joinAll(h);
			const answers = await Promise.all([
				h.lifecycle.close(SID, "rp_logout"),
				h.lifecycle.close(SID, "rp_logout"),
				h.lifecycle.resumePending(),
			]);
			expect(answers[0].outcome).toBe("done");
			expect(answers[1].outcome).toBe("done");
			expect((await h.read())?.value.state).toBe("closed");
			expect(await h.sessions.get(SID)).toBeNull();
			expect(h.revoked.has("f1")).toBe(true);
		});
	});
});

describe("a phase's items run together, at most eight at a time", () => {
	/** How long each slow notice takes: the oauth notifier's timeout. */
	const NOTICE_MS = 5_000;

	afterEach(() => {
		vi.useRealTimers();
	});

	/**
	 * A harness whose every call starting with `prefix` (notices by default)
	 * takes `NOTICE_MS`, counting how many are in flight at once.
	 */
	const slowNotices = (prefix = "notify:") => {
		vi.useFakeTimers({ toFake: ["setTimeout"] });
		const flight = { now: 0, most: 0 };
		const h = harness({
			slow: async (call) => {
				if (!call.startsWith(prefix)) return;
				flight.now += 1;
				flight.most = Math.max(flight.most, flight.now);
				await new Promise((resolve) => setTimeout(resolve, NOTICE_MS));
				flight.now -= 1;
			},
		});
		return { h, flight };
	};

	it("tells eight slow relying parties in one notice's time, not eight", async () => {
		const { h } = slowNotices();
		await h.establish();
		for (let i = 0; i < 8; i++) {
			expect(await h.lifecycle.join(SID, { rp: relyingParty(`c${i}`) })).toEqual({
				outcome: "joined",
			});
		}
		const closing = h.lifecycle.close(SID, "rp_logout");
		await vi.advanceTimersByTimeAsync(NOTICE_MS);
		// Every notice has settled, and none is waiting to start.
		expect(vi.getTimerCount()).toBe(0);
		expect((await closing).outcome).toBe("done");
		expect(h.notices).toHaveLength(8);
		expect((await h.read())?.value.state).toBe("closed");
	});

	it("tells eight slow relying parties of the old registry in one notice's time, not eight", async () => {
		const { h } = slowNotices();
		const expiresAt = await h.establish();
		for (let i = 0; i < 8; i++) {
			await h.sessionRPRegistry.registerRP(SID, relyingParty(`old${i}`), expiresAt);
		}
		const closing = h.lifecycle.close(SID, "rp_logout");
		await vi.advanceTimersByTimeAsync(NOTICE_MS);
		expect(vi.getTimerCount()).toBe(0);
		expect((await closing).outcome).toBe("done");
		expect(h.notices).toHaveLength(8);
	});

	it("never has more than eight notices in flight", async () => {
		const { h, flight } = slowNotices();
		await h.establish();
		for (let i = 0; i < 20; i++) await h.lifecycle.join(SID, { rp: relyingParty(`c${i}`) });
		const closing = h.lifecycle.close(SID, "rp_logout");
		await vi.advanceTimersByTimeAsync(3 * NOTICE_MS);
		expect((await closing).outcome).toBe("done");
		expect(flight.most).toBe(8);
		expect(h.notices).toHaveLength(20);
	});

	it("never has more than eight notices in flight across the record's relying parties and the old registry's", async () => {
		const { h, flight } = slowNotices();
		const expiresAt = await h.establish();
		for (let i = 0; i < 10; i++) {
			await h.lifecycle.join(SID, { rp: relyingParty(`c${i}`) });
			await h.sessionRPRegistry.registerRP(SID, relyingParty(`old${i}`), expiresAt);
		}
		const closing = h.lifecycle.close(SID, "rp_logout");
		await vi.advanceTimersByTimeAsync(3 * NOTICE_MS);
		expect((await closing).outcome).toBe("done");
		expect(flight.most).toBe(8);
		expect(h.notices).toHaveLength(20);
	});

	it("never has more than eight revocations in flight across the record's families and the old index's", async () => {
		const { h, flight } = slowNotices("revoke_family:");
		const expiresAt = await h.establish();
		for (let i = 0; i < 10; i++) {
			await h.lifecycle.join(SID, { familyId: `f${i}` });
			await h.sessionFamilyIndex.addFamilyIdUnlessEnded(SID, `old${i}`, expiresAt);
		}
		const closing = h.lifecycle.close(SID, "rp_logout");
		await vi.advanceTimersByTimeAsync(3 * NOTICE_MS);
		expect((await closing).outcome).toBe("done");
		expect(flight.most).toBe(8);
		expect(h.revoked.size).toBe(20);
	});

	it("records each item it ran, and keeps the one that failed pending with the phases after it", async () => {
		const h = harness();
		await h.establish();
		for (let i = 0; i < 8; i++) await h.lifecycle.join(SID, { rp: relyingParty(`c${i}`) });
		h.failing.set("notify:c3", 1);
		expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("pending");
		expect(h.notices.map((n) => n.clientId).sort()).toEqual(
			["c0", "c1", "c2", "c4", "c5", "c6", "c7"].sort(),
		);
		const record = await h.read();
		expect(record?.value.state).toBe("closing");
		expect([...(record?.value.close?.pending ?? [])].sort()).toEqual([
			"delete_user_session",
			"remove_session_indexes",
			"remove_subject_session",
			"rp:c3",
		]);
		expect(h.calls).not.toContain("delete_user_session");
		// A later close sends only the notice that failed.
		expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("done");
		expect(h.notices.filter((n) => n.clientId === "c3")).toHaveLength(1);
		expect(h.notices).toHaveLength(8);
	});

	it("tells the old registry's other relying parties when one fails, keeps the step pending, and tells all three again later", async () => {
		const h = harness();
		const expiresAt = await h.establish();
		for (const clientId of ["old0", "old1", "old2"]) {
			await h.sessionRPRegistry.registerRP(SID, relyingParty(clientId), expiresAt);
		}
		h.failing.set("notify:old1", 1);
		expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("pending");
		expect(h.notices.map((n) => n.clientId).sort()).toEqual(["old0", "old2"]);
		expect((await h.read())?.value.close?.pending).toContain("notify_bridged_rps");
		h.notices.length = 0;
		expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("done");
		expect(h.notices.map((n) => n.clientId).sort()).toEqual(["old0", "old1", "old2"]);
	});

	it("hands a failed notice's place on: the ninth and tenth are told though the first eight fail", async () => {
		const h = harness();
		await h.establish();
		for (let i = 0; i < 10; i++) await h.lifecycle.join(SID, { rp: relyingParty(`c${i}`) });
		for (let i = 0; i < 8; i++) h.failing.set(`notify:c${i}`, 1);
		expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("pending");
		expect(h.notices.map((n) => n.clientId).sort()).toEqual(["c8", "c9"]);
		const pending = (await h.read())?.value.close?.pending ?? [];
		for (let i = 0; i < 8; i++) expect(pending).toContain(`rp:c${i}`);
		expect(pending).not.toContain("rp:c8");
		expect(pending).not.toContain("rp:c9");
	});

	it("starts a phase only once every item of the earlier ones is done, however long each takes", async () => {
		const delays = new Map([
			["revoke_family:f1", 30],
			["revoke_family:f2", 5],
			["revoke_family:f3", 15],
		]);
		const h = harness({
			slow: async (call) => {
				const ms = delays.get(call) ?? 0;
				if (ms > 0) await new Promise((resolve) => setTimeout(resolve, ms));
			},
		});
		await h.establish();
		for (const [i, familyId] of ["f1", "f2", "f3"].entries()) {
			await h.lifecycle.join(SID, { rp: relyingParty(`c${i}`), familyId });
		}
		h.calls.length = 0;
		expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("done");
		const last = (prefix: string) => h.calls.findLastIndex((call) => call.startsWith(prefix));
		const first = (prefix: string) => h.calls.findIndex((call) => call.startsWith(prefix));
		expect(last("revoke_family:")).toBeLessThan(first("notify:"));
		expect(last("notify:")).toBeLessThan(h.calls.indexOf("delete_user_session"));
		expect(h.calls.at(-1)).toBe("remove_subject_session:sid-1");
	});

	it("tells no relying party while a revocation of the phase before has failed, though the others ran", async () => {
		const h = harness();
		await h.establish();
		for (const [i, familyId] of ["f1", "f2", "f3"].entries()) {
			await h.lifecycle.join(SID, { rp: relyingParty(`c${i}`), familyId });
		}
		h.failing.set("revoke_family:f2", 1);
		expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("pending");
		expect([...h.revoked].sort()).toEqual(["f1", "f3"]);
		expect(h.notices).toEqual([]);
		const pending = (await h.read())?.value.close?.pending ?? [];
		expect(pending).toContain("family:f2");
		expect(pending).not.toContain("family:f1");
		expect(pending).not.toContain("family:f3");
	});
});

describe("the notifier, read when a close runs", () => {
	it("is read at the closing commit: none then, no relying-party item is saved", async () => {
		let present = false;
		const h = harness({ notifierOf: (notifier) => () => (present ? notifier : undefined) });
		await h.establish();
		await joinAll(h);
		h.failing.set("revoke_family:f1", 1);
		expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("pending");
		present = true;
		expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("done");
		expect((await h.read())?.value.participants.map((p) => p.id)).toContain("a");
		expect(h.notices).toEqual([]);
	});

	it("is read again when it tells, so the notifier of that moment is the one called", async () => {
		const calls: string[] = [];
		const later: SessionCloseNotifier = {
			notify: async (notice) => {
				calls.push(`later:${notice.clientId}`);
			},
		};
		let current: "first" | "later" = "first";
		const h = harness({
			notifierOf: (notifier) => () => (current === "first" ? notifier : later),
		});
		await h.establish();
		await joinAll(h);
		h.failing.set("notify:a", 1);
		expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("pending");
		current = "later";
		expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("done");
		expect(calls).toEqual(["later:a"]);
	});
});

describe("the cause policy", () => {
	it.each(SESSION_CLOSE_CAUSES)(
		"%s revokes the families, removes the federation tokens and the subject's entry, and deletes the user session",
		async (cause) => {
			const h = harness();
			await h.establish();
			await joinAll(h);
			expect((await h.lifecycle.close(SID, cause)).outcome).toBe("done");
			expect(h.calls).toEqual(
				expect.arrayContaining([
					"revoke_family:f1",
					"remove_federation_tokens:sid-1",
					"remove_subject_session:sid-1",
					"delete_user_session",
				]),
			);
			expect((await h.read())?.value.close?.cause).toBe(cause);
		},
	);

	it.each(SESSION_CLOSE_CAUSES.filter((cause) => cause !== "expiry"))(
		"%s tells every relying party",
		async (cause) => {
			const h = harness();
			await h.establish();
			await joinAll(h);
			await h.lifecycle.close(SID, cause);
			expect(h.notices).toEqual([{ sid: SID, sub: SUB, clientId: "a", cause }]);
		},
	);

	it("expiry tells no relying party", async () => {
		const h = harness();
		await h.establish();
		await joinAll(h);
		expect((await h.lifecycle.close(SID, "expiry")).outcome).toBe("done");
		expect(h.notices).toEqual([]);
	});

	it("saves no relying-party item where no notifier is wired", async () => {
		const h = harness({ notifier: false });
		await h.establish();
		await joinAll(h);
		h.failing.set("revoke_family:f1", 1);
		await h.lifecycle.close(SID, "rp_logout");
		expect((await h.read())?.value.close?.pending).not.toContain("rp:a");
	});

	it("saves no subject-index item where no subject index is wired", async () => {
		const h = harness({ subjectSessionIndex: false });
		await h.establish();
		await joinAll(h);
		expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("done");
		expect(h.calls).not.toContain("remove_subject_session:sid-1");
	});
});

describe("federations", () => {
	it("lists the federations in the order they joined, the per-session index's first, once each", async () => {
		const h = harness();
		const expiresAt = await h.establish();
		expect(await h.lifecycle.join(SID, { familyId: "f1", federation: "oidc" })).toEqual({
			outcome: "joined",
		});
		expect(await h.lifecycle.join(SID, { familyId: "f2", federation: "apple" })).toEqual({
			outcome: "joined",
		});
		await h.sessionFederationIndex.addFederation(SID, "github", expiresAt);
		// Every join wrote the index before the record, so the index holds
		// them all, in join order.
		expect(await h.lifecycle.federations(SID)).toEqual({
			outcome: "listed",
			federations: ["oidc", "apple", "github"],
		});
	});

	it("lists an older federation only the per-session index holds before the record's newer one", async () => {
		const h = harness();
		const expiresAt = await h.establish(SID, { open: false });
		// Joined through the per-session stores alone, before the lifecycle.
		await h.sessionFederationIndex.addFederation(SID, "github", expiresAt);
		// A later join through the service adopts the record with a newer one.
		expect(await h.lifecycle.join(SID, { familyId: "f1", federation: "oidc" })).toEqual({
			outcome: "joined",
		});
		expect(await h.lifecycle.federations(SID)).toEqual({
			outcome: "listed",
			federations: ["github", "oidc"],
		});
		const closed = await h.lifecycle.close(SID, "rp_logout");
		expect(closed.outcome === "unavailable" ? undefined : closed.federations).toEqual([
			"github",
			"oidc",
		]);
	});

	it("lists the per-session index's alone for a session with no record", async () => {
		const h = harness();
		const expiresAt = await h.establish(SID, { open: false });
		await h.sessionFederationIndex.addFederation(SID, "google", expiresAt);
		expect(await h.lifecycle.federations(SID)).toEqual({
			outcome: "listed",
			federations: ["google"],
		});
	});

	it("lists what the close answers for the same session", async () => {
		const h = harness();
		await h.establish();
		await joinAll(h);
		const listed = await h.lifecycle.federations(SID);
		const closed = await h.lifecycle.close(SID, "rp_logout");
		expect(listed.outcome).toBe("listed");
		expect(closed.outcome).not.toBe("unavailable");
		expect(closed.outcome === "unavailable" ? undefined : closed.federations).toEqual(
			listed.outcome === "listed" ? listed.federations : undefined,
		);
		expect(listed.outcome === "listed" ? listed.federations : []).toEqual(["google"]);
	});

	it("rejects with the store's own error when the lifecycle store or the index cannot answer, saying nothing", async () => {
		const down = new Error("lifecycle store down");
		const h = harness({
			store: (inner) => ({
				...inner,
				read: async () => {
					throw down;
				},
			}),
		});
		await h.establish();
		await expect(h.lifecycle.federations(SID)).rejects.toBe(down);
		expectSilentOutage(h);
		const indexDown = new Error("index down");
		const g = harness();
		await g.establish();
		g.sessionFederationIndex.listFederations = async () => {
			throw indexDown;
		};
		await expect(g.lifecycle.federations(SID)).rejects.toBe(indexDown);
		expectSilentOutage(g);
	});

	it.each(UNHOLDABLE_SIDS)(
		"lists none for a sid the port cannot hold (%s), reading no store",
		async (_, sid) => {
			const h = harness({ store: unreadStore });
			expect(await h.lifecycle.federations(sid)).toEqual({ outcome: "listed", federations: [] });
		},
	);
});

describe("liveness", () => {
	it("is live, with the user session, while the record is active", async () => {
		const h = harness();
		await h.establish();
		const answer = await h.lifecycle.liveness(SID);
		expect(answer.outcome).toBe("live");
		expect(answer.outcome === "live" && answer.session.sid).toBe(SID);
	});

	it("is not_live from the closing commit, while the user session is still there", async () => {
		const h = harness();
		await h.establish();
		await joinAll(h);
		h.failing.set("revoke_family:f1", Number.POSITIVE_INFINITY);
		expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("pending");
		expect(await h.sessions.get(SID)).not.toBeNull();
		expect(await h.lifecycle.liveness(SID)).toEqual({ outcome: "not_live" });
	});

	it("is not_live when the user session is gone", async () => {
		const h = harness();
		await h.establish();
		await h.sessions.delete(SID);
		expect(await h.lifecycle.liveness(SID)).toEqual({ outcome: "not_live" });
	});

	it("reads the user session alone for a session with no record", async () => {
		const h = harness();
		await h.establish(SID, { open: false });
		expect((await h.lifecycle.liveness(SID)).outcome).toBe("live");
		expect(await h.lifecycle.liveness("unknown")).toEqual({ outcome: "not_live" });
	});

	it("rejects with the store's own error when the lifecycle store cannot answer, saying nothing", async () => {
		const down = new Error("lifecycle store down");
		const h = harness({
			store: (inner) => ({
				...inner,
				read: async () => {
					throw down;
				},
			}),
		});
		await h.establish();
		await expect(h.lifecycle.liveness(SID)).rejects.toBe(down);
		expectSilentOutage(h);
	});

	it("rejects with the user-session store's own error when it cannot answer, saying nothing", async () => {
		const down = new Error("user-session store down");
		const h = harness();
		await h.establish();
		h.sessions.get = async () => {
			throw down;
		};
		await expect(h.lifecycle.liveness(SID)).rejects.toBe(down);
		expectSilentOutage(h);
	});

	it.each(UNHOLDABLE_SIDS)(
		"is not_live for a sid the port cannot hold (%s), reading no store",
		async (_, sid) => {
			const h = harness({ store: unreadStore });
			expect(await h.lifecycle.liveness(sid)).toEqual({ outcome: "not_live" });
		},
	);
});

describe("a sid the port cannot hold", () => {
	it.each(UNHOLDABLE_SIDS)(
		"is refused with a RangeError by a join and a close (%s)",
		async (_, sid) => {
			const h = harness();
			await expect(h.lifecycle.join(sid, { familyId: "f1" })).rejects.toThrow(RangeError);
			await expect(h.lifecycle.close(sid, "rp_logout")).rejects.toThrow(RangeError);
		},
	);
});

describe("resumePending", () => {
	it("finishes a close a failing item left closing", async () => {
		const h = harness();
		await h.establish();
		await joinAll(h);
		h.failing.set("delete_user_session", 1);
		expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("pending");
		expect(await h.lifecycle.resumePending()).toEqual({ done: 1, pending: 0, unavailable: 0 });
		expect((await h.read())?.value.state).toBe("closed");
		expect(await h.sessions.get(SID)).toBeNull();
	});

	it("counts a close still pending, and leaves it closing", async () => {
		const h = harness();
		await h.establish();
		await joinAll(h);
		h.failing.set("notify:a", Number.POSITIVE_INFINITY);
		await h.lifecycle.close(SID, "rp_logout");
		expect(await h.lifecycle.resumePending()).toEqual({ done: 0, pending: 1, unavailable: 0 });
		expect((await h.read())?.value.state).toBe("closing");
	});

	it("counts a closing record it cannot read as unavailable, and warns for it", async () => {
		let readDown = false;
		const h = harness({
			store: (inner) => ({
				...inner,
				read: async (sid) => {
					if (readDown) throw new Error("lifecycle store down");
					return inner.read(sid);
				},
			}),
		});
		await h.establish();
		await joinAll(h);
		h.failing.set("delete_user_session", 1);
		expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("pending");
		h.lines.warn.length = 0;
		readDown = true;
		expect(await h.lifecycle.resumePending()).toEqual({ done: 0, pending: 0, unavailable: 1 });
		expect(h.lines.warn).toEqual([
			[
				{ operation: "resume", sid: SID, err: expect.objectContaining({ name: "Error" }) },
				"session_lifecycle_unavailable",
			],
		]);
		readDown = false;
		expect((await h.read())?.value.state).toBe("closing");
	});

	it("pages the closing listing from the last sid it was answered, reaching every closing record", async () => {
		const afters: string[] = [];
		const h = harness({
			store: (inner) => ({
				...inner,
				listClosing: async (limit, after) => {
					afters.push(after ?? "");
					return inner.listClosing(limit, after);
				},
			}),
		});
		const sids = Array.from({ length: 250 }, (_, i) => `sid-${String(i).padStart(3, "0")}`);
		for (const sid of sids) {
			await h.establish(sid);
			await h.lifecycle.join(sid, { familyId: `f-${sid}` });
			h.failing.set(`revoke_family:f-${sid}`, 1);
			expect((await h.lifecycle.close(sid, "operator_reset")).outcome).toBe("pending");
		}
		expect(await h.lifecycle.resumePending()).toEqual({ done: 250, pending: 0, unavailable: 0 });
		expect(afters[0]).toBe("");
		expect(afters.length).toBeGreaterThan(1);
		for (const after of afters.slice(1)) expect(sids).toContain(after);
	});

	it("rejects when the closing listing cannot be read", async () => {
		const h = harness({
			store: (inner) => ({
				...inner,
				listClosing: async () => {
					throw new Error("lifecycle store down");
				},
			}),
		});
		await expect(h.lifecycle.resumePending()).rejects.toThrow("lifecycle store down");
	});
});
