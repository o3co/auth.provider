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

import { describe, expect, it } from "vitest";
import {
	createInMemorySessionFamilyIndex,
	createInMemorySessionFederationIndex,
	createInMemorySessionLifecycleStore,
	createInMemorySessionRPRegistry,
	createInMemorySubjectSessionIndex,
	createInMemoryUserSessionStore,
	createSessionLifecycle,
	type FederationTokenStore,
	type RefreshTokenFamilyRevocation,
	type RegisteredRP,
	readVersionedSessionLifecycle,
	SESSION_CLOSE_CAUSES,
	type SessionCloseNotice,
	type SessionCloseNotifier,
	type SessionLifecycleStore,
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
	readonly subjectSessionIndex?: boolean;
	readonly store?: (inner: SessionLifecycleStore) => SessionLifecycleStore;
	/** A family index without the session-end capability: it keeps no end mark. */
	readonly familyIndexWithoutEnd?: boolean;
}

function harness(options: HarnessOptions = {}) {
	const calls: Calls = [];
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

	const inner = createInMemorySessionLifecycleStore();
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
		...(options.notifier === false ? {} : { notifier }),
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
		logger: { warn: () => undefined, error: () => undefined },
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

	it("answers unavailable when the lifecycle store cannot answer", async () => {
		const h = harness({
			store: (inner) => ({
				...inner,
				join: async () => {
					throw new Error("lifecycle store down");
				},
			}),
		});
		await h.establish();
		expect(await h.lifecycle.join(SID, { rp: relyingParty("a"), familyId: "f1" })).toEqual({
			outcome: "unavailable",
		});
	});

	it("refuses a request that joins nothing with a RangeError", async () => {
		const h = harness();
		await expect(h.lifecycle.join(SID, {})).rejects.toThrow(RangeError);
	});
});

describe("close", () => {
	it("runs every item, the user session's delete last, and answers done with the relying parties and federations", async () => {
		const h = harness();
		await h.establish();
		await joinAll(h);
		h.calls.length = 0;
		expect(await h.lifecycle.close(SID, "rp_logout")).toEqual({
			outcome: "done",
			rps: ["a"],
			federations: ["google"],
		});
		expect(h.calls).toEqual([
			"revoke_family:f1",
			"remove_federation_tokens:sid-1",
			"remove_subject_session:sid-1",
			"notify:a",
			"delete_user_session",
		]);
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
			expect.arrayContaining(["family:f1", "delete_user_session"]),
		);
		expect(record?.value.close?.pending).not.toContain("rp:a");
		expect(await h.sessions.get(SID)).not.toBeNull();
		expect(h.calls).not.toContain("delete_user_session");
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
			"rp:a",
		]);
	});

	it("answers unavailable when the closing commit cannot land, having run nothing", async () => {
		const h = harness({
			store: (inner) => ({
				...inner,
				beginClose: async () => {
					throw new Error("lifecycle store down");
				},
			}),
		});
		await h.establish();
		await joinAll(h);
		h.calls.length = 0;
		expect(await h.lifecycle.close(SID, "rp_logout")).toEqual({ outcome: "unavailable" });
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
						if (failNextCompletion) {
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
			expect((await h.lifecycle.close(SID, "rp_logout")).outcome).toBe("done");
			expect(h.calls.filter((call) => call === "revoke_family:f1")).toHaveLength(2);
			expect(h.revoked.has("f1")).toBe(true);
			expect((await h.read())?.value.state).toBe("closed");
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

	it("is unavailable when the lifecycle store cannot answer", async () => {
		const h = harness({
			store: (inner) => ({
				...inner,
				read: async () => {
					throw new Error("lifecycle store down");
				},
			}),
		});
		await h.establish();
		expect(await h.lifecycle.liveness(SID)).toEqual({ outcome: "unavailable" });
	});
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
