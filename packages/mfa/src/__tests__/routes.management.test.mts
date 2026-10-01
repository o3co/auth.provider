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
 * The account page's management of a subject's second factors under
 * `/session/mfa/factors`: the list, admitted as
 * `mfa.view`, each record with its state and never its data; a rename and a
 * removal, admitted as `mfa.manage`. A removal under `required` keeps a
 * record of an installed counting kind (`409 mfa_last_factor`), and one that
 * leaves no record that may count clears the enrollment witness after it.
 */

import {
	type AppConfig,
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	type MfaFactorRecord,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { createRecordingMailSender } from "@o3co/auth-provider-core/testing";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mfaEmailFactorConfigForTests } from "#/testing/index.mjs";
import {
	ALICE,
	BOB,
	boot,
	configFor,
	directoryEntries,
	disposeAll,
	events,
	spyLogger,
	WitnessingUserRepository,
} from "./moduleHarness.mjs";
import {
	beginLogin,
	freezeClock,
	mfaPost,
	newFactorId,
	recordingAuditSink,
	recoverySet,
	STEP_UP_REQUIRED,
	seedFactor,
	seedTotp,
	signInWithTotp,
	suiteSealing,
	T0,
	thawClock,
	verify,
} from "./routesHarness.mjs";

beforeEach(() => freezeClock());
afterEach(async () => {
	await disposeAll();
	thawClock();
});

const UNKNOWN_FACTOR = { error: "invalid_request", error_description: "Unknown second factor" };
const INVALID_LABEL = { error: "invalid_request", error_description: "Invalid label" };
const UNAVAILABLE = {
	error: "temporarily_unavailable",
	error_description: "MFA temporarily unavailable",
};
const LAST_FACTOR = {
	error: "mfa_last_factor",
	error_description: "The last second factor that counts cannot be removed",
};
const FACTOR_CONFLICT = {
	error: "mfa_factor_conflict",
	error_description: "The factor changed while it was renamed: try again",
};

/**
 * Boots `mode` with the email factor on, a recording sender, an audit sink and
 * alice's directory entry — saying she enrolled, or holding no address, when
 * `alice` asks it.
 */
async function composed(
	mode: "optional" | "required" = "optional",
	options: {
		readonly alice?: { readonly enrolled?: boolean; readonly noAddress?: boolean };
		readonly requireEmailProof?: "when-mail" | "always" | "never";
	} = {},
) {
	const factorStore = createMemoryMfaFactorStore();
	const audit = recordingAuditSink();
	const entries = directoryEntries();
	const entry = entries.get(ALICE.username);
	if (entry !== undefined && options.alice?.enrolled === true) entry.mfaEnrolled = true;
	if (entry !== undefined && options.alice?.noAddress === true) delete entry.email;
	const users = new WitnessingUserRepository(entries);
	const logger = spyLogger();
	const booted = await boot({
		config: {
			...configFor(
				mode,
				options.requireEmailProof === undefined
					? {}
					: { enrollment: { requireEmailProof: options.requireEmailProof } },
			),
			...mfaEmailFactorConfigForTests({ enabled: true }),
		} as AppConfig,
		factorStore,
		transactionStore: createMemoryMfaTransactionStore(),
		auditSink: audit,
		userRepository: users,
		mailSender: createRecordingMailSender(),
		logger,
	});
	return {
		...booted,
		factorStore,
		userSessionStore: booted.userSessionStore as UserSessionStore,
		audit,
		users,
		logger,
	};
}

/** Alice signed in with a TOTP factor seeded for her, and that factor. */
async function signedIn(built: Awaited<ReturnType<typeof composed>>) {
	const totp = await seedTotp(built.factorStore);
	const { agent } = await signInWithTotp(built.app, built.userSessionStore, totp);
	return { agent, totp };
}

const list = (agent: ReturnType<typeof request.agent>) => agent.get("/session/mfa/factors");
const rename = (agent: ReturnType<typeof request.agent>, body: Record<string, unknown>) =>
	mfaPost(agent, "/factors/rename", body);
const remove = (agent: ReturnType<typeof request.agent>, factorId: unknown) =>
	mfaPost(agent, "/factors/remove", { factor_id: factorId });

const ids = (records: readonly Pick<MfaFactorRecord, "id">[]) => records.map(({ id }) => id).sort();

describe("GET /session/mfa/factors", () => {
	it("lists every record of the session's subject, oldest first, with its state and what a page may show — never its data", async () => {
		const built = await composed();
		const { agent, totp } = await signedIn(built);
		const left = await seedFactor(built.factorStore, "recovery_code", recoverySet(2).data);
		const exhausted = await seedFactor(built.factorStore, "recovery_code", recoverySet(0).data);
		const retired = await seedFactor(built.factorStore, "retired", { anything: true });
		const copied = await seedTotp(built.factorStore, ALICE.id, { sealedFor: BOB.id });
		const older: MfaFactorRecord = {
			id: newFactorId(),
			subject: ALICE.id,
			kind: "retired",
			label: "Old key",
			binding: "password",
			createdAt: new Date(T0 - 2 * 86_400_000),
			lastUsedAt: undefined,
			version: 0,
			data: "opaque",
		};
		await built.factorStore.create(older);
		await seedTotp(built.factorStore, BOB.id);

		const res = await list(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.headers["cache-control"]).toBe("no-store");
		const day = new Date(T0 - 86_400_000).toISOString();
		const byId = (a: { id: string }, b: { id: string }) => (a.id < b.id ? -1 : 1);
		expect(res.body).toEqual({
			factors: [
				{
					id: older.id,
					kind: "retired",
					label: "Old key",
					created_at: new Date(T0 - 2 * 86_400_000).toISOString(),
					binding: "password",
					state: "not_installed",
				},
				...[
					{
						id: totp.record.id,
						kind: "totp",
						created_at: day,
						last_used_at: new Date(T0).toISOString(),
						binding: "password",
						state: "usable",
					},
					{
						id: left.id,
						kind: "recovery_code",
						created_at: day,
						binding: "password",
						state: "usable",
						recovery_codes_remaining: 2,
					},
					{
						id: exhausted.id,
						kind: "recovery_code",
						created_at: day,
						binding: "password",
						state: "exhausted",
						recovery_codes_remaining: 0,
					},
					{
						id: retired.id,
						kind: "retired",
						created_at: day,
						binding: "password",
						state: "not_installed",
					},
					{
						id: copied.record.id,
						kind: "totp",
						created_at: day,
						binding: "password",
						state: "unreadable",
					},
				].sort(byId),
			],
		});
		for (const record of [totp.record, left, exhausted, retired, copied.record]) {
			expect(JSON.stringify(res.body)).not.toContain(record.data);
		}
	});

	it("says address_changed for an email factor whose recorded address is not the session's login address, and usable for one that is", async () => {
		const built = await composed();
		const { agent } = await signedIn(built);
		const digest = (address: string) => suiteSealing().digestsFor("email").digest([address]);
		const current = await seedFactor(built.factorStore, "email", {
			addressDigest: digest(ALICE.email),
		});
		const stale = await seedFactor(built.factorStore, "email", {
			addressDigest: digest("old@example.com"),
		});

		const res = await list(agent);

		const stateOf = (id: string) =>
			(res.body.factors as { id: string; state: string }[]).find((factor) => factor.id === id)
				?.state;
		expect(stateOf(current.id)).toBe("usable");
		expect(stateOf(stale.id)).toBe("address_changed");
	});

	it("lists as unreadable an email factor whose record holds no readable digest, and one beside a session whose User has no address", async () => {
		const digest = suiteSealing().digestsFor("email").digest([ALICE.email]);
		for (const [what, setup, data] of [
			["no readable digest", {}, { addressDigest: "not a digest" }],
			["no address", { noAddress: true }, { addressDigest: digest }],
		] as const) {
			const built = await composed("optional", { alice: setup });
			const { agent } = await signedIn(built);
			const email = await seedFactor(built.factorStore, "email", data);

			const res = await list(agent);

			const listed = (res.body.factors as { id: string; state: string }[]).find(
				(factor) => factor.id === email.id,
			);
			expect(listed?.state, what).toBe("unreadable");
			await disposeAll();
		}
	});

	it("lists as unreadable, logging the key to put back, a recovery set and an email factor whose digests name a key the ring no longer holds", async () => {
		const built = await composed();
		const { agent } = await signedIn(built);
		const gone = (value: { keyId: string; digest: string }) => ({ ...value, keyId: "k-gone" });
		const set = recoverySet(2).data as { codes: { keyId: string; digest: string }[] };
		const codes = await seedFactor(built.factorStore, "recovery_code", {
			codes: set.codes.map(gone),
		});
		const email = await seedFactor(built.factorStore, "email", {
			addressDigest: gone(suiteSealing().digestsFor("email").digest([ALICE.email])),
		});

		const res = await list(agent);

		const stateOf = (id: string) =>
			(res.body.factors as { id: string; state: string; recovery_codes_remaining?: number }[]).find(
				(factor) => factor.id === id,
			);
		expect(stateOf(codes.id)).toEqual(expect.objectContaining({ state: "unreadable" }));
		expect(stateOf(codes.id)?.recovery_codes_remaining).toBeUndefined();
		expect(stateOf(email.id)?.state).toBe("unreadable");
		for (const record of [codes, email]) {
			expect(built.logger.error).toHaveBeenCalledWith(
				{
					route: "factors",
					kind: record.kind,
					factorId: record.id,
					state: "key_unavailable",
					keyId: "k-gone",
				},
				"mfa_factor_unreadable",
			);
		}
	});

	it("leaves out a date a record holds that is not a valid date, and answers 503 for one that is no date at all", async () => {
		const built = await composed();
		const { agent } = await signedIn(built);
		await seedFactor(built.factorStore, "recovery_code", recoverySet(2).data);
		const read = built.factorStore.list.bind(built.factorStore);
		const listing = vi.spyOn(built.factorStore, "list");

		listing.mockImplementation(async (subject) =>
			(await read(subject)).map((record) => ({
				...record,
				createdAt: new Date(Number.NaN),
				lastUsedAt: new Date(Number.NaN),
			})),
		);
		const invalid = await list(agent);
		expect(invalid.status, JSON.stringify(invalid.body)).toBe(200);
		expect(invalid.body.factors).toHaveLength(2);
		for (const factor of invalid.body.factors as Record<string, unknown>[]) {
			expect(factor).not.toHaveProperty("created_at");
			expect(factor).not.toHaveProperty("last_used_at");
		}

		listing.mockImplementation(async (subject) =>
			(await read(subject)).map((record) => ({
				...record,
				createdAt: "yesterday" as unknown as Date,
			})),
		);
		const notADate = await list(agent);
		expect(notADate.status).toBe(503);
		expect(notADate.body).toEqual(UNAVAILABLE);
	});

	it("is admitted as mfa.view: a session past mfa.manage.maxAgeSeconds is listed, while a rename from it steps up", async () => {
		const built = await composed();
		const { agent, totp } = await signedIn(built);
		freezeClock(T0 + 301_000);

		expect((await list(agent)).status).toBe(200);
		const renamed = await rename(agent, { factor_id: totp.record.id, label: "Phone" });
		expect(renamed.status, JSON.stringify(renamed.body)).toBe(403);
		expect(renamed.body).toMatchObject(STEP_UP_REQUIRED);
	});

	it("answers 401 login_required without a signed-in session", async () => {
		const built = await composed();
		const res = await request.agent(built.app).get("/session/mfa/factors");
		expect(res.status).toBe(401);
		expect(res.body).toMatchObject({ error: "login_required" });
	});

	it("answers 503 when the factor store cannot list, logged once", async () => {
		const built = await composed();
		const { agent } = await signedIn(built);
		vi.spyOn(built.factorStore, "list").mockRejectedValue(new Error("down"));

		const res = await list(agent);

		expect(res.status).toBe(503);
		expect(res.body).toEqual(UNAVAILABLE);
		expect(built.logger.error).toHaveBeenCalledWith(
			expect.objectContaining({ route: "factors", store: "mfa_factor", step: "list" }),
			"mfa_store_unavailable",
		);
	});
});

describe("POST /session/mfa/factors/rename", () => {
	it("writes the label by compare-and-set at the version read, keeping the data and the last use, and answers the factor", async () => {
		const built = await composed();
		const { agent, totp } = await signedIn(built);
		const [before] = await built.factorStore.list(ALICE.id);

		const res = await rename(agent, { factor_id: totp.record.id, label: "Work phone" });

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.body).toEqual({ factor: { id: totp.record.id, kind: "totp", label: "Work phone" } });
		const [after] = await built.factorStore.list(ALICE.id);
		expect(after).toEqual({ ...before, label: "Work phone", version: (before?.version ?? 0) + 1 });
	});

	it("answers 409 mfa_factor_conflict when the factor moved since it was read, writing nothing more", async () => {
		const built = await composed();
		const { agent, totp } = await signedIn(built);
		const write = built.factorStore.update.bind(built.factorStore);
		// Another write lands between the rename's read and its compare-and-set.
		vi.spyOn(built.factorStore, "update").mockImplementationOnce(
			async (subject, id, expectedVersion, next) => {
				await write(subject, id, expectedVersion, { ...next, label: "Moved" });
				return write(subject, id, expectedVersion, next);
			},
		);

		const res = await rename(agent, { factor_id: totp.record.id, label: "Work phone" });

		expect(res.status, JSON.stringify(res.body)).toBe(409);
		expect(res.body).toEqual(FACTOR_CONFLICT);
		expect((await built.factorStore.list(ALICE.id))[0]?.label).toBe("Moved");
	});

	it("answers 400 for a label a page cannot show as it is, and for a factor that is not the subject's", async () => {
		const built = await composed();
		const { agent, totp } = await signedIn(built);
		const bobs = await seedTotp(built.factorStore, BOB.id);

		for (const label of ["", "x".repeat(65), "line\nbreak", 42, undefined]) {
			const res = await rename(agent, { factor_id: totp.record.id, label });
			expect(res.status, JSON.stringify(label)).toBe(400);
			expect(res.body, JSON.stringify(label)).toEqual(INVALID_LABEL);
		}
		for (const factorId of [bobs.record.id, "not-an-id", undefined]) {
			const res = await rename(agent, { factor_id: factorId, label: "Phone" });
			expect(res.status, String(factorId)).toBe(400);
			expect(res.body, String(factorId)).toEqual(UNKNOWN_FACTOR);
		}
		expect((await built.factorStore.list(ALICE.id))[0]?.label).toBeUndefined();
		expect((await built.factorStore.list(BOB.id))[0]?.label).toBeUndefined();
	});

	it("refuses a POST without the CSRF token, reading nothing", async () => {
		const built = await composed();
		const { agent, totp } = await signedIn(built);
		const listed = vi.spyOn(built.factorStore, "list");

		for (const path of ["/factors/rename", "/factors/remove"]) {
			const res = await agent
				.post(`/session/mfa${path}`)
				.send({ factor_id: totp.record.id, label: "Phone" });
			expect(res.status, path).toBe(403);
		}
		expect(listed).not.toHaveBeenCalled();
	});
});

describe("POST /session/mfa/factors/remove", () => {
	it("removes the named factor, audits mfa.factor.removed with its kind, binding and by: user, and writes no witness while a counting factor stands", async () => {
		const built = await composed();
		const { agent, totp } = await signedIn(built);
		const other = await seedTotp(built.factorStore);
		const marks = built.users.marks.length;

		const res = await remove(agent, other.record.id);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.body).toEqual({});
		expect(ids(await built.factorStore.list(ALICE.id))).toEqual([totp.record.id]);
		expect(built.audit.of("mfa.factor.removed")).toEqual([
			expect.objectContaining({
				subject: ALICE.id,
				details: { kind: "totp", factorId: other.record.id, binding: "password", by: "user" },
			}),
		]);
		expect(built.users.marks.slice(marks)).toEqual([]);
	});

	it("clears the witness once no record that may count remains, after the removal", async () => {
		const built = await composed();
		const { agent, totp } = await signedIn(built);
		const set = await seedFactor(built.factorStore, "recovery_code", recoverySet(2).data);
		const removed = vi.spyOn(built.factorStore, "remove");
		const marked = vi.spyOn(built.users, "markMfaEnrolled");

		const res = await remove(agent, totp.record.id);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(ids(await built.factorStore.list(ALICE.id))).toEqual([set.id]);
		expect(marked.mock.calls).toEqual([[ALICE.id, false]]);
		expect(removed.mock.invocationCallOrder[0]).toBeLessThan(
			marked.mock.invocationCallOrder[0] as number,
		);
	});

	it("leaves the witness while a record that may count stands — a kind no longer installed", async () => {
		const built = await composed();
		const { agent, totp } = await signedIn(built);
		await seedFactor(built.factorStore, "retired", {});
		const marked = vi.spyOn(built.users, "markMfaEnrolled");

		const res = await remove(agent, totp.record.id);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(marked).not.toHaveBeenCalled();
	});

	it("keeps the removal when the witness cannot be cleared: 200, said once at warn", async () => {
		const built = await composed();
		const { agent, totp } = await signedIn(built);
		built.users.failWith(new Error("directory down"));

		const res = await remove(agent, totp.record.id);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(await built.factorStore.list(ALICE.id)).toEqual([]);
		expect(
			events(built.logger, "warn").filter((event) => event === "mfa_enrollment_witness_uncleared"),
		).toHaveLength(1);
	});

	it("under required, answers 409 mfa_last_factor for the last record of an installed counting kind, removing nothing — a kind no longer installed does not stand in", async () => {
		const built = await composed("required");
		const { agent, totp } = await signedIn(built);
		await seedFactor(built.factorStore, "retired", {});
		const before = ids(await built.factorStore.list(ALICE.id));

		const res = await remove(agent, totp.record.id);

		expect(res.status, JSON.stringify(res.body)).toBe(409);
		expect(res.body).toEqual(LAST_FACTOR);
		expect(ids(await built.factorStore.list(ALICE.id))).toEqual(before);
		expect(built.audit.of("mfa.factor.removed")).toEqual([]);
	});

	it("under required, answers 409 mfa_last_factor when the other counting records are not usable — a TOTP whose data does not open, an email factor whose address changed", async () => {
		for (const other of ["unreadable totp", "address_changed email"] as const) {
			const built = await composed("required");
			const { agent, totp } = await signedIn(built);
			if (other === "unreadable totp") {
				await seedTotp(built.factorStore, ALICE.id, { sealedFor: BOB.id });
			} else {
				await seedFactor(built.factorStore, "email", {
					addressDigest: suiteSealing().digestsFor("email").digest(["old@example.com"]),
				});
			}

			const res = await remove(agent, totp.record.id);

			expect(res.status, other).toBe(409);
			expect(res.body, other).toEqual(LAST_FACTOR);
			expect(await built.factorStore.list(ALICE.id), other).toHaveLength(2);
			await disposeAll();
		}
	});

	it("under required, removes a recovery set, a kind no longer installed, and a counting factor beside another of its kind", async () => {
		const built = await composed("required");
		const { agent, totp } = await signedIn(built);
		const set = await seedFactor(built.factorStore, "recovery_code", recoverySet(2).data);
		const retired = await seedFactor(built.factorStore, "retired", {});
		const other = await seedTotp(built.factorStore);

		for (const id of [set.id, retired.id, other.record.id]) {
			const res = await remove(agent, id);
			expect(res.status, JSON.stringify(res.body)).toBe(200);
		}
		expect(ids(await built.factorStore.list(ALICE.id))).toEqual([totp.record.id]);
	});

	it("answers 400 Unknown second factor for a factor that is not the subject's, removing nothing", async () => {
		const built = await composed();
		const { agent } = await signedIn(built);
		const bobs = await seedTotp(built.factorStore, BOB.id);

		for (const factorId of [bobs.record.id, "not-an-id", undefined]) {
			const res = await remove(agent, factorId);
			expect(res.status, String(factorId)).toBe(400);
			expect(res.body, String(factorId)).toEqual(UNKNOWN_FACTOR);
		}
		expect(await built.factorStore.list(BOB.id)).toHaveLength(1);
	});

	it("is admitted as mfa.manage: a session past mfa.manage.maxAgeSeconds steps up, removing nothing", async () => {
		const built = await composed();
		const { agent, totp } = await signedIn(built);
		freezeClock(T0 + 301_000);

		const res = await remove(agent, totp.record.id);

		expect(res.status, JSON.stringify(res.body)).toBe(403);
		expect(res.body).toMatchObject(STEP_UP_REQUIRED);
		expect(await built.factorStore.list(ALICE.id)).toHaveLength(1);
	});

	it("carries on as removed when the store removed the record and then failed: 200, audited, the witness cleared", async () => {
		const built = await composed();
		const { agent, totp } = await signedIn(built);
		const removeFor = built.factorStore.remove.bind(built.factorStore);
		vi.spyOn(built.factorStore, "remove").mockImplementationOnce(async (subject, id) => {
			await removeFor(subject, id);
			throw new Error("timed out after the write");
		});
		const marked = vi.spyOn(built.users, "markMfaEnrolled");

		const res = await remove(agent, totp.record.id);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(built.audit.of("mfa.factor.removed")).toHaveLength(1);
		expect(marked.mock.calls).toEqual([[ALICE.id, false]]);
	});

	it("decides the witness from the records read before, less the one removed, when they cannot be read again, said once at warn", async () => {
		const built = await composed();
		const { agent, totp } = await signedIn(built);
		await seedFactor(built.factorStore, "recovery_code", recoverySet(2).data);
		const read = built.factorStore.list.bind(built.factorStore);
		const removed = vi.spyOn(built.factorStore, "remove");
		vi.spyOn(built.factorStore, "list").mockImplementation(async (subject) => {
			if (removed.mock.calls.length > 0) throw new Error("factor store unreachable");
			return read(subject);
		});
		const marked = vi.spyOn(built.users, "markMfaEnrolled");

		const res = await remove(agent, totp.record.id);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(marked.mock.calls).toEqual([[ALICE.id, false]]);
		expect(
			events(built.logger, "warn").filter((event) => event === "mfa_factor_removal_unread"),
		).toHaveLength(1);
	});

	it("leaves the witness cleared when a login's mark lands after a removal cleared it", async () => {
		const built = await composed();
		const totp = await seedTotp(built.factorStore);
		const mark = built.users.markMfaEnrolled.bind(built.users);
		vi.spyOn(built.users, "markMfaEnrolled").mockImplementationOnce(async (subject, enrolled) => {
			// The subject's last factor is removed, and the witness cleared, just before this mark.
			await built.factorStore.removeAllForSubject(subject);
			await mark(subject, false);
			await mark(subject, enrolled);
		});

		await signInWithTotp(built.app, built.userSessionStore, totp);

		expect(built.users.marks.at(-1)).toEqual({ subject: ALICE.id, enrolled: false });
	});

	it("sends the session that removed the last counting factor to log in again for every further change, recording nothing, and the next sign-in may change them", async () => {
		const built = await composed("optional", {
			alice: { enrolled: true },
			requireEmailProof: "never",
		});
		const { agent, totp } = await signedIn(built);
		const codes = recoverySet(2);
		const set = await seedFactor(built.factorStore, "recovery_code", codes.data);
		expect((await remove(agent, totp.record.id)).status).toBe(200);

		const answers = [
			await mfaPost(agent, "/enrollment", { kind: "totp" }),
			await rename(agent, { factor_id: set.id, label: "Paper" }),
			await remove(agent, set.id),
		];
		for (const res of answers) {
			expect(res.status, JSON.stringify(res.body)).toBe(401);
			expect(res.body).toMatchObject({ error: "login_required" });
		}
		expect(built.audit.of("mfa.enrollment_state_inconsistent")).toEqual([]);

		const again = await beginLogin(built.app);
		const verified = await verify(again.agent, again.transaction, set.id, codes.codes[0]);
		expect(verified.status, JSON.stringify(verified.body)).toBe(200);
		const renamed = await rename(again.agent, { factor_id: set.id, label: "Paper" });
		expect(renamed.status, JSON.stringify(renamed.body)).toBe(200);
	});

	it("answers 503 when the factor store cannot remove, logged once, writing no witness", async () => {
		const built = await composed();
		const { agent, totp } = await signedIn(built);
		vi.spyOn(built.factorStore, "remove").mockRejectedValue(new Error("down"));
		const marked = vi.spyOn(built.users, "markMfaEnrolled");

		const res = await remove(agent, totp.record.id);

		expect(res.status).toBe(503);
		expect(res.body).toEqual(UNAVAILABLE);
		expect(built.logger.error).toHaveBeenCalledWith(
			expect.objectContaining({ route: "factors", store: "mfa_factor", step: "remove" }),
			"mfa_store_unavailable",
		);
		expect(marked).not.toHaveBeenCalled();
	});
});
