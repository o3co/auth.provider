import type { MigrationReport, SpaceReport, SubjectReading, Walk } from "@mod/erasure-extensions";
import { Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { credentialKey, subjectKey } from "../../records/records.ts";
import type {
	PasskeyRecords,
	PasskeyStore,
	RegistrationChallengeStore,
	StoredPasskey,
} from "../../store.ts";
import { credentialSubjectOf, holderSubjectOf, passkeysEraser } from "../eraser.ts";

const signal = new AbortController().signal;
const walk: Walk = { sweep: async () => ({ keys: [], server: "one" }) };
const passkey = (subject: string) => ({
	v: 1,
	subject,
	publicKey: "pQ",
	signCount: 0,
	backupEligible: false,
	backedUp: false,
});
const pending = (subject: string) => ({ ...passkey(subject), v: 2, pending: true, token: "t" });
const removal = (subject: string) => ({ v: 1, subject, removed: true });
const holder = (credentials: string[], subject?: string) => ({
	v: 1,
	handle: "aGFuZGxl",
	credentials,
	fence: 0,
	...(subject === undefined ? {} : { subject }),
});
/** Credentials read from `held` by id: an Error thrown, none where absent. */
const credentialsOf = (held: Record<string, object | Error>) => ({
	credentials: {
		read: async (key: string) => {
			const found = Object.entries(held).find(([id]) => credentialKey(id) === key)?.[1];
			if (found instanceof Error) throw found;
			return found as StoredPasskey | undefined;
		},
	} as PasskeyRecords,
});

describe("passkeys' eraser", () => {
	it("reads a credential's subject from its value alone: a passkey, a pending one or a removal mark; another shape unreadable", async () => {
		for (const value of [passkey("ann"), pending("ann"), removal("ann")]) {
			expect(await credentialSubjectOf(credentialKey("c1"), value)).toEqual({
				kind: "subject",
				subject: "ann",
			});
		}
		for (const value of [{ ...passkey("ann"), v: 3 }, { subject: "ann" }, null]) {
			expect((await credentialSubjectOf(credentialKey("c1"), value)).kind).toBe("unreadable");
		}
	});

	it("reads a holder by the subject it holds where its key is that subject's; another subject, or another shape, unreadable", async () => {
		const read = holderSubjectOf(credentialsOf({}));
		expect(await read(subjectKey("ann"), holder(["c1"], "ann"))).toEqual({
			kind: "subject",
			subject: "ann",
		});
		expect(await read(subjectKey("bob"), holder(["c1"], "ann"))).toMatchObject({
			kind: "unreadable",
			reason: expect.stringMatching(/not its key's/),
		});
		for (const value of [{ ...holder([], "ann"), v: 2 }, { v: 1, credentials: "c1" }, null]) {
			expect((await read(subjectKey("ann"), value)).kind).toBe("unreadable");
		}
	});

	it("reads a holder holding no subject by its credentials: one of its key's subject's, a confirmed absent one passed over", async () => {
		const read = holderSubjectOf(credentialsOf({ c2: passkey("bob"), c3: removal("ann") }));
		expect(await read(subjectKey("ann"), holder(["c1", "c2", "c3"]))).toEqual({
			kind: "subject",
			subject: "ann",
		});
	});

	it("reads a holder holding no subject as empty where none of its credentials is its key's subject's, and an empty holder as an orphan", async () => {
		const read = holderSubjectOf(credentialsOf({ c2: passkey("bob") }));
		expect(await read(subjectKey("ann"), holder(["c1", "c2"]))).toEqual({ kind: "orphan" });
		expect(await read(subjectKey("ann"), holder([]))).toEqual({ kind: "orphan" });
	});

	it("reads a holder holding no subject as unreadable where a credential it lists fails to read or has another shape, never as empty", async () => {
		const failing = holderSubjectOf(credentialsOf({ c1: new Unavailable("store") }));
		expect(await failing(subjectKey("ann"), holder(["c1"]))).toMatchObject({
			kind: "unreadable",
			reason: expect.stringMatching(/could not be read \(Unavailable\)/),
		});
		const other = holderSubjectOf(credentialsOf({ c1: { v: 9 }, c2: passkey("ann") }));
		expect((await other(subjectKey("ann"), holder(["c1", "c2"]))).kind).toBe("unreadable");
	});

	it("erases both spaces and fences registration challenges through the stores' ports, each subject in a window, and migrates the credentials first", async () => {
		const asked: string[] = [];
		const report = (space: string) => ({ kind: "erased", space, removed: 1 }) as SpaceReport;
		const migrated = (space: string) =>
			({ kind: "migrated", space, indexed: 0, removed: 0 }) as MigrationReport;
		const ports = (space: string) => ({
			erase: async (subject: string) => {
				asked.push(`erase ${space} ${subject}`);
				return report(space);
			},
			migrate: async (_walk: Walk, reading: SubjectReading) => {
				asked.push(`migrate ${space}`);
				if (space === "registrations") {
					expect((await reading("k", {})).kind).toBe("unreadable");
				}
				return migrated(space);
			},
		});
		const store = {
			credentials: ports("credentials"),
			subjects: ports("subjects"),
		} as unknown as PasskeyStore;
		const registrations = ports("registrations") as unknown as RegistrationChallengeStore;
		const eraser = passkeysEraser(store, registrations);
		expect([eraser.name, eraser.erasable, eraser.after]).toEqual(["passkeys", true, undefined]);
		expect((await eraser.online("ann", signal)).reports.map((r) => r.space)).toEqual([
			"credentials",
			"subjects",
			"registrations",
		]);
		expect((await eraser.window(["ann", "bob"], walk, signal)).reports).toHaveLength(6);
		asked.length = 0;
		await eraser.migrate(walk, signal);
		expect(asked).toEqual(["migrate credentials", "migrate subjects", "migrate registrations"]);
	});

	it("states that it cannot erase, with empty reports, where a port is missing or no registration challenge store is composed", async () => {
		const erasing = {
			erase: async () => ({}) as SpaceReport,
			migrate: async () => ({}) as MigrationReport,
		};
		const store = { credentials: erasing, subjects: erasing } as unknown as PasskeyStore;
		const registrations = erasing as unknown as RegistrationChallengeStore;
		for (const eraser of [
			passkeysEraser(store, undefined),
			passkeysEraser(store, { ...registrations, migrate: undefined } as never),
			passkeysEraser({ ...store, subjects: {} } as never, registrations),
		]) {
			expect(eraser.erasable).toBe(false);
			expect(await eraser.online("ann", signal)).toEqual({ reports: [], logoutGaps: 0 });
			expect(await eraser.migrate(walk, signal)).toEqual([]);
		}
	});
});
