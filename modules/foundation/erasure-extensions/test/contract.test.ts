import { expect, it } from "vitest";
import {
	type Elsewhere,
	type Erased,
	type Eraser,
	erasers,
	erasureMarks,
	type ForgottenReport,
	forgottenIn,
	type MigrationReport,
	type OwnerStopped,
	ownerStopped,
	type SpaceReport,
	type SubjectOf,
	type SubjectReading,
} from "../src/contract.ts";

it("keys erasers by their name, the one a space's erasedBy gives", () => {
	const eraser = { name: "users" } as Eraser;
	expect(erasers.rule).toMatchObject({ multiplicity: "keyed" });
	expect((erasers.rule as { keyOf: (e: Eraser) => string }).keyOf(eraser)).toBe("users");
});

it("names erasure's marks under its own name, frozen", () => {
	expect(erasureMarks).toEqual({
		enabled: "account-erasure.enabled",
		journal: "account-erasure.journal",
	});
	expect(Object.isFrozen(erasureMarks)).toBe(true);
});

it("takes no plain object for a report: one is made by records, behind a cast", () => {
	// @ts-expect-error A report's brand is records' to give.
	const forged: SpaceReport = { kind: "erased", space: "users-store.links", removed: 1 };
	expect(forged.kind).toBe("erased");
});

it("states whether an eraser can erase, and which erasers it follows", () => {
	const empty = { reports: [], logoutGaps: 0 };
	const eraser: Eraser = {
		name: "mfa-flows",
		erasable: false,
		after: ["mfa"],
		online: async () => empty,
		window: async () => empty,
		migrate: async () => [],
	};
	expect(eraser.erasable).toBe(false);
	// @ts-expect-error Whether it can erase is stated, never left out, in 0.20.
	const unstated: Eraser = { ...eraser, erasable: undefined };
	expect(unstated.after).toEqual(["mfa"]);
});

it("reads a record's subject three ways, an unreadable one with why", async () => {
	const reading: SubjectReading = async (key) =>
		key === "a" ? { kind: "subject", subject: "alice" } : { kind: "unreadable", reason: "sealed" };
	expect(await reading("a", {})).toEqual({ kind: "subject", subject: "alice" });
	// @ts-expect-error An unreadable record says why: it stops its space, proving nothing.
	const silent: SubjectOf = { kind: "unreadable" };
	expect(silent.kind).toBe("unreadable");
});

it("makes a pseudonymous space's report with no brand, beside the branded ones in an answer", () => {
	const forgotten: ForgottenReport = forgottenIn("rate-limit.lockouts", 2);
	expect(forgotten).toEqual({ kind: "forgotten", space: "rate-limit.lockouts", removed: 2 });
	const answer: Erased = { reports: [forgotten], logoutGaps: 0 };
	expect(answer.reports).toEqual([forgotten]);
	// @ts-expect-error The owner's claim is no tombstone: a brand-free object is never a SpaceReport.
	const stretched: SpaceReport = forgotten;
	expect(stretched.kind).toBe("forgotten");
});

it("takes an owner's step for an orphan: what a record holds, kept outside the space before it goes", async () => {
	const kept = new Map<string, unknown>();
	const elsewhere: Elsewhere = async (key, value) => {
		kept.set(key, value);
	};
	await elsewhere("k", { issuer: "https://idp.example" });
	await elsewhere("k", { issuer: "https://idp.example" });
	expect([...kept]).toEqual([["k", { issuer: "https://idp.example" }]]);
});

it("makes an owner's stop of a migration, which no cast makes a MigrationReport", async () => {
	const stopped: OwnerStopped = ownerStopped("federation-tokens-store.tokens", "no port");
	expect(stopped).toEqual({
		kind: "owner-stopped",
		space: "federation-tokens-store.tokens",
		reason: "no port",
	});
	const answer: Awaited<ReturnType<Eraser["migrate"]>> = [stopped];
	expect(answer).toEqual([stopped]);
	// @ts-expect-error The owner's stop states nothing written: a brand-free object is never a MigrationReport.
	const stretched: MigrationReport = stopped;
	expect(stretched.kind).toBe("owner-stopped");
});
