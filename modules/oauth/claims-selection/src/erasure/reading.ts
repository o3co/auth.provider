import type { SubjectOf, SubjectReading } from "@mod/erasure-extensions";
import type { FamilySubjects } from "../contract.ts";
import type { StoredSelection } from "../store.ts";
import { kindOf, read } from "../stored.ts";

/**
 * Frozen from v0.19.1: a 0.19 instance's longest record without its subject is a token's target,
 * kept the longest access-token lifetime (`modules/oauth/tokens/src/contract.ts`, 86,400 s) and its
 * allowance (`modules/oauth/claims-selection/src/selections.ts`, 120 s); a code's and a pin's end
 * sooner. One bound for every kind: the walk stops at the first such record, whichever it meets.
 */
const legacyBoundSeconds = 86_400 + 120;

const kindNamed = { code: "a code's selection", pin: "a pin", token: "a token's target" } as const;

const unreadable = (reason: string): SubjectOf => ({ kind: "unreadable", reason });

/** Each kind's read: a family's target is read as a token's. */
const readOf = { code: read.code, pin: read.pin, family: read.target, token: read.target };

/** A record 0.19 kept without its subject: unreadable until every one has ended. */
const legacy = (kind: keyof typeof kindNamed) =>
	unreadable(
		`${kindNamed[kind]} a 0.19 instance kept without its subject; run again ${legacyBoundSeconds.toLocaleString("en")} s after the last 0.19 instance stopped, and if it persists past that, a 0.19 instance is still writing`,
	);

/** A family's subject, as the module keeping families answers it: ended is an orphan; a failure proves nothing. */
const familyOf = async (families: FamilySubjects, familyId: string): Promise<SubjectOf> => {
	try {
		const whose = await families.subjectOf(familyId);
		return whose.kind === "subject" ? whose : { kind: "orphan" };
	} catch {
		return unreadable("a family's target whose family could not be read");
	}
};

/**
 * Whose a record is, as the migration reads it: format 2's own subject; one 0.19 kept without it,
 * a family's target by its family (`familySubjects`), every other kind unreadable for a bound;
 * a record of another name or shape unreadable, never an orphan.
 */
export const selectionSubjectOf =
	(families: FamilySubjects | undefined): SubjectReading =>
	async (key, value) => {
		const named = kindOf(key);
		if (named === undefined) return unreadable("a record of no kind claims-selection names");
		let subject: string | undefined;
		try {
			subject = readOf[named.kind](value as StoredSelection).subject;
		} catch {
			return unreadable("a record of another shape");
		}
		if (subject !== undefined) return { kind: "subject", subject };
		if (named.kind !== "family") return legacy(named.kind);
		if (!families) {
			return unreadable("a family's target with no reading of whose a family is composed");
		}
		return familyOf(families, named.of);
	};
