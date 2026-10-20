import { createHash } from "node:crypto";
import type { LoginFrom } from "@mod/login-gates";
import type { LoginFacts } from "@mod/session";
import type { StoredTransaction } from "../store.ts";

export interface Challenge {
	readonly factor: string;
	readonly sealed: string;
}

/** A login's facts as held: one held before the authentication time was reported has none. */
export type HeldFacts = Omit<LoginFacts, "authenticatedAt"> &
	Partial<Pick<LoginFacts, "authenticatedAt">>;

/** What a transaction holds by its purpose. */
export type ByPurpose =
	| {
			readonly purpose: "login" | "enroll-login";
			/** What the first factor proved, given back to the gates. */
			readonly facts?: HeldFacts;
			/** What the login answers once it opens, kept unread. */
			readonly done?: unknown;
			/** Whom `login-gates` tells once the login opens, kept unread with `done`. */
			readonly from?: LoginFrom;
	  }
	/** The session it raises, or binds a factor from, and no other. */
	| { readonly purpose: "step-up" | "enroll"; readonly handle: string };

export interface TransactionBase {
	readonly subject: string;
	/** The hash of the browser's mfa cookie: the transaction is no bearer. */
	readonly browser: string;
	/** Kernel-clock epoch ms; past `deadline`, the transaction is gone whatever the store keeps. */
	readonly startedAt: number;
	readonly deadline: number;
	readonly attemptsLeft: number;
	/** The challenge last sent for a factor, sealed by mfa; the next proof takes it. */
	readonly challenge?: Challenge;
	/** What the work a transaction is for keeps in it, as JSON; never read here. */
	readonly held?: unknown;
	/** The record's format: 2; a record without one is format 1. */
	readonly format?: 2;
	/** Taken once: kept to its lifetime so it stays taken, and read as gone. */
	readonly taken?: true;
}

export type Transaction = TransactionBase & ByPurpose;
/** What a start gives; the rest the transaction takes from its start. */
export type Started = Pick<TransactionBase, "subject" | "held"> & ByPurpose;

export const hashOf = (value: string) => createHash("sha256").update(value).digest("base64url");
/** Whose live transactions a transaction counts among: the session it is tied to, or the held login's subject. */
export const holderOf = (t: Pick<TransactionBase, "subject"> & ByPurpose) =>
	"handle" in t ? `session:${t.handle}` : `login:${t.subject}`;
/** Format 1 kept a binding's own fields at the top; read, they become what it holds. */
const formerlyTop = ["pending", "bindingChallenge", "bindingPassed", "proved"];
export const transactionOf = (record: StoredTransaction | undefined) => {
	const t = record as unknown as (Transaction & Record<string, unknown>) | undefined;
	if (!t || t.format === 2) return t;
	const top = Object.entries(t).filter(([name]) => formerlyTop.includes(name));
	const rest = Object.fromEntries(
		Object.entries(t).filter(([name]) => !formerlyTop.includes(name)),
	);
	const held = top.length > 0 ? { held: Object.fromEntries(top) } : {};
	return { ...rest, ...held, format: 2 } as Transaction;
};
export const stored = (transaction: Transaction) => transaction as unknown as StoredTransaction;
/** Whether the transaction can still be used at `now`, on the kernel's clock. */
export const live = (transaction: Transaction, now: number) =>
	!transaction.taken && now < transaction.deadline;
/** The transaction without its challenge. */
export const unchallenged = ({ challenge: _, ...rest }: Transaction): Transaction => rest;
