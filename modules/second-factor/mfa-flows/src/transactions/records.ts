import { createHash } from "node:crypto";
import type { LoginFrom } from "@mod/login-gates";
import type { LoginFacts } from "@mod/session";
import type { StoredTransaction } from "../store.ts";

export interface Challenge {
	readonly factor: string;
	readonly sealed: string;
}

/** A binding proof's challenge: the proof's name, and what mfa-binding-proof sealed. */
export interface BindingChallenge {
	readonly proof: string;
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

interface Common {
	readonly subject: string;
	/** The hash of the browser's mfa cookie: the transaction is no bearer. */
	readonly browser: string;
	/** Kernel-clock epoch ms; past `deadline`, the transaction is gone whatever the store keeps. */
	readonly startedAt: number;
	readonly deadline: number;
	readonly attemptsLeft: number;
	/** A binding waiting for its first proof, sealed by mfa. */
	readonly pending?: string;
	/** The challenge last sent for a factor, sealed by mfa; the next proof takes it. */
	readonly challenge?: Challenge;
	/** The binding proof's challenge last sent; it stands until replaced or proved. */
	readonly bindingChallenge?: BindingChallenge;
	/** The pass `mfa-binding-proof` gave for the binding proof passed in this transaction, so a binding may begin in it. */
	readonly bindingPassed?: { readonly kind: string; readonly pass: string };
	/** A binding proof passed in it: a first factor bound in it counts at once. */
	readonly proved?: true;
	/** Taken once: kept to its lifetime so it stays taken, and read as gone. */
	readonly taken?: true;
}

export type Transaction = Common & ByPurpose;
/** What a start gives; the rest the transaction takes from its start. */
export type Started = Pick<Common, "subject" | "pending" | "bindingChallenge"> & ByPurpose;

export const hashOf = (value: string) => createHash("sha256").update(value).digest("base64url");
export const transactionOf = (record: StoredTransaction | undefined) =>
	record as unknown as Transaction | undefined;
export const stored = (transaction: Transaction) => transaction as unknown as StoredTransaction;
/** Whether the transaction can still be used at `now`, on the kernel's clock. */
export const live = (transaction: Transaction, now: number) =>
	!transaction.taken && now < transaction.deadline;
/** The transaction without its challenge. */
export const unchallenged = ({ challenge: _, ...rest }: Transaction): Transaction => rest;
