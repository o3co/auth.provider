import { contract } from "@mod/kernel";

declare const storedGrant: unique symbol;
/** A grant as the store keeps it: its state, its current intent and its sealed credentials; only federation-grants reads it. */
export type StoredGrant = { readonly [storedGrant]: true };

declare const storedStep: unique symbol;
/** One step of a connection in a browser (its link, its question, its upstream round trip); only federation-grants reads it. */
export type StoredStep = { readonly [storedStep]: true };

/** A record changed from what it holds, with a new lifetime when given. */
export interface Rewrite<T> {
	readonly value: T;
	readonly lifetimeMs?: number;
}

/** Grants by id. Every call throws Unavailable when the place cannot tell. */
export interface GrantStore {
	/** Keeps a new grant for its lifetime, unless the id holds one. */
	create(id: string, record: StoredGrant, lifetimeMs: number): Promise<"created" | "exists">;
	read(id: string): Promise<StoredGrant | undefined>;
	/** Changes the grant from what it holds; `change` reruns on a race, so it is pure. Nothing when gone. */
	change(
		id: string,
		change: (record: StoredGrant) => Rewrite<StoredGrant> | undefined,
	): Promise<{ readonly before: StoredGrant; readonly after: StoredGrant } | undefined>;
	/** A page of the ids of the grants that live, and the cursor on; none when done. A walk is no one instant. */
	scan?(cursor?: string): Promise<{ readonly keys: readonly string[]; readonly cursor?: string }>;
}

export const grantStore = contract<GrantStore>("federation-grants.grant-store");

/** A grant lost or rolled back would hand out or bring back credentials; an activation is read by another request. */
export const grantStoreNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
	readsConfirmed: true,
} as const;

/** Steps by the secret a browser presents, never kept in clear. Every call throws Unavailable when the place cannot tell. */
export interface StepStore {
	create(secret: string, record: StoredStep, lifetimeMs: number): Promise<"created" | "exists">;
	read(secret: string): Promise<StoredStep | undefined>;
	/** Changes the step from what it holds; `change` reruns on a race, so it is pure. Nothing when gone. */
	change(
		secret: string,
		change: (record: StoredStep) => Rewrite<StoredStep> | undefined,
	): Promise<{ readonly before: StoredStep; readonly after: StoredStep } | undefined>;
}

export const stepStore = contract<StepStore>("federation-grants.step-store");

/** A taken step back after a failover could be answered twice; names derive from the secret. */
export const stepStoreNeeds = {
	neverEvicted: true,
	survivesFailover: true,
	namesFromSecret: true,
} as const;

/** First-time intents waiting for their connection, by client and subject, at most the wiring's cap to a pair. */
export interface PendingIntents {
	/** Adds a grant for a lifetime; answers the grants pushed out over the cap as `pushedOut`. */
	add(
		pair: string,
		grant: string,
		lifetimeMs: number,
	): Promise<{ readonly pushedOut: readonly string[] }>;
	remove(pair: string, grant: string): Promise<void>;
}

export const pendingIntents = contract<PendingIntents>("federation-grants.pending-intents");

/** A set evicted would lift the cap. */
export const pendingIntentsNeeds = { neverEvicted: true } as const;

/** Each subject's grants, listed for their records' lifetime, so a revocation's closing work finds them; a lost one only skips that work. Every call throws Unavailable when the place cannot tell. */
export interface SubjectGrants {
	add(
		subject: string,
		grant: string,
		lifetimeMs: number,
	): Promise<{ readonly pushedOut: readonly string[] }>;
	members(subject: string): Promise<readonly { readonly member: string }[]>;
	remove(subject: string, grant: string): Promise<void>;
}

export const subjectGrants = contract<SubjectGrants>("federation-grants.subject-grants");

/** A grant left off its subject's listing keeps its credentials sealed until it is next read. */
export const subjectGrantsNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
} as const;

/** Refresh locks by grant: `hold` places a holder's mark unless one is held, kept until its lifetime ends. Every call throws Unavailable when the place cannot tell. */
export interface RefreshLockStore {
	hold(grant: string, mark: string, lifetimeMs: number): Promise<"created" | "exists">;
	/** Changes a held lock from the mark it holds now, writing only over what it read; nothing when none is held. */
	update(
		grant: string,
		change: (mark: string) => Rewrite<string> | undefined,
	): Promise<{ readonly before: string; readonly after: string } | undefined>;
}

export const refreshLockStore = contract<RefreshLockStore>("federation-grants.refresh-lock-store");

/** A lock evicted while held would let two hosts refresh one grant at once. */
export const refreshLockStoreNeeds = { neverEvicted: true } as const;
