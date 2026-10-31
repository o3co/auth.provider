import type { BuildContext, Clock, Log, Random } from "@mod/kernel";
import type { Delegation } from "@mod/upstreams";
import {
	type Credentials,
	type Grant,
	type Ineligible,
	type Records,
	within,
} from "../grant/grant.ts";
import type { Settings } from "../section.ts";
import { type GrantStore, grantStore, type RefreshLockStore, refreshLockStore } from "../store.ts";
import { keeping, locked } from "./locking.ts";
import { renewWith } from "./renewing.ts";

/** What a request for a grant's upstream token comes to. */
export type Current =
	| {
			readonly kind: "handed";
			readonly accessToken: string;
			readonly tokenType: string;
			readonly expiresInSeconds: number;
			readonly scope: readonly string[];
			readonly refreshed: boolean;
	  }
	| { readonly kind: "reauthorize"; readonly reason: string }
	| { readonly kind: "ineligible"; readonly reason: Ineligible }
	| { readonly kind: "limited"; readonly retryAfterSeconds?: number }
	| { readonly kind: "refused" | "unavailable" | "lock_timeout" | "scope" | "gone" };

export interface Parts {
	readonly grants: GrantStore;
	readonly locks: RefreshLockStore;
	readonly records: Records;
	/** Whether a subject's revocation since its activation ends the grant (the grants' judge). */
	readonly revoked: (grant: Grant) => Promise<boolean>;
	/** When the grant ends, held to the longest a grant may live now (the grants' judge). */
	readonly endOf: (grant: Grant) => number | undefined;
	readonly clock: Clock;
	readonly random: Random;
	readonly log: Log;
	readonly refreshBeforeMs: number;
	readonly rotations: number;
	readonly rotationWindowMs: number;
}

/** What one request asks of the token: scopes it must carry, and how long it must still live. */
export interface Asked {
	readonly delegation: Delegation;
	readonly resource?: string;
	readonly maxAccessMs: number;
	readonly scope?: readonly string[];
	readonly minTtlMs: number;
	/** When the grant itself ends, which caps what a token is said to live. */
	readonly grantEndsAt: number;
}

/** Less than this left of a held token: it no longer serves when a refresh cannot, and is due at once. */
const leastLeftMs = 1000;
const inUse = (grant: Grant | undefined) =>
	grant?.status === "active" || grant?.status === "upstream_token_ineligible";

/** Hands a grant's upstream token, refreshing it under a lock within the rotation budget. */
export function refreshWith(parts: Parts) {
	const { grants, records } = parts;
	const versionOf = () => Buffer.from(parts.random.bytes(16)).toString("base64url");
	const leftOf = (held: Credentials) => held.expiresAt - parts.clock.now();
	/** Whether the grant is past its end by now: its credentials are then not to be used. */
	const ended = (grant: Grant) => {
		const end = parts.endOf(grant);
		return end !== undefined && end <= parts.clock.now();
	};
	/** Whether the grant, as read now, may still hand out a token: in use, not ended, not revoked. */
	const serves = async (grant: Grant) =>
		inUse(grant) && !ended(grant) && !(await parts.revoked(grant));

	const handed = (held: Credentials, asked: Asked, refreshed: boolean): Current => {
		const ends = Math.min(held.expiresAt, asked.grantEndsAt);
		return {
			kind: "handed",
			accessToken: held.accessToken,
			tokenType: held.tokenType,
			expiresInSeconds: Math.max(0, Math.floor((ends - parts.clock.now()) / 1000)),
			scope: held.scope,
			refreshed,
		};
	};
	const carries = (held: Credentials, asked: Asked) =>
		asked.scope === undefined || within(asked.scope, held.scope);
	/**
	 * A held token that still lives a second serves when a refresh cannot, but only while the grant,
	 * read again, is still in use: one revoked or ended while the upstream was asked hands out nothing.
	 */
	const heldOr = async (
		id: string,
		held: Credentials | undefined,
		asked: Asked,
		otherwise: Current,
	): Promise<Current> => {
		if (!held || leftOf(held) < leastLeftMs || !carries(held, asked)) return otherwise;
		const now = records.grantOf(await grants.read(id));
		return now && (await serves(now)) ? handed(held, asked, false) : { kind: "gone" };
	};
	/** Due near its end once half its life is spent, or when it lacks what is asked. */
	const due = (held: Credentials, asked: Asked) => {
		const left = leftOf(held);
		const half =
			left < leastLeftMs ||
			parts.clock.now() - held.obtainedAt >= (held.expiresAt - held.obtainedAt) / 2;
		const wanted = left <= parts.refreshBeforeMs || left <= asked.minTtlMs || !carries(held, asked);
		return half && wanted;
	};

	/** Rewrites the grant only while it holds `version` and is in use, so a revocation is never written over. */
	const rewrite = async (grant: Grant, next: (grant: Grant) => Grant) => {
		const changed = await grants.change(grant.id, (stored) => {
			const now = records.grantOf(stored);
			if (now?.version !== grant.version || !inUse(now)) return undefined;
			return { value: records.stored(next(now)) };
		});
		// Its own write only: another writer's since the read also moves the version.
		const before = records.grantOf(changed?.before);
		const after = records.grantOf(changed?.after);
		return before?.version === grant.version && after && after.version !== grant.version
			? after
			: undefined;
	};

	const { renew, unended } = renewWith(parts, {
		rewrite,
		heldOr,
		handed,
		carries,
		ended,
		versionOf,
	});

	return {
		/** The grant's token as `asked`, from the grant read by the caller (active, owned, not ended). */
		current: async (grant: Grant, asked: Asked): Promise<Current> => {
			const unwritten = unended(grant);
			if (unwritten && unwritten.until > parts.clock.now())
				return { kind: "reauthorize", reason: unwritten.reason };
			const held = records.open(grant);
			if (!held) return { kind: "reauthorize", reason: "credentials_unreadable" };
			if (!due(held, asked))
				return carries(held, asked) ? handed(held, asked, false) : { kind: "scope" };
			const mark = Buffer.from(parts.random.bytes(16)).toString("base64url");
			if (!(await locked(parts.locks, grant.id, mark)))
				return heldOr(grant.id, held, asked, { kind: "lock_timeout" });
			const kept = keeping(parts.locks, grant.id, mark);
			try {
				// Read again under the lock: another request may have refreshed, ended or revoked it, or the
				// subject's revocation or the grant's end may have come while it waited.
				const now = records.grantOf(await grants.read(grant.id));
				if (!now || !(await serves(now))) return { kind: "gone" };
				const again = records.open(now);
				if (!again) return { kind: "reauthorize", reason: "credentials_unreadable" };
				if (!due(again, asked))
					return carries(again, asked) ? handed(again, asked, false) : { kind: "scope" };
				return await renew(now, again, asked, kept.ours);
			} finally {
				kept.stop();
				// Only while it still holds its own mark: one that ran out may be another host's now.
				await parts.locks.update(grant.id, (holds) =>
					holds === mark ? { value: holds, lifetimeMs: 1 } : undefined,
				);
			}
		},
	};
}

export type Refresh = ReturnType<typeof refreshWith>;

export const refreshTakes = [grantStore, refreshLockStore] as const;

/** The refresher over the grants and locks the assembly gives, on `records`. */
export const refreshOver = async (
	c: BuildContext<Settings>,
	records: Records,
	judge: {
		readonly revoked: (grant: Grant) => Promise<boolean>;
		readonly endOf: (grant: Grant) => number | undefined;
	},
) =>
	refreshWith({
		revoked: judge.revoked,
		endOf: judge.endOf,
		grants: await c.get(grantStore),
		locks: await c.get(refreshLockStore),
		records,
		clock: c.clock,
		random: c.random,
		log: c.log,
		refreshBeforeMs: c.section["refresh-before"] * 1000,
		rotations: c.section.rotations,
		rotationWindowMs: c.section["rotation-window"] * 1000,
	});
