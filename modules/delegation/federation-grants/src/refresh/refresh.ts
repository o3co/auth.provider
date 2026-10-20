import { type BuildContext, type Clock, isUnavailable, type Log, type Random } from "@mod/kernel";
import { type Delegation, UpstreamRefused } from "@mod/upstreams";
import {
	type Credentials,
	credentialsFrom,
	type Grant,
	type Ineligible,
	type Records,
	within,
	withoutCredentials,
} from "../grant/grant.ts";
import type { Settings } from "../section.ts";
import { type GrantStore, grantStore, type RefreshLockStore, refreshLockStore } from "../store.ts";

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

const lockMs = 10_000;
const inUse = (grant: Grant | undefined) =>
	grant?.status === "active" || grant?.status === "upstream_token_ineligible";
const pollMs = 100;
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

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
		if (!held || leftOf(held) < 1000 || !carries(held, asked)) return otherwise;
		const now = records.grantOf(await grants.read(id));
		return now && (await serves(now)) ? handed(held, asked, false) : { kind: "gone" };
	};
	/** Due near its end once half its life is spent, or when it lacks what is asked. */
	const due = (held: Credentials, asked: Asked) => {
		const left = leftOf(held);
		const half =
			left < 1000 || parts.clock.now() - held.obtainedAt >= (held.expiresAt - held.obtainedAt) / 2;
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

	/**
	 * Grants, by id and version, whose end an upstream asked could not be written: refused as the
	 * upstream answered until the held token ends, when a request is due and asks again.
	 */
	const unwritten = new Map<string, { readonly until: number; readonly reason: string }>();
	const keyOf = (grant: Grant) => `${grant.id}\n${grant.version}`;
	/** Ends the grant as the upstream asked; an end the store cannot write is remembered, then thrown on. */
	const end = async (counted: Grant, held: Credentials, reason: string): Promise<Current> => {
		try {
			const ended = await rewrite(counted, (g) => ({
				...withoutCredentials(g),
				version: versionOf(),
				status: "reauthorization_required",
				reason,
			}));
			return ended ? { kind: "reauthorize", reason } : { kind: "gone" };
		} catch (error) {
			const now = parts.clock.now();
			for (const [key, kept] of unwritten) if (kept.until <= now) unwritten.delete(key);
			unwritten.set(keyOf(counted), { until: held.expiresAt, reason });
			throw error;
		}
	};

	/** Spends one rotation of the window: the grant written with it, how long until the window lets one, or gone. */
	const spend = async (
		grant: Grant,
	): Promise<
		| { readonly kind: "spent"; readonly grant: Grant }
		| { readonly kind: "wait"; readonly ms: number }
		| { readonly kind: "gone" }
	> => {
		const now = parts.clock.now();
		const fresh = now - grant.rotations.from >= parts.rotationWindowMs;
		const rotations = fresh ? { from: now, count: 0 } : grant.rotations;
		if (rotations.count >= parts.rotations) {
			return { kind: "wait", ms: rotations.from + parts.rotationWindowMs - now };
		}
		const spent = await rewrite(grant, (g) => ({
			...g,
			version: versionOf(),
			rotations: { from: rotations.from, count: rotations.count + 1 },
		}));
		return spent ? { kind: "spent", grant: spent } : { kind: "gone" };
	};
	/** Holds the grant's lock under `mark`, asking again for half its life; false when another holder kept it. */
	const locked = async (id: string, mark: string) => {
		for (let waited = 0; waited <= lockMs / 2; waited += pollMs) {
			if ((await parts.locks.hold(id, mark, lockMs)) === "created") return true;
			if (waited < lockMs / 2) await pause(pollMs);
		}
		return false;
	};

	/** The lock kept for its life again every half of it, only under `mark`; `ours` keeps it once more, answering whether it is still held. */
	const keeping = (id: string, mark: string) => {
		const keep = async () =>
			(
				await parts.locks.update(id, (holds) =>
					holds === mark ? { value: holds, lifetimeMs: lockMs } : undefined,
				)
			)?.before === mark;
		let lost = false;
		const timer = setInterval(() => {
			keep().then(
				(ours) => {
					if (!ours) {
						lost = true;
						clearInterval(timer);
					}
				},
				() => clearInterval(timer),
			);
		}, lockMs / 2);
		timer.unref?.();
		return { ours: async () => !lost && (await keep()), stop: () => clearInterval(timer) };
	};

	const renew = async (
		grant: Grant,
		held: Credentials,
		asked: Asked,
		ours: () => Promise<boolean>,
	): Promise<Current> => {
		const spent = await spend(grant);
		if (spent.kind === "gone") return { kind: "gone" };
		if (spent.kind === "wait") {
			const after = Math.max(1, Math.ceil(spent.ms / 1000));
			return heldOr(grant.id, held, asked, { kind: "limited", retryAfterSeconds: after });
		}
		// The grant with this rotation counted: what every later write lands over.
		const counted = spent.grant;
		if (!held.refreshToken)
			return heldOr(grant.id, held, asked, { kind: "reauthorize", reason: "refresh_token_absent" });
		let refreshed: Awaited<ReturnType<Delegation["refresh"]>>;
		try {
			refreshed = await asked.delegation.refresh(held.refreshToken, counted.scopes, asked.resource);
		} catch (error) {
			// The upstream down or refusing says nothing of the credential, which stays.
			if (isUnavailable(error)) return heldOr(grant.id, held, asked, { kind: "unavailable" });
			if (error instanceof UpstreamRefused)
				return heldOr(grant.id, held, asked, { kind: "refused" });
			throw error;
		}
		// A grant ended, or its subject revoked, while the upstream was asked gets nothing, written or
		// handed: a grant its listing missed is not ended by the follower, only by the boundary.
		if (ended(counted) || (await parts.revoked(counted))) return { kind: "gone" };
		// A lock run out is another holder's refresh now: nothing answered here is written.
		if (!(await ours())) return heldOr(grant.id, held, asked, { kind: "unavailable" });
		if (refreshed.kind === "limited") {
			const { retryAfterSeconds } = refreshed;
			const limited = retryAfterSeconds === undefined ? {} : { retryAfterSeconds };
			return heldOr(grant.id, held, asked, { kind: "limited", ...limited });
		}
		if (refreshed.kind === "invalid_grant") return end(counted, held, "upstream_invalid_grant");
		// The grant stands upstream, but the user must act there: the client asks for it anew.
		if (refreshed.kind === "interaction_required")
			return end(counted, held, "upstream_interaction_required");
		// Only a refresh that handed tokens is read on; an answer of another kind is refused.
		const answered = refreshed.kind === "refreshed" ? refreshed : undefined;
		if (!answered) return heldOr(grant.id, held, asked, { kind: "refused" });
		const now = parts.clock.now();
		const read = credentialsFrom(answered.tokens, {
			now,
			maxAccessMs: asked.maxAccessMs,
			shown: counted.scopes,
			held: held.refreshToken,
		});
		if (read.kind === "refused") {
			// A rotated refresh token is written before anything is judged of the rest.
			const rotated = {
				...held,
				...(read.refreshToken ? { refreshToken: read.refreshToken } : {}),
			};
			const marked = await rewrite(counted, (g) => ({
				...g,
				version: versionOf(),
				sealed: records.seal(g, rotated),
				status: g.status === "active" ? "upstream_token_ineligible" : g.status,
				reason: read.why,
			}));
			parts.log.warn("federation-grants.refresh_ineligible", { reason: read.why });
			if (!marked) return { kind: "gone" };
			return heldOr(counted.id, rotated, asked, { kind: "ineligible", reason: read.why });
		}
		const kept = await rewrite(counted, (g) => {
			const { reason: _cleared, ...rest } = g;
			return {
				...rest,
				version: versionOf(),
				sealed: records.seal(g, read.credentials),
				status: g.status === "upstream_token_ineligible" ? "active" : g.status,
			};
		});
		if (!kept) return { kind: "gone" };
		return carries(read.credentials, asked)
			? handed(read.credentials, asked, true)
			: { kind: "scope" };
	};

	return {
		/** The grant's token as `asked`, from the grant read by the caller (active, owned, not ended). */
		current: async (grant: Grant, asked: Asked): Promise<Current> => {
			const unended = unwritten.get(keyOf(grant));
			if (unended && unended.until > parts.clock.now())
				return { kind: "reauthorize", reason: unended.reason };
			const held = records.open(grant);
			if (!held) return { kind: "reauthorize", reason: "credentials_unreadable" };
			if (!due(held, asked))
				return carries(held, asked) ? handed(held, asked, false) : { kind: "scope" };
			const mark = Buffer.from(parts.random.bytes(16)).toString("base64url");
			if (!(await locked(grant.id, mark)))
				return heldOr(grant.id, held, asked, { kind: "lock_timeout" });
			const kept = keeping(grant.id, mark);
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
