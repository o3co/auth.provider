import { isUnavailable } from "@mod/kernel";
import { type Delegation, UpstreamRefused } from "@mod/upstreams";
import {
	type Credentials,
	credentialsFrom,
	type Grant,
	withoutCredentials,
} from "../grant/grant.ts";
import type { Asked, Current, Parts } from "./refresh.ts";

/** What renewing works with of the refresher: the grant's write over its version, and how a token is handed or held. */
export interface Held {
	readonly rewrite: (grant: Grant, next: (grant: Grant) => Grant) => Promise<Grant | undefined>;
	readonly heldOr: (
		id: string,
		held: Credentials | undefined,
		asked: Asked,
		otherwise: Current,
	) => Promise<Current>;
	readonly handed: (held: Credentials, asked: Asked, refreshed: boolean) => Current;
	readonly carries: (held: Credentials, asked: Asked) => boolean;
	readonly ended: (grant: Grant) => boolean;
	readonly versionOf: () => string;
}

/** A grant's token renewed under its lock, within the rotation budget, and the ends the store could not write. */
export function renewWith(
	parts: Parts,
	{ rewrite, heldOr, handed, carries, ended, versionOf }: Held,
) {
	const { records } = parts;
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
			if (UpstreamRefused.is(error)) return heldOr(grant.id, held, asked, { kind: "refused" });
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
			kept: held,
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
	/** The end an upstream asked for the grant at its version, where the store could not write it. */
	const unended = (grant: Grant) => unwritten.get(keyOf(grant));
	return { renew, unended };
}
