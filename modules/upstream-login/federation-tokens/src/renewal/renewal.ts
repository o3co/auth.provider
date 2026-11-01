import { createHash } from "node:crypto";
import { type BuildContext, type Clock, isUnavailable, type Log, type Random } from "@mod/kernel";
import { type Sessions, sessions } from "@mod/session";
import { type Upstreams, type UpstreamTokens, upstreams } from "@mod/upstreams";
import type { Settings } from "../section.ts";
import {
	type RefreshLocks,
	refreshLocks,
	type UpstreamTokenStore,
	upstreamTokenStore,
} from "../store.ts";
import {
	type Entries,
	type Entry,
	type Kept,
	type Vault,
	vaultFrom,
	vaultTakes,
} from "../vault/vault.ts";
import { bearer, endOf, renewWith, scopeOf, text } from "./renewing.ts";

/** What a request for a session's upstream token comes to. */
export type Current =
	| {
			readonly kind: "handed";
			readonly accessToken: string;
			readonly expiresInSeconds?: number;
			readonly scope: readonly string[];
			readonly refreshed: boolean;
	  }
	| {
			readonly kind:
				| "not_linked"
				| "ineligible"
				| "refresh_absent"
				| "reauthenticate"
				| "interaction_required";
	  }
	| { readonly kind: "limited"; readonly retryAfterSeconds?: number }
	| { readonly kind: "failed"; readonly reason: string }
	| { readonly kind: "not_supported" | "lock_timeout" | "unavailable" };

export interface Parts {
	readonly store: UpstreamTokenStore;
	readonly locks: RefreshLocks;
	readonly upstreams: Upstreams;
	readonly sessions: Pick<Sessions, "entryOf">;
	readonly vault: Vault;
	readonly clock: Clock;
	readonly random: Random;
	readonly log: Log;
	readonly refreshBeforeMs: number;
	readonly maxLifetimeMs: number;
	readonly lockMs: number;
}

const leastLeftMs = 1000;
/** How many times a login's entry is written before it is given up, the record changing under it each time. */
const keepAttempts = 3;
/** How often a request waiting for another's refresh looks again. */
const pollMs = 100;
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function holding(locks: RefreshLocks, name: string, mark: string, lifetimeMs: number) {
	const keep = async () => {
		let ours = false;
		await locks.update(name, (held) => {
			ours = held === mark;
			return ours ? { value: held, lifetimeMs } : undefined;
		});
		return ours;
	};
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
	}, lifetimeMs / 2);
	timer.unref();
	return {
		ours: async () => !lost && (await keep()),
		stop: () => clearInterval(timer),
	};
}

/** Keeps each session's upstream tokens by IdP, and renews one near its end under a lock. */
export function renewalWith(parts: Parts) {
	const { store, vault } = parts;
	const failedUntil = new Map<string, number>();
	const versionOf = () => Buffer.from(parts.random.bytes(16)).toString("base64url");
	/**
	 * Near its end, once half its life is spent, so a life shorter than `refresh-before` is not
	 * renewed on every request; at once with less than a second left, or no time it was obtained.
	 */
	const due = (kept: Kept) => {
		const now = parts.clock.now();
		const { expiresAt: end, obtainedAt: from } = kept;
		if (end === undefined || end - now > parts.refreshBeforeMs) return false;
		return from === undefined || end - now < leastLeftMs || now - from >= (end - from) / 2;
	};
	const entryOf = async (session: string, idp: string) => {
		const entries = vault.entriesOf(await store.read(session));
		return Object.hasOwn(entries, idp) ? entries[idp] : undefined;
	};
	/** Names a token's failed refresh without keeping the token in memory. */
	const failedKey = (session: string, idp: string, kept: Kept) =>
		`${session}\n${idp}\n${createHash("sha256").update(kept.accessToken).digest("base64url")}`;

	/**
	 * What is left of the session, so its record never outlives it; none once it lets nobody in at
	 * use: closed, ended, revoked, or short of a requirement.
	 */
	const lifetimeOf = async (session: string) => {
		const entry = await parts.sessions.entryOf(session);
		const left = entry.kind === "entered" ? entry.endsAt - parts.clock.now() : 0;
		return left > 0 ? left : undefined;
	};

	/** Rewrites one IdP's entry, only while it holds `version` (or none, when none is answered). */
	const rewrite = async (
		session: string,
		idp: string,
		next: Entry | undefined,
		version?: string,
	) => {
		// A session that lets nobody in gets no write; what it holds goes with its closing or its lifetime.
		const lifetimeMs = await lifetimeOf(session);
		if (lifetimeMs === undefined) return false;
		const changed = await store.update(session, (record) => {
			const entries = vault.entriesOf(record);
			if (version !== undefined && entries[idp]?.version !== version) return undefined;
			const { [idp]: _gone, ...rest } = entries;
			const after: Entries = next ? { ...rest, [idp]: next } : rest;
			return { value: vault.recordOf(after), lifetimeMs };
		});
		const after = changed && vault.entriesOf(changed.after)[idp];
		return next ? after?.version === next.version : changed !== undefined && !after;
	};

	/** Removes one IdP's entry whatever the session's state, only at `version` when given; a session that lets nobody in keeps no record. */
	const forget = async (session: string, idp: string, version?: string) => {
		if (await rewrite(session, idp, undefined, version)) return;
		if ((await lifetimeOf(session)) === undefined) await store.remove(session);
	};

	/** Writes a login's entry into the record, or as its first; false for a session that lets nobody in. */
	const keep = async (session: string, idp: string, entry: Entry) => {
		for (let attempt = 0; attempt < keepAttempts; attempt++) {
			if (await rewrite(session, idp, entry)) return true;
			const lifetimeMs = await lifetimeOf(session);
			if (lifetimeMs === undefined) return false;
			const record = vault.recordOf({ [idp]: entry });
			if ((await store.save(session, record, lifetimeMs)) === "created") return true;
		}
		return false;
	};

	const handed = (kept: Kept, refreshed: boolean): Current => {
		const left =
			kept.expiresAt === undefined
				? undefined
				: Math.floor((kept.expiresAt - parts.clock.now()) / 1000);
		if (left !== undefined && left < 1) return { kind: "unavailable" };
		return {
			kind: "handed",
			accessToken: kept.accessToken,
			...(left === undefined ? {} : { expiresInSeconds: left }),
			scope: kept.scope,
			refreshed,
		};
	};

	/** Reads one entry: its tokens, or none, removing an entry that no longer opens. */
	const opened = async (session: string, idp: string) => {
		const entry = await entryOf(session, idp);
		if (!entry) return undefined;
		const read = vault.read(session, idp, entry);
		if (read) {
			// A past key's entry is sealed again in passing, over the version read: a write that cannot
			// be made leaves the read whole, for a later read or the resealer.
			if (read.resealed) {
				await rewrite(session, idp, read.resealed, entry.version).catch((error: unknown) => {
					if (!isUnavailable(error)) throw error;
				});
			}
			return { entry, kept: read.kept };
		}
		parts.log.warn("federation-tokens.record_unreadable", { idp });
		await rewrite(session, idp, undefined, entry.version);
		return undefined;
	};

	const renew = renewWith(parts, { entryOf, rewrite, handed, versionOf, failedUntil, failedKey });

	return {
		current: async (session: string, idp: string): Promise<Current> => {
			const found = await opened(session, idp);
			if (!found) return { kind: "not_linked" };
			if (!bearer(found.kept.tokenType)) return { kind: "ineligible" };
			if (!due(found.kept)) return handed(found.kept, false);
			const failed = failedKey(session, idp, found.kept);
			if ((failedUntil.get(failed) ?? 0) > parts.clock.now()) {
				return { kind: "failed", reason: "unknown" };
			}
			failedUntil.delete(failed);
			const lock = `${session}\n${idp}`;
			const mark = Buffer.from(parts.random.bytes(16)).toString("base64url");
			for (let waited = 0; ; waited += pollMs) {
				if ((await parts.locks.hold(lock, mark, parts.lockMs)) === "created") break;
				if (waited >= parts.lockMs) return { kind: "lock_timeout" };
				await pause(pollMs);
			}
			const keeping = holding(parts.locks, lock, mark, parts.lockMs);
			try {
				// Read again under the lock: another request may have renewed or removed it.
				const now = await opened(session, idp);
				if (!now) return { kind: "not_linked" };
				if (!bearer(now.kept.tokenType)) return { kind: "ineligible" };
				if (!due(now.kept)) return handed(now.kept, false);
				return await renew(session, idp, now.entry, now.kept, keeping.ours);
			} finally {
				keeping.stop();
				// Only while it still holds its own mark: one that ran out may be another host's now.
				await parts.locks.update(lock, (held) =>
					held === mark ? { value: held, lifetimeMs: 1 } : undefined,
				);
			}
		},
		/** Keeps a login's tokens for the session, answering the entry's version; tokens without an access token are not kept. */
		receive: async (
			session: string,
			idp: string,
			tokens: UpstreamTokens,
		): Promise<string | undefined> => {
			const said = tokens as unknown as Partial<Record<keyof UpstreamTokens, unknown>>;
			const accessToken = text(said.accessToken);
			const granted = scopeOf(said.scope);
			const unreadable = (key: "refreshToken" | "idToken") =>
				said[key] !== undefined && text(said[key]) === undefined;
			if (!accessToken || !granted || unreadable("refreshToken") || unreadable("idToken")) {
				parts.log.warn("federation-tokens.login_tokens_refused", { idp });
				await rewrite(session, idp, undefined);
				return undefined;
			}
			const refreshToken = text(said.refreshToken);
			const idToken = text(said.idToken);
			const now = parts.clock.now();
			const ends = endOf(said.expiresInSeconds, now, parts.maxLifetimeMs, "login", !!refreshToken);
			const kept: Kept = {
				accessToken,
				tokenType: typeof said.tokenType === "string" ? said.tokenType : "",
				...(refreshToken ? { refreshToken } : {}),
				...(idToken ? { idToken } : {}),
				...(ends === "invalid" || ends.end === undefined ? {} : { expiresAt: ends.end }),
				...(ends === "invalid" || ends.obtainedAt === undefined
					? {}
					: { obtainedAt: ends.obtainedAt }),
				granted,
				scope: granted,
			};
			const entry = vault.seal(session, idp, kept, versionOf());
			const written = await keep(session, idp, entry);
			// A session that closed, or fell short of a requirement, while they were written: they go here.
			if (written && (await lifetimeOf(session)) !== undefined) return entry.version;
			if (written) await forget(session, idp, entry.version);
			parts.log.warn("federation-tokens.login_tokens_not_kept", { idp });
			return undefined;
		},
		/** Removes one IdP's entry; answers its id_token, or not linked when it held none. */
		disconnect: async (session: string, idp: string) => {
			const entry = await entryOf(session, idp);
			if (!entry) return { kind: "not_linked" } as const;
			const kept = vault.open(session, idp, entry);
			await rewrite(session, idp, undefined);
			return { kind: "disconnected", ...(kept?.idToken ? { idToken: kept.idToken } : {}) } as const;
		},
		/** The first IdP the session holds tokens of, with its id_token when the entry opens. */
		first: async (session: string) => {
			const entries = vault.entriesOf(await store.read(session));
			const [idp] = Object.keys(entries);
			const entry = idp === undefined ? undefined : entries[idp];
			if (idp === undefined || entry === undefined) return undefined;
			return { idp, idToken: vault.open(session, idp, entry)?.idToken };
		},
		/** Takes back what a login kept, by its receipt; without one, the login kept nothing. */
		withdraw: async (session: string, idp: string, receipt: string | undefined) => {
			if (receipt !== undefined) await forget(session, idp, receipt);
		},
		close: (session: string) => store.remove(session),
	};
}

export type Renewal = ReturnType<typeof renewalWith>;

/** What `renewalIn` takes from the build context, `sessions` late, and the vault's. */
export const renewalTakes = [
	sessions,
	upstreamTokenStore,
	refreshLocks,
	upstreams,
	...vaultTakes,
] as const;

/** The keeper over the build context: its stores, `upstreams`, the vault and `session`'s entries, taken here. */
export async function renewalIn(c: BuildContext<Settings>): Promise<Renewal> {
	// Late: session collects this module's participant, which uses the keeper.
	const lateSessions = c.late(sessions);
	return renewalWith({
		store: await c.get(upstreamTokenStore),
		locks: await c.get(refreshLocks),
		upstreams: await c.get(upstreams),
		sessions: { entryOf: (handle, level) => lateSessions().entryOf(handle, level) },
		vault: await vaultFrom(c),
		clock: c.clock,
		random: c.random,
		log: c.log,
		refreshBeforeMs: c.section["refresh-before"] * 1000,
		maxLifetimeMs: c.section["max-lifetime"] * 1000,
		lockMs: c.section["lock-lifetime"] * 1000,
	});
}
