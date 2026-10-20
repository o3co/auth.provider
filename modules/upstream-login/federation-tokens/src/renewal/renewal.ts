import { createHash } from "node:crypto";
import { type Clock, isUnavailable, type Log, type Random } from "@mod/kernel";
import type { Sessions } from "@mod/session";
import type { Upstreams, UpstreamTokens } from "@mod/upstreams";
import type { RefreshLocks, UpstreamTokenStore } from "../store.ts";
import type { Entries, Entry, Kept, Vault } from "../vault/vault.ts";

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

/** How long a failed refresh answers the same without asking the upstream again. */
const failedForMs = 30_000;
/** How often a request waiting for another's refresh looks again. */
const pollMs = 100;
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const bearer = (type: string) => type.toLowerCase() === "bearer";
const text = (value: unknown) => (typeof value === "string" && value !== "" ? value : undefined);
const scopeOf = (value: unknown) =>
	Array.isArray(value) && value.every((s) => typeof s === "string" && s !== "")
		? (value as readonly string[])
		: undefined;

/**
 * The one judgment of when a token ends, on `kernel`'s clock, and when it was obtained where its
 * end was stated. At login, an end that is not a positive number is due at once, and none stays
 * none unless a refresh token can renew it; at a refresh, none is the cap and anything not
 * positive refuses the answer. Both are capped.
 */
function endOf(
	said: unknown,
	now: number,
	maxMs: number,
	at: "login" | "refresh",
	renews: boolean,
) {
	const ok = typeof said === "number" && Number.isFinite(said) && said > 0;
	if (said === undefined) {
		if (at === "refresh") return { end: now + maxMs, obtainedAt: now };
		return renews ? { end: now } : {};
	}
	if (!ok) return at === "login" ? { end: now } : "invalid";
	return { end: now + Math.min(said * 1000, maxMs), obtainedAt: now };
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
		return from === undefined || end - now < 1000 || now - from >= (end - from) / 2;
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
		for (let attempt = 0; attempt < 3; attempt++) {
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

	/** Asks the upstream for new tokens, holding the lock; writes only over the version read. */
	const renew = async (session: string, idp: string, entry: Entry, kept: Kept) => {
		const upstream = parts.upstreams.of(idp);
		if (!kept.refreshToken) return { kind: "refresh_absent" } as const;
		if (!upstream?.refresh) return { kind: "not_supported" } as const;
		const failed = (reason: string): Current => {
			const now = parts.clock.now();
			for (const [key, until] of failedUntil) if (until <= now) failedUntil.delete(key);
			failedUntil.set(failedKey(session, idp, kept), now + failedForMs);
			parts.log.warn("federation-tokens.refresh_failed", { idp, reason });
			return { kind: "failed", reason };
		};
		let answer: Awaited<ReturnType<NonNullable<typeof upstream.refresh>>>;
		try {
			answer = await upstream.refresh(kept.refreshToken, kept.granted);
		} catch (error) {
			if (isUnavailable(error)) return { kind: "unavailable" } as const;
			return failed("unknown");
		}
		if (answer.kind === "limited") return answer;
		if (answer.kind === "invalid_grant") {
			await rewrite(session, idp, undefined, entry.version);
			return { kind: "reauthenticate" } as const;
		}
		// Forgotten too, so no refresh is asked again until the user logs in there anew.
		if (answer.kind === "interaction_required") {
			await rewrite(session, idp, undefined, entry.version);
			return { kind: "interaction_required" } as const;
		}
		// Only a refresh that handed tokens is read on; an answer of another kind is a failure.
		const refreshed = answer.kind === "refreshed" ? answer : undefined;
		if (!refreshed) return failed("unknown");
		const said = refreshed.tokens as unknown as Partial<Record<keyof UpstreamTokens, unknown>>;
		// A rotated refresh token is kept when the answer matches the IdP type's token answer schema, even where the rest of it is refused here.
		const refreshToken = text(said.refreshToken) ?? kept.refreshToken;
		// None said is the whole grant again; one wider than the grant, or unreadable, changes nothing.
		const answered = said.scope === undefined ? [] : scopeOf(said.scope);
		const scope =
			answered?.length === 0
				? kept.granted
				: answered?.every((s) => kept.granted.includes(s))
					? answered
					: kept.scope;
		const accessToken = text(said.accessToken);
		const ends = endOf(
			said.expiresInSeconds,
			parts.clock.now(),
			parts.maxLifetimeMs,
			"refresh",
			true,
		);
		const tokenType = typeof said.tokenType === "string" ? said.tokenType : "";
		const refused = !accessToken
			? "no_access_token"
			: ends === "invalid"
				? "invalid_expiry"
				: !bearer(tokenType)
					? "invalid_token_type"
					: undefined;
		if (refused || accessToken === undefined || ends === "invalid") {
			if (refreshToken !== kept.refreshToken) {
				const rotated = vault.seal(session, idp, { ...kept, refreshToken }, versionOf());
				await rewrite(session, idp, rotated, entry.version);
			}
			return failed(refused ?? "unknown");
		}
		const idToken = text(said.idToken) ?? kept.idToken;
		const next: Kept = {
			accessToken,
			tokenType,
			refreshToken,
			...(idToken ? { idToken } : {}),
			...(ends.end === undefined ? {} : { expiresAt: ends.end }),
			...(ends.obtainedAt === undefined ? {} : { obtainedAt: ends.obtainedAt }),
			granted: kept.granted,
			scope,
		};
		const version = versionOf();
		if (await rewrite(session, idp, vault.seal(session, idp, next, version), entry.version)) {
			return handed(next, true);
		}
		// Removed or linked again while this ran: neither is brought back nor written over.
		return (await entryOf(session, idp))
			? ({ kind: "unavailable" } as const)
			: ({ kind: "not_linked" } as const);
	};

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
			try {
				// Read again under the lock: another request may have renewed or removed it.
				const now = await opened(session, idp);
				if (!now) return { kind: "not_linked" };
				if (!bearer(now.kept.tokenType)) return { kind: "ineligible" };
				if (!due(now.kept)) return handed(now.kept, false);
				return await renew(session, idp, now.entry, now.kept);
			} finally {
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
