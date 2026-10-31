import { isUnavailable } from "@mod/kernel";
import { refreshedExpiry, type UpstreamTokens } from "@mod/upstreams";
import type { Entry, Kept } from "../vault/vault.ts";
import type { Current, Parts } from "./renewal.ts";

/** How long a failed refresh answers the same without asking the upstream again. */
const failedForMs = 30_000;
export const bearer = (type: string) => type.toLowerCase() === "bearer";
export const text = (value: unknown) =>
	typeof value === "string" && value !== "" ? value : undefined;
export const scopeOf = (value: unknown) =>
	Array.isArray(value) && value.every((s) => typeof s === "string" && s !== "")
		? (value as readonly string[])
		: undefined;

/**
 * The one judgment of when a token ends, on `kernel`'s clock, and when it was obtained where its
 * end was stated. At login, an end that is not a positive number is due at once, and none stays
 * none unless a refresh token can renew it; at a refresh, none is the cap and anything not
 * positive refuses the answer. Both are capped.
 */
export function endOf(
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

/** What renewing works with of the record keeping: reads and writes over a version, and how a token is handed. */
export interface Records {
	readonly entryOf: (session: string, idp: string) => Promise<Entry | undefined>;
	readonly rewrite: (
		session: string,
		idp: string,
		next: Entry | undefined,
		version?: string,
	) => Promise<boolean>;
	readonly handed: (kept: Kept, refreshed: boolean) => Current;
	readonly versionOf: () => string;
	/** When each failed refresh, by `failedKey`, may be asked again. */
	readonly failedUntil: Map<string, number>;
	readonly failedKey: (session: string, idp: string, kept: Kept) => string;
}

/** The renewal of one entry near its end, under the lock the caller holds. */
export function renewWith(parts: Parts, records: Records) {
	const { vault } = parts;
	const { entryOf, rewrite, handed, versionOf, failedUntil, failedKey } = records;
	/** Asks the upstream for new tokens, holding the lock; writes only over the version read. */
	return async (
		session: string,
		idp: string,
		entry: Entry,
		kept: Kept,
		held: () => Promise<boolean>,
	) => {
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
		if (!(await held())) return { kind: "unavailable" } as const;
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
		// None said is the whole grant again; one wider than the grant, or unreadable, refuses the answer.
		const answered = said.scope === undefined ? [] : scopeOf(said.scope);
		const scope =
			answered?.length === 0
				? kept.granted
				: answered?.every((s) => kept.granted.includes(s))
					? answered
					: undefined;
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
					: answered === undefined
						? "invalid_scope"
						: scope === undefined
							? "wider_scope"
							: undefined;
		if (refused || accessToken === undefined || ends === "invalid" || scope === undefined) {
			if (refreshToken !== kept.refreshToken) {
				const rotated = vault.seal(session, idp, { ...kept, refreshToken }, versionOf());
				await rewrite(session, idp, rotated, entry.version);
			}
			return failed(refused ?? "unknown");
		}
		const idToken = text(said.idToken) ?? kept.idToken;
		const end =
			ends.end === undefined
				? undefined
				: refreshedExpiry({ accessToken, expiresAt: ends.end }, kept);
		const next: Kept = {
			accessToken,
			tokenType,
			refreshToken,
			...(idToken ? { idToken } : {}),
			...(end === undefined ? {} : { expiresAt: end }),
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
}
