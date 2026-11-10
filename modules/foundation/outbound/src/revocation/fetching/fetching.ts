import { signatureAlgorithms, type VerifiedCrl, verifyCrl } from "@mod/x509-path";
import type { Kept } from "../kept/kept.ts";
import type { Certificate } from "../trust.ts";

/** Why a peer's revocation is unconfirmed. */
export type Unconfirmed =
	| "path"
	| "https-only"
	| "unlisted"
	| "unsupported"
	| "unreachable"
	| "refused"
	| "too-large"
	| "malformed"
	| "stale"
	| "signature"
	| "issuer"
	| "rollback"
	| "revocation-state-full";

/** What a fetch of a CRL brought: its bytes, why none, or `aborted` by the signal it was given. */
export type Fetched = Uint8Array | "refused" | "unreachable" | "too-large" | "aborted";

/** How CRLs are fetched, and when; the package's, which alone sends requests and counts them. */
export interface Fetching {
	fetch(url: string, signal: AbortSignal): Promise<Fetched>;
	/** Runs a refresh in a place of its own where one is free, else passes it over. */
	inBackground(refresh: (signal: AbortSignal) => Promise<unknown>): void;
	now(): number;
	/** How long a failed fetch is remembered; how long after a fetch it is fetched again. */
	readonly failureMs: number;
	readonly crlTtlMs: number;
}

/** How far ahead of now a CRL's this update is taken. */
const skewMs = 5 * 60_000;
/** The failures remembered at most, the oldest going first. */
const mostFailures = 4096;

/** x509-path's reasons a CRL is unusable for its issuer: its name, its right to sign CRLs, its dates. */
const byIssuer = new Set(["issuer", "issuer cannot sign crls", "issuer out of date"]);

/** x509-path's reason a CRL is unusable, in outbound's words. */
export const reasonOf = (reason: string): Unconfirmed =>
	reason === "malformed" || reason === "unsupported"
		? reason
		: reason === "stale" || reason === "not yet"
			? "stale"
			: byIssuer.has(reason)
				? "issuer"
				: "signature";

const fromTaken = {
	rollback: "rollback",
	"state-full": "revocation-state-full",
	"too-large": "too-large",
} as const;

/**
 * An issuer's CRL, fetched once for every check waiting on it, verified with the issuer's key and
 * kept until its next update, fetched again after `crlTtlMs` or near its next update in a place of its
 * own, the one kept answering meanwhile. A fetch that failed is remembered `failureMs`; one cut short
 * by the check that started it is not, and those waiting fetch again once, where time is left.
 */
export function crlsOver(kept: Kept, fetching: Fetching) {
	const running = new Map<string, Promise<VerifiedCrl | Unconfirmed | "aborted">>();
	const failed = new Map<string, { readonly reason: Unconfirmed; readonly until: number }>();
	const fetchedAt = new Map<string, number>();

	async function fetched(
		key: string,
		issuer: Certificate,
		urls: readonly string[],
		signal: AbortSignal,
	): Promise<VerifiedCrl | Unconfirmed | "aborted"> {
		let reason: Unconfirmed = "unreachable";
		for (const url of urls) {
			const bytes = await fetching.fetch(url, signal);
			if (bytes === "aborted") return bytes;
			if (typeof bytes === "string") {
				reason = bytes;
				continue;
			}
			const read = await verifyCrl(
				bytes,
				issuer,
				fetching.now(),
				skewMs,
				signatureAlgorithms,
				signal,
			);
			// Ended while it was read: what the reading says is not this fetch's to remember.
			if (read.kind === "aborted" || signal.aborted) return "aborted";
			if (read.kind === "unusable") {
				reason = reasonOf(read.reason);
				continue;
			}
			const taken = kept.take(key, read.crl);
			if (taken === "kept" || taken === "same") {
				fetchedAt.set(key, fetching.now());
				failed.delete(key);
				return kept.crlOf(key) ?? read.crl;
			}
			reason = fromTaken[taken];
		}
		if (signal.aborted) return "aborted";
		failed.delete(key);
		if (failed.size >= mostFailures) failed.delete(failed.keys().next().value as string);
		failed.set(key, { reason, until: fetching.now() + fetching.failureMs });
		return reason;
	}

	const started = (
		key: string,
		issuer: Certificate,
		urls: readonly string[],
		signal: AbortSignal,
	) => {
		const run = fetched(key, issuer, urls, signal).finally(() => running.delete(key));
		running.set(key, run);
		return run;
	};

	function refreshIfDue(
		key: string,
		issuer: Certificate,
		urls: readonly string[],
		crl: VerifiedCrl,
		now: number,
	) {
		// A failure remembered holds a refresh back as it holds a fetch.
		const failure = failed.get(key);
		if (failure && now < failure.until) return;
		const margin = Math.max((crl.nextUpdate - crl.thisUpdate) / 10, 60_000);
		const due =
			now - (fetchedAt.get(key) ?? 0) >= fetching.crlTtlMs || now >= crl.nextUpdate - margin;
		if (due && !running.has(key)) {
			fetching.inBackground((signal) =>
				running.has(key) ? Promise.resolve() : started(key, issuer, urls, signal),
			);
		}
	}

	const whileAwaited = <T>(run: Promise<T>, signal: AbortSignal) => {
		let ended = () => {};
		const aborted = new Promise<"aborted">((end) => {
			ended = () => end("aborted");
			if (signal.aborted) ended();
			signal.addEventListener("abort", ended, { once: true });
		});
		return Promise.race([run, aborted]).finally(() => signal.removeEventListener("abort", ended));
	};

	return {
		/** The issuer's CRL for a check under `signal`, or why it is unconfirmed. */
		async crlFor(
			key: string,
			issuer: Certificate,
			urls: readonly string[],
			signal: AbortSignal,
		): Promise<VerifiedCrl | Unconfirmed> {
			for (let tries = 0; tries < 2; tries++) {
				const now = fetching.now();
				const crl = kept.crlOf(key);
				if (crl && now < crl.nextUpdate) {
					refreshIfDue(key, issuer, urls, crl, now);
					return crl;
				}
				const failure = failed.get(key);
				if (failure && now < failure.until) return failure.reason;
				const got = await whileAwaited(
					running.get(key) ?? started(key, issuer, urls, signal),
					signal,
				);
				if (got !== "aborted") return got;
				if (signal.aborted) return "unreachable";
			}
			return "unreachable";
		},
	};
}
