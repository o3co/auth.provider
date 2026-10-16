import type * as pkijs from "pkijs";
import type { Fetched, PathPolicy, RevocationPolicy, Sources } from "../contract.ts";
import { crlUrlsOf, type Judged, judgeCrl } from "./crl.ts";
import { type Answer, judgeOcsp, ocspRequestOf, ocspUrlsOf } from "./ocsp.ts";

type Failed = { readonly kind: "refused" | "outage"; readonly reason: string };

/** Only an outage is left to the caller's policy; anything else not good refuses. */
export type Status = { readonly kind: "good" } | { readonly kind: "revoked" } | Failed;
/** A status as a source says it, a revocation telling whether it is on hold. */
type Said =
	| { readonly kind: "good" }
	| { readonly kind: "revoked"; readonly held: boolean }
	| Failed;

const good = { kind: "good" } as const;
const isFailed = (x: { readonly kind: string }): x is Failed =>
	x.kind === "refused" || x.kind === "outage";
const refused = (reason: string): Failed => ({ kind: "refused", reason });
const outage = (reason: string): Failed => ({ kind: "outage", reason });
/** The failure to report: a refusal outweighs an outage; otherwise the first found stands. */
const worse = (a: Failed | undefined, b: Failed) =>
	!a || (a.kind === "outage" && b.kind === "refused") ? b : a;
const failedOf = (fetched: Exclude<Fetched, { kind: "material" }>) =>
	fetched.kind === "refused" ? refused("source refused") : outage("unreachable");
const limited = outage("fetch limit");

/** One check's fetches, within its limit; none past it, and nothing remembered for those. */
type Fetch = (url: string, body?: Uint8Array) => Promise<Fetched | undefined>;

type Entry<T> = { readonly value: T; readonly until: number };

/** At most `size` entries, each until its time, the oldest going first. */
function expiring<T>(size: number, now: () => number) {
	const entries = new Map<string, Entry<T>>();
	return {
		get: (key: string) => {
			const entry = entries.get(key);
			if (!entry || entry.until > now()) return entry;
			entries.delete(key);
			return undefined;
		},
		set: (key: string, value: T, until: number) => {
			if (entries.size >= size) entries.delete(entries.keys().next().value as string);
			entries.set(key, { value, until });
		},
	};
}

type KeptAnswer = Omit<Extract<Answer, { until: number }>, "until">;

const hex = (bytes: Uint8Array) =>
	Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

/** A certificate by its issuer's name and key, as the certificate names it, and its serial. */
const keyOf = (cert: pkijs.Certificate, issuer: pkijs.Certificate) =>
	[
		new Uint8Array(cert.issuer.toSchema().toBER(false)),
		issuer.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView,
		cert.serialNumber.valueBlock.valueHexView,
	]
		.map(hex)
		.join(":");

/**
 * Checks the certificates of a path, the anchor aside, against the sources the policy names; a
 * delegated OCSP responder is held to the path's RSA bits.
 */
export function revocationOver(
	policy: RevocationPolicy & Pick<PathPolicy, "minRsaBits">,
	sources: Sources,
) {
	const crls = expiring<Uint8Array | Failed>(policy.crlEntries, sources.now);
	const answers = expiring<KeptAnswer | Failed>(policy.ocspEntries, sources.now);
	// Only a hold is ever lifted, so any other revocation stands after what said it ends.
	const revoked = expiring<true>(policy.ocspEntries, sources.now);
	// One lookup of a key at a time, so none overwrites what another kept; a caller waits, then looks again.
	const running = new Map<string, Promise<unknown>>();
	async function alone<T>(key: string, look: () => Promise<T>): Promise<T> {
		let other = running.get(key);
		// Lookups report failures as values, so a rejection here is a bug and is passed on as it is.
		while (other) {
			await other;
			other = running.get(key);
		}
		const mine = look();
		running.set(key, mine);
		try {
			return await mine;
		} finally {
			running.delete(key);
		}
	}

	const crlSays = (url: string, cert: pkijs.Certificate, issuer: pkijs.Certificate, fetch: Fetch) =>
		alone(`crl ${url}`, () => crlLooked(url, cert, issuer, fetch));
	async function crlLooked(
		url: string,
		cert: pkijs.Certificate,
		issuer: pkijs.Certificate,
		fetch: Fetch,
	): Promise<Said> {
		const now = sources.now();
		const entry = crls.get(url);
		if (entry) {
			if (!(entry.value instanceof Uint8Array)) return entry.value;
			const judged = await judgeCrl(entry.value, cert, issuer, now, policy.skewMs);
			return judged.kind === "unusable" ? refused(judged.reason) : saidOf(judged);
		}
		const fetched = await fetch(url);
		if (!fetched) return limited;
		if (fetched.kind !== "material") {
			const failed = failedOf(fetched);
			crls.set(url, failed, now + policy.failureMs);
			return failed;
		}
		const judged = await judgeCrl(fetched.body, cert, issuer, now, policy.skewMs);
		if (judged.kind === "unusable") {
			crls.set(url, refused(judged.reason), now + policy.failureMs);
			return refused(judged.reason);
		}
		crls.set(url, fetched.body, Math.min(judged.until, now + policy.crlTtlMs));
		return saidOf(judged);
	}

	const saidOf = (judged: Exclude<Judged, { kind: "unusable" }>): Said =>
		judged.kind === "revoked" ? { kind: "revoked", held: judged.held } : good;

	async function byCrl(
		cert: pkijs.Certificate,
		issuer: pkijs.Certificate,
		fetch: Fetch,
	): Promise<Said> {
		const urls = crlUrlsOf(cert);
		if (urls.length === 0) return refused("no source");
		let failed: Failed | undefined;
		for (const url of urls) {
			const said = await crlSays(url, cert, issuer, fetch);
			if (!isFailed(said)) return said;
			failed = worse(failed, said);
		}
		return failed ?? refused("no source");
	}

	async function answerFor(
		cert: pkijs.Certificate,
		issuer: pkijs.Certificate,
		fetch: Fetch,
	): Promise<KeptAnswer | Failed> {
		const key = keyOf(cert, issuer);
		return alone(`ocsp ${key}`, () => answerLooked(key, cert, issuer, fetch));
	}

	async function answerLooked(
		key: string,
		cert: pkijs.Certificate,
		issuer: pkijs.Certificate,
		fetch: Fetch,
	): Promise<KeptAnswer | Failed> {
		const entry = answers.get(key);
		if (entry) return entry.value;
		const urls = ocspUrlsOf(cert);
		if (urls.length === 0) return refused("no source");
		let failed: Failed | undefined;
		for (const url of urls) {
			const now = sources.now();
			const nonce = policy.nonce ? sources.random(16) : undefined;
			const fetched = await fetch(url, await ocspRequestOf(cert, issuer, nonce));
			// What already failed stands, a refusal above all; the limit is only an outage.
			if (!fetched) return failed ?? limited;
			if (fetched.kind !== "material") {
				failed = worse(failed, failedOf(fetched));
				continue;
			}
			const answer = await judgeOcsp(fetched.body, cert, issuer, {
				now,
				skewMs: policy.skewMs,
				freshMs: policy.ocspFreshMs,
				minRsaBits: policy.minRsaBits,
				...(nonce ? { nonce } : {}),
			});
			if (answer.kind === "busy") {
				failed = worse(failed, outage("busy"));
				continue;
			}
			if (answer.kind === "unusable") {
				failed = worse(failed, refused(answer.reason));
				continue;
			}
			const { until, ...said } = answer;
			answers.set(key, said, until);
			return said;
		}
		const last = failed ?? refused("no source");
		answers.set(key, last, sources.now() + policy.failureMs);
		return last;
	}

	async function byOcsp(
		cert: pkijs.Certificate,
		issuer: pkijs.Certificate,
		fetch: Fetch,
	): Promise<Said | { readonly kind: "unknown" }> {
		const answer = await answerFor(cert, issuer, fetch);
		if (isFailed(answer)) return answer;
		// Revoked and unknown stand as they are; only good needs its signer trusted.
		if (answer.kind === "revoked") return { kind: "revoked", held: answer.held ?? false };
		if (answer.kind === "unknown") return { kind: "unknown" };
		// A responder the issuer delegated to is taken only once its own revocation is checked.
		if (answer.responder) {
			if (policy.mode !== "both") return refused("responder");
			const checked = await byCrl(answer.responder, issuer, fetch);
			if (checked.kind === "outage") return checked;
			if (checked.kind !== "good") return refused("responder");
		}
		return good;
	}

	async function statusOf(
		cert: pkijs.Certificate,
		issuer: pkijs.Certificate,
		fetch: Fetch,
	): Promise<Status> {
		const key = keyOf(cert, issuer);
		if (revoked.get(key)) return { kind: "revoked" };
		const said = await asked(cert, issuer, fetch);
		if (said.kind !== "revoked") return said;
		if (!said.held) revoked.set(key, true, Number.POSITIVE_INFINITY);
		return { kind: "revoked" };
	}

	async function asked(
		cert: pkijs.Certificate,
		issuer: pkijs.Certificate,
		fetch: Fetch,
	): Promise<Said> {
		if (policy.mode === "crl") return byCrl(cert, issuer, fetch);
		const asked = await byOcsp(cert, issuer, fetch);
		if (asked.kind === "unknown") {
			// The CRL may only add a revocation to an unknown.
			const listed = policy.mode === "both" ? await byCrl(cert, issuer, fetch) : undefined;
			return listed?.kind === "revoked" ? listed : refused("unknown");
		}
		if (policy.mode === "ocsp" || !isFailed(asked)) return asked;
		const listed = await byCrl(cert, issuer, fetch);
		if (listed.kind === "revoked") return listed;
		return isFailed(listed) ? worse(asked, listed) : listed;
	}

	return {
		/** Revoked as soon as one is; otherwise a refusal before an outage, or good. */
		check: async (path: readonly pkijs.Certificate[]): Promise<Status> => {
			let left = policy.maxFetches;
			const fetch: Fetch = async (url, body) => {
				if (left === 0) return undefined;
				left -= 1;
				return sources.fetch(url, body);
			};
			let failed: Failed | undefined;
			for (let at = 0; at + 1 < path.length; at++) {
				const status = await statusOf(
					path[at] as pkijs.Certificate,
					path[at + 1] as pkijs.Certificate,
					fetch,
				);
				if (status.kind === "revoked") return status;
				if (isFailed(status)) failed = worse(failed, status);
			}
			return failed ?? good;
		},
	};
}
