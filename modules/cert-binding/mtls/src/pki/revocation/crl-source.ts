import {
	crlSays,
	distributionPointsOf,
	type Judged,
	type VerifiedCrl,
	verifyCrl,
} from "@mod/x509-path";
import type * as pkijs from "pkijs";
import type { PathPolicy, RevocationPolicy, Sources } from "../contract.ts";
import type { Alone, Expiring } from "./kept.ts";
import {
	type Failed,
	type Fetch,
	failedOf,
	good,
	isFailed,
	limited,
	outage,
	refused,
	type Said,
	worse,
} from "./outcome.ts";

/** A CRL verified once, as it was fetched, by its issuer's key; judged again for each certificate. */
export type KeptCrl = VerifiedCrl | Failed;

/** The serials kept CRLs list at most, together: measured some 46 to 60 MiB at the full budget. */
export const mostKeptSerials = 1 << 19;

/** How much a kept CRL weighs against `mostKeptSerials`: the serials it lists. */
export const serialsIn = (kept: KeptCrl) => ("listed" in kept ? kept.listed.size : 0);

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");
/** The most bytes an issuer's name may take, keyed by: a CRL naming a longer one is refused anyway. */
const mostNameBytes = 4096;

/** A CRL kept by where it came from and the issuer whose key verified it: another's is never taken for it. */
const keptAs = (url: string, issuer: pkijs.Certificate) =>
	`${url} ${hex(new Uint8Array(issuer.subject.toSchema().toBER(false)))} ${hex(
		issuer.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView,
	)}`;

/** Where a certificate's CRL is: its usable points' URLs; none where it names none, or they are unreadable. */
const crlUrlsOf = (cert: pkijs.Certificate) => {
	const points = distributionPointsOf(cert);
	return points.kind === "points" ? points.urls : [];
};

const saidOf = (judged: Exclude<Judged, { kind: "unusable" }>): Said =>
	judged.kind === "revoked" ? { kind: "revoked", held: judged.held } : good;

/** What a certificate's CRLs say, each CRL kept by its location. */
export function crlSource(
	policy: RevocationPolicy & Pick<PathPolicy, "signatureAlgorithms">,
	sources: Sources,
	crls: Expiring<KeptCrl>,
	alone: Alone,
) {
	const lookedAlone = (
		url: string,
		cert: pkijs.Certificate,
		issuer: pkijs.Certificate,
		fetch: Fetch,
	) => alone(`crl ${url}`, () => crlLooked(url, cert, issuer, fetch));
	async function crlLooked(
		url: string,
		cert: pkijs.Certificate,
		issuer: pkijs.Certificate,
		fetch: Fetch,
	): Promise<Said> {
		const now = sources.now();
		const key = keptAs(url, issuer);
		const entry = crls.get(key);
		if (entry) {
			if (!("listed" in entry.value)) return entry.value;
			const judged = crlSays(entry.value, cert, issuer, now);
			return judged.kind === "unusable" ? refused(judged.reason) : saidOf(judged);
		}
		const fetched = await fetch(url);
		if (!fetched) return limited;
		if (fetched.kind !== "material") {
			const failed = failedOf(fetched);
			crls.set(key, failed, now + policy.failureMs);
			return failed;
		}
		const verified = await verifyCrl(
			fetched.body,
			issuer,
			now,
			policy.skewMs,
			policy.signatureAlgorithms,
			AbortSignal.timeout(policy.timeoutMs),
		);
		// No turn to read it within a fetch's time: an outage as a fetch past its time is, and nothing
		// of the CRL is remembered, as it was never read.
		if (verified.kind === "aborted") return outage("unreachable");
		if (verified.kind === "unusable") {
			crls.set(key, refused(verified.reason), now + policy.failureMs);
			return refused(verified.reason);
		}
		const judged = crlSays(verified.crl, cert, issuer, now);
		if (judged.kind === "unusable") {
			crls.set(key, refused(judged.reason), now + policy.failureMs);
			return refused(judged.reason);
		}
		crls.set(key, verified.crl, Math.min(judged.until, now + policy.crlTtlMs));
		return saidOf(judged);
	}

	return async function byCrl(
		cert: pkijs.Certificate,
		issuer: pkijs.Certificate,
		fetch: Fetch,
	): Promise<Said> {
		// The issuer's name keys what is kept: one past the bound is refused, never kept.
		if (issuer.subject.toSchema().toBER(false).byteLength > mostNameBytes) {
			return refused("malformed");
		}
		const urls = crlUrlsOf(cert);
		if (urls.length === 0) return refused("no source");
		let failed: Failed | undefined;
		for (const url of urls) {
			const said = await lookedAlone(url, cert, issuer, fetch);
			if (!isFailed(said)) return said;
			failed = worse(failed, said);
		}
		return failed ?? refused("no source");
	};
}
