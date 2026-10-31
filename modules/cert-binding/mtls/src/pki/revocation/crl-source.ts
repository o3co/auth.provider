import type * as pkijs from "pkijs";
import type { RevocationPolicy, Sources } from "../contract.ts";
import { crlUrlsOf, type Judged, judgeCrl } from "./crl.ts";
import type { Alone, Expiring } from "./kept.ts";
import {
	type Failed,
	type Fetch,
	failedOf,
	good,
	isFailed,
	limited,
	refused,
	type Said,
	worse,
} from "./outcome.ts";

const saidOf = (judged: Exclude<Judged, { kind: "unusable" }>): Said =>
	judged.kind === "revoked" ? { kind: "revoked", held: judged.held } : good;

/** What a certificate's CRLs say, each CRL kept by its location. */
export function crlSource(
	policy: RevocationPolicy,
	sources: Sources,
	crls: Expiring<Uint8Array | Failed>,
	alone: Alone,
) {
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

	return async function byCrl(
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
	};
}
