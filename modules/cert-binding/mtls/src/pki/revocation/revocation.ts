import type * as pkijs from "pkijs";
import type { PathPolicy, RevocationPolicy, Sources } from "../contract.ts";
import { crlSource } from "./crl-source.ts";
import { expiring, keyOf, oneAtATime } from "./kept.ts";
import { type KeptAnswer, ocspSource } from "./ocsp-source.ts";
import {
	type Failed,
	type Fetch,
	good,
	isFailed,
	refused,
	type Said,
	type Status,
	worse,
} from "./outcome.ts";

export type { Status } from "./outcome.ts";

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
	const alone = oneAtATime();
	const byCrl = crlSource(policy, sources, crls, alone);
	const byOcsp = ocspSource(policy, sources, answers, alone, byCrl);

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
