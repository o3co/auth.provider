import type * as pkijs from "pkijs";
import type { PathPolicy, RevocationPolicy, Sources } from "../contract.ts";
import { type Alone, type Expiring, keyOf } from "./kept.ts";
import { type Answer, judgeOcsp, ocspRequestOf, ocspUrlsOf } from "./ocsp.ts";
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

export type KeptAnswer = Omit<Extract<Answer, { until: number }>, "until">;

type ByCrl = (cert: pkijs.Certificate, issuer: pkijs.Certificate, fetch: Fetch) => Promise<Said>;

/** What a certificate's OCSP responders answer, each answer kept by the certificate's key. */
export function ocspSource(
	policy: RevocationPolicy & Pick<PathPolicy, "minRsaBits">,
	sources: Sources,
	answers: Expiring<KeptAnswer | Failed>,
	alone: Alone,
	byCrl: ByCrl,
) {
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

	return async function byOcsp(
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
	};
}
