import { createHash } from "node:crypto";
import { crlSays, pathOf, type Trust } from "@mod/x509-path";
import { crlsOver, type Fetching, reasonOf, type Unconfirmed } from "./fetching/fetching.ts";
import { keptOver } from "./kept/kept.ts";
import { pointsOf } from "./points.ts";
import { type Certificate, peerRules } from "./trust.ts";

export type { Fetched, Fetching, Unconfirmed } from "./fetching/fetching.ts";
export { storeTrust } from "./trust.ts";

/** What a peer's revocation is: none known on the path checked, revoked, or unconfirmed and why. */
export type Verdict =
	| { readonly kind: "good" }
	| { readonly kind: "revoked" }
	| { readonly kind: "unconfirmed"; readonly reason: Unconfirmed };

const good: Verdict = { kind: "good" };
const revoked: Verdict = { kind: "revoked" };
const unconfirmed = (reason: Unconfirmed): Verdict => ({ kind: "unconfirmed", reason });

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");

/** An issuer as its CRLs are kept: its name's DER and its key's SHA-256. */
const issuerKeyOf = (issuer: Certificate) =>
	`${hex(new Uint8Array(issuer.subject.toSchema().toBER(false)))} ${createHash("sha256")
		.update(new Uint8Array(issuer.subjectPublicKeyInfo.toSchema().toBER(false)))
		.digest("hex")}`;

/**
 * Checks a peer's revocation: the one path `x509-path` chooses from what the peer sent toward the
 * trust, under outbound's rules, then every certificate on it but the anchor by its issuer's CRL,
 * fetched from the hosts listed.
 */
export function revocationOver(given: {
	readonly trust: Trust;
	readonly hosts: readonly string[];
	readonly crlEntries: number;
	readonly fetching: Fetching;
}) {
	const kept = keptOver(given.crlEntries);
	const crls = crlsOver(kept, given.fetching);

	async function certificateVerdict(
		cert: Certificate,
		issuer: Certificate,
		signal: AbortSignal,
	): Promise<Verdict> {
		const points = pointsOf(cert, given.hosts);
		if (points.kind === "none") return good;
		if (points.kind === "unconfirmed") return unconfirmed(points.reason);
		const key = issuerKeyOf(issuer);
		const serial = hex(cert.serialNumber.valueBlock.valueHexView);
		if (kept.isRevoked(key, serial)) return revoked;
		const crl = await crls.crlFor(key, issuer, points.urls, signal);
		if (typeof crl === "string") return unconfirmed(crl);
		const judged = crlSays(crl, cert, issuer, given.fetching.now());
		switch (judged.kind) {
			case "good":
				return kept.isUnrecorded(key) ? unconfirmed("revocation-state-full") : good;
			case "revoked":
				if (!judged.held) kept.recordRevoked(key, serial);
				return revoked;
			case "unusable":
				return unconfirmed(reasonOf(judged.reason));
		}
	}

	return {
		/** The peer's leaf and the rest of what it sent, checked under `signal`. */
		async check(
			leaf: Uint8Array,
			sent: readonly Uint8Array[],
			signal: AbortSignal,
		): Promise<Verdict> {
			const built = await pathOf(leaf, sent, given.trust, peerRules, given.fetching.now());
			if (built.kind === "invalid") return unconfirmed("path");
			let verdict = good;
			for (const [at, cert] of built.path.slice(0, -1).entries()) {
				const one = await certificateVerdict(cert, built.path[at + 1] as Certificate, signal);
				if (one.kind === "revoked") return one;
				if (verdict.kind === "good") verdict = one;
			}
			return verdict;
		},
	};
}
