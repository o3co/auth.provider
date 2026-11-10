import type { VerifiedCrl } from "@mod/x509-path";

/** The serials kept CRLs list at most, together: some 47 B each as x509-path keeps them. */
const mostSerials = 1 << 20;
/** The issuers whose high-water mark is kept, and the revocations seen: never evicted. */
const mostMarks = 4096;
const mostRevoked = 4096;

/** The highest CRL an issuer was seen to sign, and whether a revocation of it went unrecorded. */
interface Mark {
	number?: bigint;
	thisUpdate: number;
	unrecorded: boolean;
}

/** Whether a CRL was taken: kept, the one kept already, or refused as a rollback or past a bound. */
export type Taken = "kept" | "same" | "rollback" | "state-full" | "too-large";

/**
 * What outbound keeps of revocation, by issuer (its name's DER and key), in this process alone: CRLs
 * as verified, the oldest going first past `crlEntries` or the serials' budget; each issuer's
 * high-water mark, so an older CRL is never taken after a newer; and revocations other than a hold,
 * by issuer and serial, for certificates checked here. Marks and revocations are never evicted:
 * past their bounds, what they would keep is unconfirmed.
 */
export function keptOver(crlEntries: number) {
	const bodies = new Map<string, VerifiedCrl>();
	let serials = 0;
	const marks = new Map<string, Mark>();
	const revoked = new Set<string>();
	const drop = (issuer: string) => {
		serials -= bodies.get(issuer)?.listed.size ?? 0;
		bodies.delete(issuer);
	};
	const keep = (issuer: string, crl: VerifiedCrl) => {
		drop(issuer);
		while (bodies.size >= crlEntries || serials + crl.listed.size > mostSerials) {
			drop(bodies.keys().next().value as string);
		}
		bodies.set(issuer, crl);
		serials += crl.listed.size;
	};
	return {
		crlOf: (issuer: string) => bodies.get(issuer),
		/** Takes a verified CRL of `issuer`, held to its high-water mark. */
		take(issuer: string, crl: VerifiedCrl): Taken {
			if (crl.listed.size > mostSerials) return "too-large";
			const mark = marks.get(issuer);
			if (!mark) {
				if (marks.size >= mostMarks) return "state-full";
				marks.set(issuer, {
					...(crl.number === undefined ? {} : { number: crl.number }),
					thisUpdate: crl.thisUpdate,
					unrecorded: false,
				});
				keep(issuer, crl);
				return "kept";
			}
			if (crl.thisUpdate < mark.thisUpdate) return "rollback";
			if (mark.number !== undefined) {
				if (crl.number === undefined || crl.number < mark.number) return "rollback";
				if (crl.number === mark.number) {
					// The same CRL: the one kept stays; evicted, it is taken again, its next update its own.
					if (bodies.has(issuer)) return "same";
					keep(issuer, crl);
					return "kept";
				}
			}
			if (crl.number !== undefined) mark.number = crl.number;
			mark.thisUpdate = crl.thisUpdate;
			keep(issuer, crl);
			return "kept";
		},
		isRevoked: (issuer: string, serial: string) => revoked.has(`${issuer} ${serial}`),
		/** Records a revocation; past the bound, the issuer's good is no longer taken. */
		recordRevoked(issuer: string, serial: string) {
			const key = `${issuer} ${serial}`;
			if (revoked.has(key)) return;
			if (revoked.size < mostRevoked) {
				revoked.add(key);
				return;
			}
			const mark = marks.get(issuer);
			if (mark) mark.unrecorded = true;
		},
		/** Whether a revocation of the issuer's went unrecorded, so its good cannot be taken. */
		isUnrecorded: (issuer: string) => marks.get(issuer)?.unrecorded ?? false,
	};
}

export type Kept = ReturnType<typeof keptOver>;
