import { hostList } from "@mod/host-entries";
import { setting } from "@mod/kernel";
import { z } from "zod";

/** A time written with its unit, from `min` to `max` milliseconds. */
const time = (min: number, max: number, fallback: string) =>
	setting.duration("ms").pipe(z.number().int().min(min).max(max)).prefault(fallback);

/** The operator's section `outbound.revocation`: where CRLs are fetched from, and how many are kept how long. */
export const revocationSection = z
	.strictObject({
		hosts: hostList.describe(
			"The hosts a peer's CRL may be fetched from over plain http; `outbound.allow` and `deny` hold too. None: no peer's revocation is checked.",
		),
		"accept-unconfirmed": z
			.boolean()
			.prefault(false)
			.describe(
				"Whether a request goes to a peer whose revocation cannot be confirmed (a CRL unsigned as it should be among them), said at every start. A revoked peer is never taken, from 0.22.",
			),
		"crl-entries": z
			.number()
			.int()
			.min(1)
			.max(1024)
			.prefault(64)
			.describe("How many issuers' CRLs are kept, from 1 to 1,024."),
		"failure-lifetime": time(1000, 3_600_000, "30s").describe(
			"How long a CRL fetch that failed is remembered, its peers unconfirmed meanwhile, from 1s to 1h.",
		),
		"crl-ttl": time(1000, 86_400_000, "1h").describe(
			"How long after a fetch a CRL is fetched again, the one kept answering until its next update, from 1s to 1d.",
		),
	})
	.prefault({});

/** What the section leaves unchecked or accepts, said at every start, by a reason alone. */
export function startWarnings(
	section: z.output<typeof revocationSection>,
): readonly (readonly [event: string, fields: { readonly reason: string }])[] {
	return [
		...(section.hosts.length === 0
			? [
					[
						"outbound.revocation_unchecked",
						{ reason: "no CRL host is listed, so no peer's revocation is checked" },
					] as const,
				]
			: []),
		...(section["accept-unconfirmed"]
			? [
					[
						"outbound.revocation_unconfirmed_accepted",
						{ reason: "a request goes to a peer whose revocation cannot be confirmed" },
					] as const,
				]
			: []),
	];
}
