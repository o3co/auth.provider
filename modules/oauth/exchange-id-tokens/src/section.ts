import { algorithmsSetting, knownAlgorithms } from "@mod/external-jwt";
import { setting } from "@mod/kernel";
import { z } from "zod";

/** The longest `max-age` and `clock-skew` any section may give, in seconds: records are kept by these, never by the section. */
export const longestMaxAge = 3600;
export const longestClockSkew = 300;

/** The kinds of id_token taken, each with its issuer fixed. */
export const kinds = ["apple", "google"] as const;
export type Kind = (typeof kinds)[number];

/** What one client of this provider takes: an id_token for one of its audiences, from one of its parties. */
const client = z.strictObject({
	audiences: z
		.array(z.string().min(1))
		.min(1)
		.describe("The id_token audiences (`aud`) this client takes, the app's client IDs upstream."),
	"authorized-parties": z
		.array(z.string().min(1))
		.prefault([])
		.describe(
			"The authorized parties (`azp`) taken; none listed takes an id_token without `azp`, or with `azp` its `aud`.",
		),
});
export type ClientEntry = z.output<typeof client>;

const upstream = (name: Kind) =>
	z
		.strictObject({
			upstream: z
				.string()
				.min(1)
				.prefault(name)
				.describe(
					"The upstream's name, by which users finds the account an id_token's `sub` is linked to.",
				),
			clients: z
				.record(z.string().min(1), client)
				.refine((map) => Object.keys(map).length > 0, "names at least one client")
				.describe("This provider's client IDs, each with the id_tokens it may exchange."),
			algorithms: algorithmsSetting(knownAlgorithms, ["RS256"]).describe(
				`The algorithms ${name === "apple" ? "Apple's" : "Google's"} id_tokens may be signed with: asymmetric ones only, RS256 by default.`,
			),
		})
		.optional()
		.describe(`Takes ${name === "apple" ? "Apple's" : "Google's"} id_tokens when written.`);

/** The (aud, azp) pairs a client takes; an absent `azp` is written as the empty string. */
export const pairsOf = (entry: ClientEntry): readonly string[] =>
	entry.audiences.flatMap((aud) =>
		(entry["authorized-parties"].length === 0 ? ["", aud] : entry["authorized-parties"]).map(
			(azp) => JSON.stringify([aud, azp]),
		),
	);

export const section = z
	.strictObject({
		"max-age": setting
			.duration("s")
			.pipe(z.number().int().min(60).max(longestMaxAge))
			.prefault("10m")
			.describe("The oldest an id_token may be, from its `iat`, from 1m to 1h."),
		"clock-skew": setting
			.duration("s")
			.pipe(z.number().int().min(0).max(longestClockSkew))
			.prefault("30s")
			.describe(
				"How far an id_token's times may be off this host's clock, from 0s to 5m. Set it no lower than your issuers' real clock drift: narrowing it can admit an id_token a wider skew refused at a revocation.",
			),
		apple: upstream("apple"),
		google: upstream("google"),
	})
	.superRefine((s, ctx) => {
		if (kinds.every((kind) => s[kind] === undefined)) {
			ctx.addIssue({ code: "custom", message: `needs one of ${kinds.join(", ")}` });
		}
		for (const kind of kinds) {
			const taken = new Map<string, string>();
			for (const [id, entry] of Object.entries(s[kind]?.clients ?? {})) {
				for (const pair of pairsOf(entry)) {
					const first = taken.get(pair);
					if (first !== undefined && first !== id) {
						ctx.addIssue({
							code: "custom",
							path: [kind, "clients", id],
							// The other client by its key path, as the refusal names this one.
							message: `takes an (aud, azp) pair that exchange-id-tokens.${kind}.clients.${first} takes too; one app's id_token is one client's`,
						});
						break;
					}
					taken.set(pair, id);
				}
			}
		}
	});
export type Settings = z.output<typeof section>;
