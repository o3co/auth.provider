import type { DocumentCopy } from "@mod/client-documents";
import type { Section } from "@mod/clients";
import { z } from "zod";

/** OpenID Discovery 1.0 §3: the algorithm `id_token_signing_alg_values_supported` must include. */
export const requiredAlg = "RS256";

/** What a client registers of its ID tokens. */
export interface ClientIdTokens {
	readonly "id-token-alg"?: string | undefined;
}

/**
 * The client section, under the algorithm ID tokens are signed with: a client naming another is
 * refused by its schema, so at boot for a registered one and when a source's record is read for
 * any other, by `clients`' refusals.
 */
export function clientSectionOf(alg: string): Section<ClientIdTokens> {
	return {
		name: "oidc",
		schema: z.strictObject({
			"id-token-alg": z
				.string()
				.refine((named) => named === alg, "ID tokens are signed with oidc.id-token-alg alone")
				.optional()
				.describe(
					"The JWS algorithm the client's ID tokens are signed with (`id_token_signed_response_alg`): the one `keys` signs with, the default; another is refused.",
				),
		}),
	};
}

/** The section's copy from a client's metadata document, for `client-documents`' `documentCopies`. */
export const clientCopyOf = (section: Section<ClientIdTokens>): DocumentCopy => ({
	section,
	reads: ["id_token_signed_response_alg"],
	copy: (document) => {
		const alg = document.id_token_signed_response_alg;
		return alg === undefined ? undefined : { value: { "id-token-alg": alg } };
	},
});
