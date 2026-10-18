import type { KeySource } from "@mod/external-jwt";
import type { Kind } from "./section.ts";

/** Who issues a kind's id_tokens: the `iss` values it signs under, and where its keys are. */
export interface Issuer {
	/** The first is the issuer users is told and the answer names. */
	readonly iss: readonly [string, ...string[]];
	readonly keys: KeySource;
}
export type Issuers = Readonly<Record<Kind, Issuer>>;

/** Fixed by the kind, never a setting: only the testing module builds with others. */
export const fixedIssuers: Issuers = Object.freeze({
	apple: {
		iss: ["https://appleid.apple.com"],
		keys: { jwks: { url: "https://appleid.apple.com/auth/keys", hosts: ["appleid.apple.com"] } },
	},
	google: {
		iss: ["https://accounts.google.com", "accounts.google.com"],
		keys: {
			jwks: { url: "https://www.googleapis.com/oauth2/v3/certs", hosts: ["www.googleapis.com"] },
		},
	},
});
