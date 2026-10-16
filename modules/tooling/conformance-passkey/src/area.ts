import { area } from "@mod/conformance";

/** Passkeys registered from a session, and logging in with them, for one relying party. */
export interface PasskeyPart {
	/** The relying party's domain. */
	readonly rpId: string;
	/** The origins ceremonies may come from. */
	readonly origins: readonly string[];
	/** The pages that may frame a ceremony; none when left out. */
	readonly topOrigins?: readonly string[];
	/** Whether a ceremony needs a verified user; the target's default when left out. */
	readonly userVerification?: "required" | "preferred" | "discouraged";
	/** How long a challenge may be answered; the target's default when left out. */
	readonly challengeSeconds?: number;
	/** How many passkeys one user may hold; the target's default when left out. */
	readonly maxCredentials?: number;
	/** Logging in with a passkey at the token endpoint, and how many options requests a source may make. */
	readonly login?: { readonly requests: number; readonly windowSeconds: number };
	/** WebAuthn as a second factor, beside the second-factor area's, for the same relying party. */
	readonly secondFactor?: boolean;
}

export const passkeyArea = area<PasskeyPart>("passkey");
