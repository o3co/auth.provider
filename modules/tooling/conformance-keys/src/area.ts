import { area } from "@mod/conformance";

export type SigningScene =
	| {
			readonly kid: string;
			readonly alg: "EdDSA" | "ES256" | "RS256";
			readonly privatePem: string;
			readonly publicPem: string;
	  }
	| { readonly kid: string; readonly alg: "HS256"; readonly secretHex: string };

export interface PreviousKeyScene {
	readonly kid: string;
	readonly alg: "EdDSA" | "ES256" | "RS256";
	readonly publicPem: string;
	readonly expiresAt: string;
}

/** The keys a deployment signs with, and the earlier ones it still publishes. */
export interface KeysPart {
	readonly signing?: SigningScene;
	readonly previous?: readonly PreviousKeyScene[];
	/** A setting the key section does not know, where a scene is about refusing one. */
	readonly unknownSetting?: boolean;
}

export const keysArea = area<KeysPart>("keys");
