import { contract } from "@mod/kernel";

export type VerifyResult =
	| { readonly kind: "valid"; readonly claims: Readonly<Record<string, unknown>> }
	| {
			readonly kind: "invalid";
			readonly reason: "malformed" | "typ" | "kid_unknown" | "kid_expired" | "signature";
	  };

export interface Keys {
	/** True when signatures can be checked with a public key; false for a shared secret. */
	asymmetric(): boolean;
	/** The JWS `alg` signatures are made with (the current signing key's). */
	algorithm(): string;
	/** The path on `http`'s origin the public key set is published at. */
	keySetPath(): string;
	sign(claims: Readonly<Record<string, unknown>>, typ: string): Promise<string>;
	verify(token: string, typ: string): Promise<VerifyResult>;
}

export const keys = contract<Keys>("keys");

/** Signs and verifies access tokens (`at+jwt`) with the ring `keys` signs with. */
export interface AccessTokenSigning {
	sign(claims: Readonly<Record<string, unknown>>): Promise<string>;
	verify(token: string): Promise<VerifyResult>;
}

/** Taken by `tokens` alone, so no other module of a composition signs or verifies an access token. */
export const accessTokenSigning = contract<AccessTokenSigning>("keys.access-signing", {
	takenBy: ["tokens"],
});

export { isCanonicalJws } from "./material/jws.ts";
export {
	isVerifyAlgorithm,
	type Jwk,
	publicJwk,
	publicMembers,
	publicPem,
	thumbprint,
	type VerifyAlgorithm,
	verifiesUnder,
	verifyAlgorithms,
} from "./material/public.ts";
export { bearerToken, secretBytes } from "./secret/secret.ts";
