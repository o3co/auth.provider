import { type HeldUpstreamToken } from "../federations/token-lifetime.mjs";
import type { FederationGrantCredentials, FederationGrantCredentialsInput } from "./types.mjs";
/** A grant credential's access token, as a store answers it. */
export type StoredAccessToken = NonNullable<FederationGrantCredentials["accessToken"]>;
/** A grant credential's access token, as a writer hands it to a store. */
export type WrittenAccessToken = NonNullable<FederationGrantCredentialsInput["accessToken"]>;
/** The access token to store, from a finite reading that names its issued lifetime. */
export declare function federationGrantAccessToken(token: Pick<StoredAccessToken, "value" | "tokenType" | "scopes">, lifetime: {
    readonly obtainedAt: Date;
    readonly expiresAt: Date;
    readonly issuedLifetime: number;
}): WrittenAccessToken;
/**
 * The stored access token as a token held. A start, an end or a lifetime
 * that is no instant or no finite number reads as an Invalid Date, which
 * `judgeHeldUpstreamToken` does not believe: the token is refreshed.
 */
export declare function federationGrantHeldToken(token: Pick<StoredAccessToken, "obtainedAt" | "issuedLifetime" | "effectiveExpiresAt">): HeldUpstreamToken;
/**
 * A stored access token written back as it is: it states the end it is read
 * to have. Its fields are read by name, never spread, so a token a store
 * answers as a class instance whose fields are getters keeps them; its dates
 * are copies, so nothing the store holds is shared.
 */
export declare function federationGrantKeptAccessToken(token: StoredAccessToken): WrittenAccessToken;
//# sourceMappingURL=held-token.d.mts.map