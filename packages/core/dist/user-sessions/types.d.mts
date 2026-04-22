import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";
/**
 * OIDC-standard user claims durably attached to a session. Populated at login.
 * Used as the authoritative source for /userinfo and id_token; independent of
 * the browser session.
 */
export interface UserSessionClaims {
    readonly email?: string;
    readonly emailVerified?: boolean;
    readonly name?: string;
    readonly picture?: string;
    readonly groups?: ReadonlyArray<string>;
    readonly [customClaim: string]: unknown;
}
export interface RegisteredRP {
    readonly clientId: string;
    readonly backchannelLogoutUri?: string;
    readonly backchannelLogoutSessionRequired?: boolean;
    readonly frontchannelLogoutUri?: string;
    readonly frontchannelLogoutSessionRequired?: boolean;
    readonly registeredAt: Date;
}
export interface UserSession {
    readonly sid: string;
    readonly sub: string;
    readonly authTime: Date;
    readonly createdAt: Date;
    readonly expiresAt: Date;
    readonly federations: ReadonlyArray<string>;
    readonly activeRPs: ReadonlyArray<RegisteredRP>;
    readonly familyIds: ReadonlyArray<string>;
    readonly claims: UserSessionClaims;
}
/**
 * Parameters for creating a new session. createdAt / activeRPs / familyIds
 * are initialized by the store (not caller-supplied).
 */
export interface CreateUserSessionInput {
    readonly sid: string;
    readonly sub: string;
    readonly authTime: Date;
    readonly expiresAt: Date;
    readonly federations?: ReadonlyArray<string>;
    readonly claims: UserSessionClaims;
}
export interface UserSessionStoreBase {
    readonly kind: string;
    create(input: CreateUserSessionInput): Promise<void>;
    get(sid: string): Promise<UserSession | null>;
    registerRP(sid: string, rp: RegisteredRP): Promise<void>;
    linkFamily(sid: string, familyId: string): Promise<void>;
    updateClaims(sid: string, claims: Partial<UserSessionClaims>): Promise<void>;
    removeFederation(sid: string, federationName: string): Promise<void>;
    /**
     * Delete the session record. MUST NOT cascade to other stores — cascade is
     * orchestrated by the logout route handler (see spec Section 14.2).
     */
    delete(sid: string): Promise<void>;
}
export type UserSessionStoreFactory = AdapterFactory<UserSessionStoreBase>;
//# sourceMappingURL=types.d.mts.map