import { type MfaFactor } from "@o3co/auth-provider-core";
import { type TotpAlgorithm } from "./rfc6238.mjs";
/** The kind a TOTP factor's records carry, and the key it is contributed under. */
export declare const TOTP_FACTOR_KIND = "totp";
/** What the factor is built with: the parameters of a new enrollment, the window every verification allows, and the URI's issuer. */
export interface TotpFactorSettings {
    readonly algorithm: TotpAlgorithm;
    readonly digits: number;
    /** Seconds per step. */
    readonly period: number;
    /** Steps accepted either side of now. */
    readonly window: number;
    /** The `otpauth://` URI's issuer, and the first half of its label. */
    readonly issuer: string;
}
/** The `totp` factor, with `settings` for new enrollments and the window. */
export declare function createTotpFactor(settings: TotpFactorSettings): MfaFactor;
//# sourceMappingURL=factor.d.mts.map