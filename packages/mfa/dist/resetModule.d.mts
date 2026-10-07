import { type MfaReset } from "./reset.mjs";
declare module "@o3co/auth-provider-core" {
    interface ComponentMap {
        /** The operator reset: `resetMfaForSubject`, from `@o3co/auth-provider-mfa`'s `mfaResetModule`. */
        readonly mfaReset?: MfaReset;
    }
}
/** The operator reset's module (see this file's header). */
export declare const mfaResetModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=resetModule.d.mts.map