/**
 * The actions the MFA package's routes admit a browser session for, with the
 * grade each is registered under: `mfa.manage` — enrolling a factor outside a
 * login, renaming or removing one, regenerating recovery codes — changes the
 * ways into the account, so it is a `credential_change`; `mfa.view` — listing
 * the subject's factors — reads them, so it is a `use`.
 *
 * Declared, and registered by no module: a module registers only what its
 * own code admits, and the module whose route admits a session contributes
 * these as its `admissionActions`.
 */
export declare const MFA_ADMISSION_ACTIONS: Readonly<{
    readonly "mfa.manage": Readonly<{
        grade: "credential_change";
    }>;
    readonly "mfa.view": Readonly<{
        grade: "use";
    }>;
}>;
/** An action the MFA package's routes admit. */
export type MfaAdmissionAction = keyof typeof MFA_ADMISSION_ACTIONS;
//# sourceMappingURL=admissionActions.d.mts.map