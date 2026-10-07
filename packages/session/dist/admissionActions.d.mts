/**
 * The actions the federation link flow admits, with the grades `sessionModule`
 * registers: the start adds a way into the account, so a recent-authentication
 * rule is decided there; the callback uses the session the start bound.
 */
export declare const SESSION_ADMISSION_ACTIONS: Readonly<{
    readonly "session.link": Readonly<{
        grade: "credential_change";
    }>;
    readonly "session.link_callback": Readonly<{
        grade: "use";
    }>;
}>;
/** An action the link flow admits. */
export type SessionAdmissionAction = keyof typeof SESSION_ADMISSION_ACTIONS;
//# sourceMappingURL=admissionActions.d.mts.map