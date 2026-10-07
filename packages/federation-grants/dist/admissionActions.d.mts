/**
 * The actions the browser half admits, one per step, each exercising the
 * session (`use`): the connect start, the consent read and answer, and the
 * callback's reads.
 */
export declare const FEDERATION_GRANTS_ADMISSION_ACTIONS: Readonly<{
    readonly "federation_grants.connect": Readonly<{
        grade: "use";
    }>;
    readonly "federation_grants.consent": Readonly<{
        grade: "use";
    }>;
    readonly "federation_grants.callback": Readonly<{
        grade: "use";
    }>;
}>;
/** An action the browser half admits. */
export type FederationGrantsAdmissionAction = keyof typeof FEDERATION_GRANTS_ADMISSION_ACTIONS;
//# sourceMappingURL=admissionActions.d.mts.map