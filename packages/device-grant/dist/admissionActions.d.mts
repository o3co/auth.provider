/**
 * The actions device verification admits, one per body action, with the grade
 * the device grant registers for each: a lookup and a denial grant nothing, so
 * a user refuses a phished device request without a step-up; an approval grants
 * a device a token.
 */
export declare const DEVICE_GRANT_ADMISSION_ACTIONS: Readonly<{
    readonly "device.lookup": Readonly<{
        grade: "grants_nothing";
    }>;
    readonly "device.approve": Readonly<{
        grade: "use";
    }>;
    readonly "device.deny": Readonly<{
        grade: "grants_nothing";
    }>;
}>;
/** An action device verification admits. */
export type DeviceGrantAdmissionAction = keyof typeof DEVICE_GRANT_ADMISSION_ACTIONS;
//# sourceMappingURL=admissionActions.d.mts.map