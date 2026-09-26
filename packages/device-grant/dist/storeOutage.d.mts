/** The body of the `503` a device route answers a store outage with. */
export declare const DEVICE_CODE_STORE_UNAVAILABLE: {
    readonly error: "temporarily_unavailable";
    readonly description: "the device authorization store is unavailable; retry later";
};
/**
 * Log a device-code store outage as `event`, at error. A logger with no error
 * channel is passed over for core's console logger, as the verification
 * route's limiter outage is, rather than losing the line.
 */
export declare const reportDeviceCodeStoreOutage: (logger: {
    error?(obj: Record<string, unknown>, msg: string): void;
} | undefined, event: string, err: unknown, fields?: Record<string, unknown>) => void;
//# sourceMappingURL=storeOutage.d.mts.map