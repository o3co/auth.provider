export declare const REFRESH_BACKOFF_WINDOW_MS = 30000;
export interface RefreshBackoffKey {
    readonly sid: string;
    readonly federationName: string;
    /** As the record holds it: a value that is not a string is digested as `""`, never thrown on. */
    readonly accessToken: unknown;
}
export interface RefreshBackoff {
    /** Whether a stamp of this record, made at most the window before `now`, stands. */
    holds(key: RefreshBackoffKey, now: number): boolean;
    /** Stamps this record's refresh as failed at `now`. */
    stamp(key: RefreshBackoffKey, now: number): void;
}
export declare const createRefreshBackoff: (limits?: {
    readonly windowMs: number;
    readonly maxEntries: number;
}) => RefreshBackoff;
//# sourceMappingURL=federationTokenRefreshBackoff.d.mts.map