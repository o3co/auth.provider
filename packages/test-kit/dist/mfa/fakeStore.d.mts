/** A user the fake Store authenticates. */
export interface FakeStoreUser {
    /** `User.id`: the subject. */
    readonly id: string;
    readonly username: string;
    readonly password: string;
    /** The handles `authenticateByToken` resolves to this user. */
    readonly tokens?: readonly string[];
    /** The other fields of the `User` it answers. */
    readonly claims?: Readonly<Record<string, unknown>>;
}
export interface FakeStoreOptions {
    readonly users?: readonly FakeStoreUser[];
    /**
     * When set, a request whose `Authorization` is not exactly
     * `Bearer <token>` is answered `401` with `WWW-Authenticate: Bearer
     * error="invalid_token"`.
     */
    readonly bearerToken?: string;
    /**
     * The Store's clock, in epoch milliseconds, by which an emptied set's
     * tombstone expires. Default `Date.now`.
     */
    readonly now?: () => number;
    /**
     * The Store's clock a conditional write's `deadlineMs` is checked
     * against, in epoch milliseconds: apart from `now`, so moving the
     * tombstones' clock makes no write late. Default `Date.now`.
     */
    readonly requestNow?: () => number;
}
/** The fake Store's endpoints. */
export type FakeStoreEndpoint = "authenticate" | "authenticateByToken" | "list" | "create" | "update" | "delete" | "markMfaEnrolled";
/** Each endpoint's URL, named as the configuration names it. */
export interface FakeStoreUrls {
    readonly authenticateUrl: string;
    readonly authenticateByTokenUrl: string;
    readonly listUrl: string;
    readonly createUrl: string;
    readonly updateUrl: string;
    readonly deleteUrl: string;
    readonly markMfaEnrolledUrl: string;
}
/** A request the fake Store received. */
export interface FakeStoreRequest {
    readonly endpoint: FakeStoreEndpoint;
    /** Its headers, names lower-cased. */
    readonly headers: Readonly<Record<string, string>>;
    /** Its body, parsed as JSON; `undefined` when it is not JSON. */
    readonly body: unknown;
}
/** An answer the fake Store is told to give. */
export interface FakeStoreAnswer {
    readonly status: number;
    readonly headers?: Readonly<Record<string, string>>;
    readonly body?: string;
}
/**
 * Answers a request in place of the contract, or `undefined` to leave it to
 * the contract — at once, or through a promise that settles later or never.
 */
export type FakeStoreAnswerer = (request: FakeStoreRequest) => FakeStoreAnswer | undefined | Promise<FakeStoreAnswer | undefined>;
/** The largest request body the fake Store reads: 1 MiB. */
export declare const FAKE_STORE_MAX_BODY_BYTES: number;
export interface FakeStore {
    readonly urls: FakeStoreUrls;
    /** Every request received, in order. */
    readonly requests: readonly FakeStoreRequest[];
    /** The records held for `subject`, as held. */
    factors(subject: string): readonly unknown[];
    /** The witness held for `subject`; `undefined` when never marked. */
    enrolled(subject: string): boolean | undefined;
    /**
     * Holds `record` for `subject` as it is, readable or not, and leaves the
     * set without a generation, as an older writer's rewrite of the whole set
     * would: its next list mints one, and a conditional write at the one it
     * had answers `conflict`.
     */
    holdFactor(subject: string, record: unknown): void;
    /** Answers `endpoint` with `answerer` first while set; `undefined` restores the contract. */
    answer(endpoint: FakeStoreEndpoint, answerer: FakeStoreAnswerer | undefined): void;
    close(): Promise<void>;
}
/** Starts a fake Store on `127.0.0.1`, on a port of its own. */
export declare function startFakeStore(options?: FakeStoreOptions): Promise<FakeStore>;
//# sourceMappingURL=fakeStore.d.mts.map