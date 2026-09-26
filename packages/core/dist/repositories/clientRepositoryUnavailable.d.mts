import type { Logger } from "../logging/Logger.mjs";
/** Which client lookup failed, and where. */
export interface ClientRepositoryOutage {
    /** The lookup that threw: `findById`, or `authenticate` with a secret. */
    readonly step: "find" | "authenticate";
    /**
     * The route or grant that asked, when it is not client authentication's own
     * middleware: `authorize`, `token_exchange`, `federation_token`.
     */
    readonly site?: string;
    /**
     * The client id that was looked up. It is the client's input, so it is
     * recorded through `auditErrorText`: sanitised, and capped at 200
     * characters.
     */
    readonly clientId: unknown;
}
/**
 * Logs `client_repository_unavailable` at error level: the outage's `step`,
 * its `site` when given, the client id sanitised and capped, and the error's
 * projection (`loggableError`) — never the error, which can carry what the
 * store was sent.
 */
export declare function logClientRepositoryUnavailable(logger: Pick<Logger, "error"> | undefined, outage: ClientRepositoryOutage, cause: unknown): void;
//# sourceMappingURL=clientRepositoryUnavailable.d.mts.map