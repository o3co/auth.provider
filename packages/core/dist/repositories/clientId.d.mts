/**
 * The longest `client_id` a repository is asked for: 256 characters. RFC 6749
 * bounds nothing; a registered client id is an operator-chosen identifier,
 * and a Client ID Metadata Document's is an `https` URL that names a
 * document — both far shorter in practice. A Client ID Metadata Document URL
 * longer than this is not a client id this server honours, at `/authorize`
 * or at the token endpoint.
 *
 * It is not a column size. `VARCHAR(255)`, the most common identifier column,
 * holds one character fewer. A repository whose store fails on a 256-character
 * id, rather than finding no row, must answer that id `null` itself: only a
 * store that cannot answer may throw.
 */
export declare const MAX_CLIENT_ID_LENGTH = 256;
/** Whether `clientId` can name a client (see the module comment). */
export declare function isWellFormedClientId(clientId: unknown): clientId is string;
/**
 * Refuses a set of registered client ids any of which no request could name.
 * The error names the entry's position (1-based, in registration order) and
 * what is wrong — never the id itself, which may carry control characters.
 */
export declare function assertRegistrableClientIds(owner: string, clientIds: Iterable<unknown>): void;
//# sourceMappingURL=clientId.d.mts.map