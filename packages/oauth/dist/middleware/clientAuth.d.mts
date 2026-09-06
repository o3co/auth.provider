import type { ClientRepository, PublicClient } from "@o3co/auth-provider-core";
import type { RequestHandler } from "express";
declare global {
    namespace Express {
        interface Request {
            /**
             * The authenticated OAuth client, set by {@link createClientAuthMiddleware}
             * after successful RFC 6749 §2.3.1 client authentication. Absent when the
             * request has not been through client-auth middleware.
             */
            oauthClient?: PublicClient;
        }
    }
}
/**
 * Creates RFC 6749 §2.3.1 client-authentication middleware for the /oauth/introspect
 * endpoint (and any other route requiring authenticated OAuth client access).
 *
 * Extracts client credentials from the request using:
 * 1. HTTP Basic authentication (preferred per RFC 6749 §2.3.1)
 * 2. Form-encoded `client_id` / `client_secret` body parameters (fallback)
 *
 * On success: sets `req.oauthClient` to the authenticated {@link PublicClient} and
 * calls `next()`. The built-in /introspect handler does not consume this field — it
 * is exposed for consumers who compose this middleware onto their own routes and need
 * the authenticated client's identity downstream.
 *
 * On failure: responds with 401 + `WWW-Authenticate: Basic realm="oauth"` header
 * and `{ error: "invalid_client" }` body (RFC 6749 §5.2). A differentiated
 * `error_description` is included on most failure paths to aid client debugging;
 * the repository-throw path intentionally omits it to avoid leaking server-side
 * operational detail to callers.
 *
 * @param clientRepository - used to look up the client by credential pair.
 * @returns an express RequestHandler.
 */
export declare function createClientAuthMiddleware(clientRepository: ClientRepository): RequestHandler;
//# sourceMappingURL=clientAuth.d.mts.map