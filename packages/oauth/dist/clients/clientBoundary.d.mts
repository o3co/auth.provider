/**
 * The one reading of the `ClientRepository` an oauth entry point or grant is
 * handed (`createOAuthRouter`, `createClientAuthMiddleware`, the
 * authorization-code grant): behind core's client-record boundary, so every
 * registered client an endpoint reads is held to the registration schema.
 */
import { type ClientRepository, type ClientRepositoryBoundaryOptions } from "@o3co/auth-provider-core";
/**
 * `repository` behind core's boundary (`validatedClientRepository`, which
 * answers a boundary as it is). A document fallback is answered as it is:
 * it reads its registered clients through the boundary already, and a
 * boundary over it would copy its document clients away from their
 * provenance.
 */
export declare function behindClientBoundary(repository: ClientRepository, logger: NonNullable<ClientRepositoryBoundaryOptions["logger"]>): ClientRepository;
//# sourceMappingURL=clientBoundary.d.mts.map