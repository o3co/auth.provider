import { z } from "zod";
import type { ClientRepository, PublicClient } from "./ClientRepository.mjs";
/**
 * @internal
 *
 * Zod schema for per-client configuration entries consumed by the in-memory and
 * YAML client repositories. NOT part of the public API — consumers implementing
 * a custom `ClientRepository` should define their own input schema suited to
 * their backing store (database row, JWT claims, LDAP attributes, etc.).
 * This schema is exported only to share fixtures with unit tests within the
 * package.
 */
export declare const ClientEntrySchema: z.ZodObject<{
    clientSecret: z.ZodString;
    allowedRedirectUris: z.ZodDefault<z.ZodArray<z.ZodString>>;
    allowedScopes: z.ZodDefault<z.ZodArray<z.ZodString>>;
    postLogoutRedirectUris: z.ZodOptional<z.ZodArray<z.ZodString>>;
    backchannelLogoutUri: z.ZodOptional<z.ZodString>;
    backchannelLogoutSessionRequired: z.ZodDefault<z.ZodOptional<z.ZodBoolean>>;
    frontchannelLogoutUri: z.ZodOptional<z.ZodString>;
    frontchannelLogoutSessionRequired: z.ZodDefault<z.ZodOptional<z.ZodBoolean>>;
    allowedAzpForFederationToken: z.ZodDefault<z.ZodOptional<z.ZodBoolean>>;
}, z.core.$strict>;
export type ClientEntry = z.infer<typeof ClientEntrySchema>;
export declare class InMemoryClientRepository implements ClientRepository {
    private clients;
    constructor(clients: Map<string, ClientEntry>);
    findById(clientId: string): Promise<PublicClient | null>;
    authenticate(clientId: string, secret: string): Promise<PublicClient | null>;
}
//# sourceMappingURL=InMemoryClientRepository.d.mts.map