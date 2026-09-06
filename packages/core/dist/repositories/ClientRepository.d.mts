import type { Client } from "./types.mjs";
export type PublicClient = Omit<Client, "clientSecret">;
export interface ClientRepository {
    findById(clientId: string): Promise<PublicClient | null>;
    authenticate(clientId: string, secret: string): Promise<PublicClient | null>;
}
//# sourceMappingURL=ClientRepository.d.mts.map