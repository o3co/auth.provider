import { type AdapterFactory } from "../adapters/AdapterFactory.mjs";
import type { ClientRepository } from "./ClientRepository.mjs";
import type { CodeRepository } from "./CodeRepository.mjs";
import type { UserRepository } from "./UserRepository.mjs";
/**
 * Construct the three default repository factories with built-in yaml/static/memory
 * adapters pre-registered. Consumers register additional adapters (e.g. http, redis)
 * via `registerBuiltinAdapters` from `@o3co/auth-provider-foundation`.
 */
export declare const createDefaultFactories: () => {
    clientFactory: AdapterFactory<ClientRepository>;
    userFactory: AdapterFactory<UserRepository>;
    codeFactory: AdapterFactory<CodeRepository>;
};
//# sourceMappingURL=RepositoryFactory.d.mts.map