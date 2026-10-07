import type { AdapterFactory, CodeRepository, PathResolver, UserRepository } from "@o3co/auth-provider-core";
export declare const registerBuiltinAdapters: (factories: {
    userFactory: AdapterFactory<UserRepository>;
    codeFactory: AdapterFactory<CodeRepository>;
    pathResolver?: PathResolver;
}) => void;
export { HttpUserRepository } from "./repositories/HttpUserRepository.mjs";
export { RedisCodeRepository } from "./repositories/RedisCodeRepository.mjs";
//# sourceMappingURL=index.d.mts.map