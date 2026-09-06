import { type ClientRepository, type CodeRepository, type GrantDependencies, type GrantHandler } from "@o3co/auth-provider-core";
export declare const createAuthorizationGrant: (deps: GrantDependencies & {
    codeRepository: CodeRepository;
    clientRepository: ClientRepository;
}) => GrantHandler;
//# sourceMappingURL=authorization.d.mts.map