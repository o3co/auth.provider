import type { GrantDependencies, GrantHandler, GrantModule } from "./types.mjs";
export declare class GrantRegistry {
    private handlers;
    register(grantType: string, handler: GrantHandler): void;
    get(grantType: string): GrantHandler | undefined;
    addModule(module: GrantModule, deps: GrantDependencies): void;
    cleanup(): void;
}
//# sourceMappingURL=registry.d.mts.map