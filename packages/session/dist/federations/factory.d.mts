import { type AdapterFactory } from "@o3co/auth-provider-core";
import type { FederationProvider } from "./types.mjs";
export type FederationProviderFactory = AdapterFactory<FederationProvider>;
export declare function createFederationProviderFactory(): FederationProviderFactory;
export declare function registerBuiltinFederations(factory: FederationProviderFactory): void;
//# sourceMappingURL=factory.d.mts.map