export type { FederationProviderFactory } from "./federations/factory.mjs";
export { createFederationProviderFactory, registerBuiltinFederations, } from "./federations/factory.mjs";
export type { GithubProviderConfig } from "./federations/github.mjs";
export { createGithubProvider } from "./federations/github.mjs";
export type { GoogleProviderConfig } from "./federations/google.mjs";
export { createGoogleProvider } from "./federations/google.mjs";
export type { EndSessionRequest, EndSessionResult, FederationProfile, FederationProvider, FederationResult, MappedClaims, RefreshedTokens, SupportsClaimMapping, SupportsLogout, SupportsRefresh, } from "./federations/types.mjs";
export { supportsClaimMapping, supportsLogout, supportsRefresh, } from "./federations/types.mjs";
export { sessionModule } from "./module.mjs";
export type { SessionStoreFactory } from "./store/factory.mjs";
export { createSessionStoreFactory, registerBuiltinSessionStores, } from "./store/factory.mjs";
//# sourceMappingURL=index.d.mts.map