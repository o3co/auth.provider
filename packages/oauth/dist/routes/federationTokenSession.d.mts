import type { FederationTokenCaller, FederationTokenContext } from "./federationTokenContext.mjs";
/** Answers and returns `false` unless the caller's session is live for its `sub`. */
export declare const checkSessionLive: (ctx: FederationTokenContext, caller: FederationTokenCaller) => Promise<boolean>;
//# sourceMappingURL=federationTokenSession.d.mts.map