/**
 * Built-in module that provides the in-process
 * {@link FederationGrantIntentStore} (#593, D16, slice 6) — acquisition's
 * records: the intent a backend lodged, the consent challenge a browser
 * answers, and the connect transaction a callback consumes.
 *
 * Dev and single-replica only, and refused by name under
 * `deployment.mode = "multi"`. Unlike the in-memory grant store beside a
 * durable one, this pairing is permitted for a single replica: a restart loses
 * flows in progress, and no established grant or revocation with it.
 *
 * It needs no configuration. The one deadline of an acquisition is the flow
 * budget, which core sets when it lodges the intent, and the bound on live
 * first-time intents is a constant on the port — neither is an operator's to
 * tune, so this module reads nothing.
 */
export declare const memoryFederationGrantIntentStoreModule: import("../modules/index.mjs").Module;
/**
 * Built-in module that provides the in-process memory
 * {@link FederationGrantStore} (#593). Dev and single-replica only — no
 * persistence across restarts, which for a grant means every user connects
 * again, and refused by name under `deployment.mode = "multi"`.
 */
export declare const memoryFederationGrantStoreModule: import("../modules/index.mjs").Module;
//# sourceMappingURL=module.d.mts.map