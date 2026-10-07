/**
 * Where both routes live: `POST <mount>/:grantId/token` and
 * `POST <mount>/:grantId/status` (#593, D9).
 *
 * Exported because a deployment that fronts the provider has to say the same
 * thing in its proxy rules and its network policy, and a path restated by hand
 * in three places is a path that will be wrong in one of them.
 */
export declare const FEDERATION_GRANTS_MOUNT_PATH = "/oauth/federation-grants";
//# sourceMappingURL=types.d.mts.map