/**
 * Where the guard looks beside the mode itself (#473). A deployment that has
 * declared more than one replica is never a development box, whatever its
 * environment is named.
 */
export interface EncryptionGuardContext {
    readonly environment?: string;
    readonly deploymentMode?: string;
}
/**
 * OR-12 / #473 — refuse to construct a federation-token store with
 * `mode = "allow-plaintext"` where plaintext is not acceptable, unless the
 * operator explicitly sets `FEDERATION_TOKENS_ALLOW_INSECURE=1`. Logs a
 * CRITICAL line when the escape hatch is active. Everywhere else it emits a
 * soft `console.warn` but does not throw.
 *
 * Plaintext is refused when any of these holds:
 *   - the explicit `environment` is `production` or `staging`;
 *   - `NODE_ENV` is `production` or `staging` (always consulted; the sole
 *     signal when no environment is passed);
 *   - `deploymentMode` is `"multi"`.
 *
 * Runs at factory time before the DI container is fully wired, so direct
 * `console.*` is the appropriate emission channel (no Logger available yet).
 */
export declare function validateEncryptionMode(label: string, mode: "required" | "allow-plaintext", { environment, deploymentMode }: EncryptionGuardContext): void;
//# sourceMappingURL=encryption-mode.d.mts.map