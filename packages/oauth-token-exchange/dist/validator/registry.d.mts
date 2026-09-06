import type { ExchangeTokenValidator } from "./types.mjs";
export type ExchangeTokenValidatorRegistryErrorReason = "duplicate" | "unknown" | "frozen";
/**
 * Error class for ExchangeTokenValidatorRegistry mutation failures.
 * Per A6+A7 §2.4.
 *
 * The `registered` snapshot lets callers see what is currently registered
 * so the diagnostic reveals the actual mental-model mismatch.
 */
export declare class ExchangeTokenValidatorRegistryError extends Error {
    readonly reason: ExchangeTokenValidatorRegistryErrorReason;
    readonly tokenType: string;
    readonly registered: readonly string[];
    constructor(args: {
        reason: ExchangeTokenValidatorRegistryErrorReason;
        tokenType: string;
        registered: readonly string[];
    });
}
/**
 * Registry keyed by RFC 8693 `token_type` URI. Used by the Token Exchange
 * grant handler to dispatch `subject_token` / `actor_token` validation.
 *
 * Per A6+A7 §2.1–§2.4 (v0.5.0 unified contract):
 * - `register(name, validator)` throws on duplicate REGARDLESS of freeze
 *   state (was: silent overwrite pre-freeze in v0.4.x).
 * - `replace(name, validator)` is the explicit override path.
 * - `freeze()` is the activation boundary — after freeze, register and
 *   replace throw reason="frozen"; get continues to work.
 *
 * Phase 4 (A2-β boot planner) becomes the only caller in v0.5.0; Phase 9
 * internalises the registry per spec §3.1bis. Phase 3 establishes the
 * contract.
 */
export declare class ExchangeTokenValidatorRegistry {
    private validators;
    private frozen;
    register(tokenType: string, validator: ExchangeTokenValidator): void;
    replace(tokenType: string, validator: ExchangeTokenValidator): void;
    get(tokenType: string): ExchangeTokenValidator | undefined;
    /**
     * Seal the registry. Idempotent: calling freeze() on an already-frozen
     * registry is a no-op.
     */
    freeze(): void;
}
//# sourceMappingURL=registry.d.mts.map