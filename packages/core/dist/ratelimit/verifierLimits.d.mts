/**
 * The prefixes whose limit a verifier sets itself: the attempts a credential
 * check allows, counted on the attempt counter at the owner's setting and
 * never by a rate limiter. The owning module declares each by claiming it
 * with `verifierLimitClaim`, which names the setting; the bundled limiter
 * modules' sections may not name one in their `limits`, and a refusal points
 * to that setting. The builders and constructors take `limits` as given.
 *
 * Boot reads the declarations of every loaded module, switched on or off, at
 * stage 1, and holds them for the section parse alone
 * (`withVerifierLimitDeclarations`): a section is parsed before any module's
 * switch is read.
 */
import type { z } from "zod";
import type { RateLimitBudgetFactory, VerifierLimitDeclaration } from "../modules/manifest/contributes-map.mjs";
/**
 * Runs `parse` with `declared` (prefix to setting) as the verifier limits a
 * limiter section refuses, and restores what was held before. `parse` is
 * synchronous, so no other parse sees them.
 * @internal
 */
export declare function withVerifierLimitDeclarations<T>(declared: ReadonlyMap<string, string>, parse: () => T): T;
/**
 * Where the limit under `prefix` is set when a verifier owns it — the
 * setting a refusal names: the one `declared` holds (by default, what boot
 * holds while parsing), else `undefined`. Core names no prefix itself: only
 * a declaration makes one a verifier's.
 */
export declare const verifierLimitSetting: (prefix: string, declared?: ReadonlyMap<string, string> | undefined) => string | undefined;
/**
 * A limiter section's `limits` check (`superRefine`): an issue at each entry
 * naming a verifier's prefix.
 */
export declare function refuseVerifierLimitEntries(limits: Readonly<Record<string, unknown>>, ctx: z.RefinementCtx): void;
/**
 * A `rateLimitBudgets` claim of a prefix a verifier limits itself: it
 * answers `null`, as every claim does, and declares the setting the limit is
 * made at. Frozen.
 */
export declare function verifierLimitClaim(declaration: VerifierLimitDeclaration): RateLimitBudgetFactory<unknown>;
//# sourceMappingURL=verifierLimits.d.mts.map