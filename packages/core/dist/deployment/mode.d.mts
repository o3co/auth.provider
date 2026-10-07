/**
 * The one reading of the configuration's `core.deployment.mode` — what boot fills
 * the `deploymentMode` slot with before any provider runs, and what the
 * replica-safety guard decides by — and the check a reader holds the slot's
 * value to. Every other module requires the slot; a composition root that
 * builds a reader by hand passes `deploymentModeOf(config)`.
 */
import type { DeploymentMode } from "./types.mjs";
/**
 * `single` or `multi` as `core.deployment.mode` states it, `unset` for anything
 * else — absence included. Core's schema admits only the two, or none; any
 * other value reaches here only through a configuration the schema never
 * saw, and reads as `unset`, never as `single` or `multi`.
 */
export declare function deploymentModeOf(config: unknown): DeploymentMode;
/**
 * `value` when it is one of the slot's three values, or a `TypeError` naming
 * `name`, the value's source — absence included. A reader refuses what it
 * cannot read as a mode rather than reading it as `unset`: a mode lost on the
 * way would lift the refusals `multi` makes.
 */
export declare function checkDeploymentMode(value: unknown, name: string): DeploymentMode;
//# sourceMappingURL=mode.d.mts.map