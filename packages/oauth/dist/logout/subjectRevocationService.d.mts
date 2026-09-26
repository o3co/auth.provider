/**
 * Wires every store the service needs, and refuses the compositions that would
 * make it lie.
 *
 * The refusals are here rather than at request time because each is structural
 * — what a component *is* — and a subject revocation is the wrong moment to
 * discover that the grants it should have ended had nowhere to be read from.
 * They apply only when grants are enabled: a deployment with the feature off
 * gets exactly the service #296 would have had.
 */
export declare const subjectRevocationServiceModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=subjectRevocationService.d.mts.map