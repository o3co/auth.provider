import { type InterruptionAnswer } from "./requirement.mjs";
/**
 * Holds an interruption's answer to the closed body (`ANSWER_KEYS`, `error`
 * in the RFC 6749 error-text class) and to the `hintKeys` the requirement
 * named `name` declared, each hint a boolean, a bounded integer or
 * enum-like tokens, so a snapshot, a URL, an address or a name cannot pass.
 * Answers a frozen copy; a body that fails is the requirement's fault, a
 * `RangeError` the route answers as an `open` failure.
 */
export declare function checkInterruptionAnswer(value: unknown, name: string, hintKeys: readonly string[]): InterruptionAnswer;
//# sourceMappingURL=interruption-answer.d.mts.map