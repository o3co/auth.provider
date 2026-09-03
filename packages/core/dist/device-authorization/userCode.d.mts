/** RFC 8628 §6.1's base-20 character set. */
export declare const USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ";
/** Characters per code. 8 × log2(20) ≈ 34.5 bits — the §5.1 worked example. */
export declare const USER_CODE_LENGTH = 8;
/**
 * A fresh `user_code`, in display form (`BCDF-GHJK`).
 *
 * `randomInt` rather than `randomBytes() % 20`: the modulo of 256 by 20 is
 * biased toward the first 16 characters, which would quietly cost about a bit
 * of the 34.5 this is counting on. `randomInt` rejects and re-draws instead.
 */
export declare const generateUserCode: () => string;
/** Insert the display hyphen into a normalised code. */
export declare const formatUserCode: (normalised: string) => string;
/**
 * Reduce anything a human typed to the canonical form used for storage and
 * comparison, or `null` when it cannot be one of our codes.
 *
 * Lower case is folded up and formatting characters are dropped, because a
 * user copying `bcdf-ghjk` off a television has entered the right code.
 * Characters *outside* the alphabet are **rejected rather than stripped**: a
 * `0` typed for an `O` is a mistake, and silently removing it would turn an
 * 8-character mistake into a 7-character lookup that fails for a reason the
 * user cannot see — or worse, matches a different code.
 */
export declare const normaliseUserCode: (input: string) => string | null;
/**
 * A fresh `device_code`. 256 bits, base64url — §5.2 wants "a very high
 * entropy code", and nothing types this one.
 */
export declare const generateDeviceCode: () => string;
//# sourceMappingURL=userCode.d.mts.map