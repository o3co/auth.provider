/**
 * A name an authenticator can show: well formed, 1 to 64 code points, no control or format character
 * (a bidirectional override, say).
 */
export const showable = (value: unknown): string | undefined =>
	typeof value === "string" && value.isWellFormed() && /^[^\p{Cc}\p{Cf}]{1,64}$/u.test(value)
		? value
		: undefined;
