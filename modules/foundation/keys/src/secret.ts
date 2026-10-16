import { z } from "zod";

/** Standard base64 alone, padded: a lax decoder skips other characters and reads what is left. */
const strictBase64 =
	/^(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$|^(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)$/;

/** A key of fewer byte values is weak (all zero, a short repeated pattern); a random one is, with odds under 1e-36. */
const fewestByteValues = 8;

/** A secret setting's bytes: hex where `hex` is taken and the value is whole bytes of hex, else strict base64; none when neither. */
export function bytesOf(value: string, { hex = false } = {}): Buffer | undefined {
	if (hex && /^(?:[0-9a-fA-F]{2})+$/.test(value)) return Buffer.from(value, "hex");
	return strictBase64.test(value) ? Buffer.from(value, "base64") : undefined;
}

/**
 * The setting of a secret's bytes: strict base64 (or hex, where `hex` is taken) of `exactly` or
 * `atLeast` that many bytes, of at least 8 byte values, never a `REPLACE-` sample. A refusal names
 * the rule, never the value.
 */
export function secretBytes(
	size: { readonly exactly: number } | { readonly atLeast: number },
	{ hex = false } = {},
) {
	return z.string().superRefine((value, ctx) => {
		const refuse = (message: string) => ctx.addIssue({ code: "custom", message });
		if (value.startsWith("REPLACE-"))
			return refuse("a sample left in place: REPLACE- is never a secret");
		const bytes = bytesOf(value, { hex });
		if (!bytes) return refuse(hex ? "not hex or base64" : "not base64");
		if ("exactly" in size && bytes.length !== size.exactly) return refuse(`${size.exactly} bytes`);
		if ("atLeast" in size && bytes.length < size.atLeast)
			return refuse(`at least ${size.atLeast} bytes`);
		if (new Set(bytes).size < fewestByteValues) {
			return refuse(`a weak key: fewer than ${fewestByteValues} byte values`);
		}
	});
}
