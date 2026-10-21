import { z } from "zod";

/** Standard base64 alone, padded: a lax decoder skips other characters and reads what is left. */
const strictBase64 =
	/^(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$|^(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)$/;

/** A key of fewer byte values is weak (all zero, a short repeated pattern); a random one is, with odds under 1e-36. */
const fewestByteValues = 8;

/** How a secret's text is read as its bytes, where the operator names it: hex, strict base64, or the text's own UTF-8 bytes. */
export type SecretEncoding = "hex" | "base64" | "utf8";

interface Reading {
	/** Unnamed, hex is taken where the value is whole bytes of hex, else strict base64. */
	readonly hex?: boolean;
	/** Named, that reading alone. */
	readonly encoding?: SecretEncoding | undefined;
}

const isHex = (value: string) => /^(?:[0-9a-fA-F]{2})+$/.test(value);

/** A secret setting's bytes, as the reading takes them; none when the value is not of it. */
export function bytesOf(
	value: string,
	{ hex = false, encoding }: Reading = {},
): Buffer | undefined {
	if (encoding === "utf8") return Buffer.from(value, "utf8");
	if (encoding === "hex") return isHex(value) ? Buffer.from(value, "hex") : undefined;
	if (encoding === undefined && hex && isHex(value)) return Buffer.from(value, "hex");
	return strictBase64.test(value) ? Buffer.from(value, "base64") : undefined;
}

type Size = { readonly exactly: number } | { readonly atLeast: number };

/**
 * Why a secret is refused, read as `reading` takes it: a `REPLACE-` sample, not of the reading, of
 * another size, or of fewer than 8 byte values; nothing when it is taken. Names the rule, never the value.
 */
export function secretProblem(
	value: string,
	size: Size,
	reading: Reading = {},
): string | undefined {
	if (value.startsWith("REPLACE-")) return "a sample left in place: REPLACE- is never a secret";
	const bytes = bytesOf(value, reading);
	if (!bytes) {
		if (reading.encoding !== undefined) return `not ${reading.encoding}`;
		return reading.hex ? "not hex or base64" : "not base64";
	}
	if ("exactly" in size && bytes.length !== size.exactly) return `${size.exactly} bytes`;
	if ("atLeast" in size && bytes.length < size.atLeast) return `at least ${size.atLeast} bytes`;
	if (new Set(bytes).size < fewestByteValues) {
		return `a weak key: fewer than ${fewestByteValues} byte values`;
	}
	return undefined;
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
		const problem = secretProblem(value, size, { hex });
		if (problem) ctx.addIssue({ code: "custom", message: problem });
	});
}

/** Each way a token can be read as key material: its own bytes, and what hex or base64 decodes it to. */
function readingsOf(token: string): Buffer[] {
	const hex = /^(?:[0-9a-fA-F]{2})+$/.test(token);
	const body = token.replace(/=+$/, "");
	const padding = token.length - body.length;
	// Base64 as written: one alphabet, no lone sixth bit, and padding that completes the last four.
	const alphabet = /^[A-Za-z0-9+/]+$/.test(body) || /^[A-Za-z0-9_-]+$/.test(body);
	const rest = body.length % 4;
	const base64 = alphabet && padding <= 2 && rest !== 1 && (padding === 0 || rest + padding === 4);
	return [
		Buffer.from(token),
		...(hex ? [Buffer.from(token, "hex")] : []),
		...(base64 ? [Buffer.from(body, "base64url")] : []),
	];
}

/** A bearer token's setting: a b64token of at least `atLeast` bytes and 8 byte values of key material however read, never a sample. */
export function bearerToken({ atLeast }: { readonly atLeast: number }) {
	return z.string().superRefine((value, ctx) => {
		const refuse = (message: string) => ctx.addIssue({ code: "custom", message });
		if (value.startsWith("REPLACE-"))
			return refuse("a sample left in place: REPLACE- is never a secret");
		if (!/^[A-Za-z0-9\-._~+/]+=*$/.test(value)) return refuse("not an RFC 6750 b64token");
		const readings = readingsOf(value);
		if (Math.min(...readings.map((b) => b.length)) < atLeast) {
			return refuse(`at least ${atLeast} bytes of key material`);
		}
		if (readings.some((b) => new Set(b).size < fewestByteValues)) {
			refuse(`a weak key: fewer than ${fewestByteValues} byte values`);
		}
	});
}
