import { timingSafeEqual } from "node:crypto";

/** Whether two secrets (strings as UTF-8) hold the same bytes; only equal lengths are compared, in constant time. */
export function sameSecret(a: string | Uint8Array, b: string | Uint8Array): boolean {
	const x = typeof a === "string" ? Buffer.from(a, "utf8") : a;
	const y = typeof b === "string" ? Buffer.from(b, "utf8") : b;
	return x.byteLength === y.byteLength && timingSafeEqual(x, y);
}
