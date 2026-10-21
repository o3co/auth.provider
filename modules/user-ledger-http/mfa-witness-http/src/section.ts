import { setting } from "@mod/kernel";
import { bearerToken } from "@mod/keys";
import { urlSetting } from "@mod/url-setting";
import { z } from "zod";

/**
 * A path or query with what RFC 3986 calls equivalent spelled one way: an unreserved character
 * encoded is the character, and the hex of any other encoding upper case (§6.2.2.1, §6.2.2.2).
 */
const equivalent = (part: string) =>
	part.replace(/%([0-9A-Fa-f]{2})/g, (_, hex: string) => {
		const char = String.fromCharCode(Number.parseInt(hex, 16));
		return /[A-Za-z0-9\-._~]/.test(char) ? char : `%${hex.toUpperCase()}`;
	});

/** Whether two URLs reach one target as outbound sends them: their origin, path and query, whatever their spelling. */
export function sameTarget(a: string, b: string): boolean {
	const [x, y] = [new URL(a), new URL(b)];
	return (
		x.origin === y.origin &&
		equivalent(x.pathname) === equivalent(y.pathname) &&
		equivalent(x.search) === equivalent(y.search)
	);
}

const ledgerUrl = (what: string) =>
	urlSetting({ schemes: ["https", "http"] }).describe(
		`${what} At the same origin as the other URLs. Plain http is reached only where outbound's policy names it.`,
	);

export const section = z
	.strictObject({
		"read-url": ledgerUrl("Where whether a subject carries the mark is read."),
		"enroll-url": ledgerUrl("Where the mark is set to a token unless one is set."),
		"clear-url": ledgerUrl("Where the mark is removed."),
		"withdraw-url": ledgerUrl(
			"Where the mark is removed only where it is the token sent's, by a compare-and-delete on the mark's own row. Optional: without it a ledger is asked to clear instead, and each boot warns. Never reaching clear-url's target, however spelled.",
		).optional(),
		credential: bearerToken({ atLeast: 32 }).describe(
			"A bare bearer token (RFC 6750 b64token) of at least 32 bytes of key material, sent on every call.",
		),
		timeout: setting
			.duration("ms")
			.pipe(z.number().int().min(1).max(60_000))
			.prefault("5s")
			.describe(
				"How long a call may take, from 1ms to 1m, narrowing outbound's cap; a write's deadline is its sending time plus the time outbound holds the call to.",
			),
		"max-response-size": setting
			.size()
			.pipe(z.number().int().min(1).max(16_777_216))
			.optional()
			.describe("The largest answer read, from 1B to 16MiB, narrowing outbound's cap."),
	})
	// A route that clears whatever mark stands would answer a withdraw 204 and take a binding's mark.
	.refine(
		(s) => s["withdraw-url"] === undefined || !sameTarget(s["withdraw-url"], s["clear-url"]),
		{
			message: "reaches clear-url's target: a withdraw removes the token's mark alone",
			path: ["withdraw-url"],
			// Asked only of URLs url-setting took, so a URL it refused is told once.
			when: (payload) => payload.issues.length === 0,
		},
	);
