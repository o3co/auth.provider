import { setting } from "@mod/kernel";
import { bearerToken } from "@mod/keys";
import { urlSetting } from "@mod/url-setting";
import { z } from "zod";

const ledgerUrl = (what: string) =>
	urlSetting({ schemes: ["https", "http"] }).describe(
		`${what} At the same origin as the other two URLs. Plain http is reached only where outbound's policy names it.`,
	);

export const section = z.strictObject({
	"read-url": ledgerUrl("Where whether a subject carries the mark is read."),
	"enroll-url": ledgerUrl("Where the mark is set to a token unless one is set."),
	"clear-url": ledgerUrl("Where the mark is removed."),
	credential: bearerToken({ atLeast: 32 }).describe(
		"A bare bearer token (RFC 6750 b64token) of at least 32 bytes of key material, sent on every call.",
	),
	timeout: setting
		.duration("ms")
		.pipe(z.number().int().min(1).max(60_000))
		.prefault("5s")
		.describe(
			"How long a call may take, from 1ms to 1m, narrowing outbound's cap; a write's deadline is its sending time plus this.",
		),
	"max-response-size": setting
		.size()
		.pipe(z.number().int().min(1).max(16_777_216))
		.optional()
		.describe("The largest answer read, from 1B to 16MiB, narrowing outbound's cap."),
});
