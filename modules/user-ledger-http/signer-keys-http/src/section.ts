import { setting } from "@mod/kernel";
import { bearerToken } from "@mod/keys";
import { urlSetting } from "@mod/url-setting";
import { z } from "zod";

export const section = z.strictObject({
	issuer: z
		.string()
		.min(1)
		.describe("The `iss` it answers for: one of jwt-bearer's `issuers` with no keys of its own."),
	"keys-url": urlSetting({ schemes: ["https", "http"] }).describe(
		"Where a signer's keys are looked up. Plain http is reached only where outbound's policy names it.",
	),
	credential: bearerToken({ atLeast: 32 })
		.optional()
		.describe("A bare bearer token (RFC 6750 b64token) of at least 32 bytes of key material."),
	timeout: setting
		.duration("ms")
		.pipe(z.number().int().min(1).max(60_000))
		.optional()
		.describe("How long a lookup may take, from 1ms to 1m, narrowing outbound's cap."),
	"max-response-size": setting
		.size()
		.pipe(z.number().int().min(1).max(16_777_216))
		.optional()
		.describe("The largest answer read, from 1B to 16MiB, narrowing outbound's cap."),
});
