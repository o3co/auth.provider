import { setting } from "@mod/kernel";
import { bearerToken } from "@mod/keys";
import { urlSetting } from "@mod/url-setting";
import { z } from "zod";

export const section = z.strictObject({
	issuer: z
		.string()
		.min(1)
		.describe("The `iss` whose assertions it uses up: one of jwt-bearer's `issuers`."),
	"consume-url": urlSetting({ schemes: ["https", "http"] }).describe(
		"Where an assertion's jti is used up. Plain http is reached only where outbound's policy names it.",
	),
	credential: bearerToken({ atLeast: 32 })
		.optional()
		.describe("A bare bearer token (RFC 6750 b64token) of at least 32 bytes of key material."),
	"credential-header": z
		.string()
		.optional()
		.describe(
			"The header the credential goes in, as it is, such as x-internal-token; unset, it goes as Authorization: Bearer.",
		),
	timeout: setting
		.duration("ms")
		.pipe(z.number().int().min(1).max(60_000))
		.optional()
		.describe("How long a call may take, from 1ms to 1m, narrowing outbound's cap."),
	"max-response-size": setting
		.size()
		.pipe(z.number().int().min(1).max(16_777_216))
		.optional()
		.describe("The largest answer read, from 1B to 16MiB, narrowing outbound's cap."),
});
