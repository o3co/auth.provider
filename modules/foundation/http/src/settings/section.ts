import { certificateSettings } from "@mod/client-certificate";
import { setting } from "@mod/kernel";
import { sourceSettings } from "@mod/request-source";
import { urlSetting } from "@mod/url-setting";
import { z } from "zod";

export const section = z
	.strictObject({
		host: z.string().prefault("127.0.0.1").describe("The address it listens on."),
		port: z
			.number()
			.int()
			.min(0)
			.max(65535)
			.prefault(8080)
			.describe("The port it listens on; 0 takes a free one."),
		...sourceSettings.shape,
		"public-origin": urlSetting({ schemes: ["https", "http"], origin: true })
			.optional()
			.describe(
				"The scheme, host and port users reach this deployment at: an origin only, with no path.",
			),
		"cors-origins": z
			.array(
				// The parser takes `*` in a host, so a pattern is refused here: an origin matches exactly.
				urlSetting({ schemes: ["https"], origin: true }).refine(
					(s) => !s.includes("*"),
					"an exact origin, without a pattern",
				),
			)
			.prefault([])
			.describe(
				"The https origins whose pages may read cross-origin routes: exact, without a pattern.",
			),
		"insecure-origin": z
			.boolean()
			.prefault(false)
			.describe(
				"Accepts a plain-http `public-origin`, knowing its cookies cannot be made secure: an http `public-origin` boots only with it, and only with `kernel.environment = development`, as a production deployment refuses it.",
			),
		/** Where a trusted proxy forwards the client's certificate; none is read without it. */
		"client-certificate": certificateSettings.optional(),
		"headers-timeout": setting
			.duration("s")
			.pipe(z.number().int().min(1).max(60))
			.prefault("10s")
			.describe(
				"How long a client may take to send a request's headers, from 1s to 1m, such as 10s; past it the request is answered 408 and its connection closed.",
			),
		"request-timeout": setting
			.duration("s")
			.pipe(z.number().int().min(1).max(300))
			.prefault("30s")
			.describe(
				"How long a client may take to send a whole request, its body included, from 1s to 5m and no less than headers-timeout, such as 30s; past it the request is answered 408 and its connection closed.",
			),
		"max-connections": z
			.number()
			.int()
			.min(1)
			.max(1_000_000)
			.prefault(10_000)
			.describe(
				"The most connections held open at once, from 1 to 1000000; one past it is closed as it arrives.",
			),
	})
	.refine((s) => s["headers-timeout"] <= s["request-timeout"], {
		message: "headers-timeout must be no more than request-timeout",
		path: ["headers-timeout"],
	})
	.refine((s) => !s["public-origin"]?.startsWith("http:") || s["insecure-origin"], {
		message:
			"an http public origin needs http.insecure-origin = true, and kernel.environment = development",
		path: ["public-origin"],
	});
