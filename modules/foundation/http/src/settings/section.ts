import { certificateSettings } from "@mod/client-certificate";
import { sourceSettings } from "@mod/request-source";
import { z } from "zod";

export const section = z
	.strictObject({
		host: z.string().default("127.0.0.1").describe("The address it listens on."),
		port: z
			.number()
			.int()
			.min(0)
			.max(65535)
			.default(8080)
			.describe("The port it listens on; 0 takes a free one."),
		"trusted-proxies": sourceSettings.shape["trusted-proxies"],
		"public-origin": z
			.url({ protocol: /^https?$/ })
			.refine((s) => new URL(s).origin === s, "origin only (no path)")
			.optional()
			.describe(
				"The scheme, host and port users reach this deployment at: an origin only, with no path.",
			),
		"cors-origins": z
			.array(
				z
					.url({ protocol: /^https$/ })
					.refine((s) => !s.includes("*") && new URL(s).origin === s, "an https origin"),
			)
			.default([])
			.describe(
				"The https origins whose pages may read cross-origin routes: exact, without a pattern.",
			),
		"insecure-origin": z
			.boolean()
			.default(false)
			.describe(
				"Accepts a plain-http `public-origin`, knowing its cookies cannot be made secure: an http `public-origin` boots only with it.",
			),
		"proxy-hops": sourceSettings.shape["proxy-hops"],
		/** Where a trusted proxy forwards the client's certificate; none is read without it. */
		"client-certificate": certificateSettings.optional(),
	})
	.refine((s) => !s["public-origin"]?.startsWith("http:") || s["insecure-origin"], {
		message: "an http public origin needs insecure-origin set explicitly",
		path: ["public-origin"],
	});
