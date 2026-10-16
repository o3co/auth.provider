import { z } from "zod";

export const section = z.strictObject({
	"max-lifetime-seconds": z
		.number()
		.int()
		.min(1)
		.max(86_400)
		.default(3600)
		.describe("The longest lifetime a client assertion may have, in seconds."),
	"clock-skew-seconds": z
		.number()
		.int()
		.min(0)
		.max(300)
		.default(30)
		.describe(
			"How far a client's clock may be off when an assertion's times are checked, in seconds.",
		),
});
