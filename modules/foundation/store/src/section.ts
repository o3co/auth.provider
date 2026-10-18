import { z } from "zod";

export const section = z.strictObject({
	"accept-volatile": z
		.boolean()
		.prefault(false)
		.describe("Whether spaces that need durable or replicated storage may boot on memory."),
});
