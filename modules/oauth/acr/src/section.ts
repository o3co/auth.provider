import { z } from "zod";
import { amrSetsShape } from "./contract.ts";

export const section = z.strictObject({
	values: z
		.record(z.string(), amrSetsShape)
		.prefault({})
		.describe("Each acr and the amr sets that meet it: one set wholly held is enough."),
});
