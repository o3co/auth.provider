import { z } from "zod";

export const section = z.strictObject({
	"code-seconds": z.number().int().min(10).max(600).default(600),
	"sweep-seconds": z.number().int().min(1).max(3600).default(30),
});
