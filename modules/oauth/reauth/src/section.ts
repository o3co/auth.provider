import { setting } from "@mod/kernel";
import { z } from "zod";

export const section = z.strictObject({
	"record-lifetime": setting
		.duration("ms")
		.pipe(z.number().int().min(60_000).max(3_600_000))
		.prefault("10m")
		.describe(
			"How long a re-authentication record lives, from 1m to 1h: a login that `prompt=login`, `max_age` or an essential `auth_time` asked, back later than this, is asked again.",
		),
});

export type Settings = z.output<typeof section>;
