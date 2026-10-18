import { setting } from "@mod/kernel";
import { bearerToken } from "@mod/keys";
import { addressList } from "@mod/request-source";
import { z } from "zod";

const window = () => setting.duration("ms").pipe(z.number().int().min(1000).max(3_600_000));

export const section = z.strictObject({
	credential: bearerToken({ atLeast: 32 }).describe(
		"The bearer token the ledger sends: a bare b64token (RFC 6750) of at least 32 bytes of key material.",
	),
	"previous-credential": bearerToken({ atLeast: 32 })
		.optional()
		.describe(
			"The token being replaced, still taken while the ledger moves to the new one; remove it once it has.",
		),
	sources: addressList()
		.min(1)
		.describe(
			"The IP addresses or CIDR blocks the ledger sends from, as request-source tells a request's source.",
		),
	failures: z
		.number()
		.int()
		.min(1)
		.max(1000)
		.prefault(10)
		.describe(
			"Refused requests (a wrong source or credential) allowed per source in each failure-window, from 1 to 1000.",
		),
	"failure-window": window()
		.prefault("1m")
		.describe(
			"The window a source's refused requests are counted in: a duration with a unit, from 1s to 1h, e.g. 1m.",
		),
	requests: z
		.number()
		.int()
		.min(1)
		.max(100_000)
		.prefault(600)
		.describe("Authenticated requests allowed per source in each window, from 1 to 100000."),
	window: window()
		.prefault("1m")
		.describe(
			"The window a source's authenticated requests are counted in: a duration with a unit, from 1s to 1h, e.g. 1m.",
		),
});
