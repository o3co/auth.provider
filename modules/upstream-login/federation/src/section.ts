import { setting } from "@mod/kernel";
import { urlSetting } from "@mod/url-setting";
import { z } from "zod";

/** An IdP's name: its path segment, so it is one spelling. */
const name = z.string().regex(/^[a-z0-9][a-z0-9-]{0,31}$/);

/** An amr value of ours (RFC 8176's or the operator's own). */
const amr = z.string().regex(/^[A-Za-z0-9_-]{1,32}$/);

export const section = z.strictObject({
	idps: z
		.record(
			name,
			z.looseObject({
				type: z.string().min(1),
				"upstream-amr": z.record(z.string().min(1), amr).prefault({}),
				"fresh-login-allowance": setting
					.duration("s")
					.pipe(z.number().int().min(0).max(300))
					.optional(),
			}),
		)
		.prefault({})
		.describe(
			"Each IdP by name (1 to 32 lowercase letters, digits and `-`, not starting with `-`): its `type`, `upstream-amr` (the upstream's amr values mapped to ours; none by default; mapping one to `mfa`, say, trusts the upstream's claim for that amr and any acr it satisfies, such as `urn:o3co:acr:mfa`, and lets its logins past the local second factor), `fresh-login-allowance` (how long before a demand for a fresh login the upstream may say the user logged in, for `prompt=login` and a max age, from 0s to 5m; the type's clock allowance, `clock-skew`, by default) and the type's own settings. With none, every login answers not found, and each boot warns `federation.no_idps`.",
		),
	landing: urlSetting({ schemes: ["https"] })
		.optional()
		.describe(
			"The https URL a login lands on when it named no return target; the public origin's root by default.",
		),
	"held-page": urlSetting({ schemes: ["https"], loopbackHttp: true })
		.optional()
		.describe(
			"The page a browser goes to when a gate holds its login, to go on there: on the public origin, as it reads the held login with this deployment's cookies; https, or http on a loopback host with `kernel.environment = development`. Without it, a held login is answered 403 with the gate's answer.",
		),
	"transaction-lifetime": setting
		.duration("s")
		.pipe(z.number().int().min(60).max(3600))
		.prefault("10m")
		.describe("How long a round trip, or a held login's tokens, may wait, from 1m to 1h."),
	requests: z
		.number()
		.int()
		.min(1)
		.max(1000)
		.prefault(60)
		.describe("Starts and callbacks allowed per source in each window."),
	window: setting
		.duration("s")
		.pipe(z.number().int().min(1).max(3600))
		.prefault("1m")
		.describe("The window `requests` counts in, from 1s to 1h."),
});

export type Settings = z.output<typeof section>;
