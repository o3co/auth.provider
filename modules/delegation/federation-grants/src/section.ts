import { setting } from "@mod/kernel";
import { urlSetting } from "@mod/url-setting";
import { z } from "zod";

export const name = "federation-grants";

/** A connection's name: its path segment, so it is one spelling. */
export const connectionName = z.string().regex(/^[a-z0-9][a-z0-9-]{0,31}$/);
/** A scope token (RFC 6749 §3.3). */
const scope = z.string().regex(/^[\x21\x23-\x5b\x5d-\x7e]+$/);
const page = urlSetting({ schemes: ["https"], loopbackHttp: true });

/** A time read in whole seconds, written with its unit, within its bounds. */
const seconds = (min: number, max: number) =>
	setting.duration("s").pipe(z.number().int().min(min).max(max));

/** One connection: what a grant may be for. */
const connection = z.strictObject({
	/** The IdP, by `federation`'s name, whose delegation it uses. */
	idp: connectionName,
	/** What the user may be asked for; `openid` among them. */
	scopes: z
		.array(scope)
		.min(1)
		.refine((all) => all.includes("openid"), "scopes must hold openid"),
	resource: z.url().optional(),
	"max-access-token-lifetime": seconds(1, 86_400).describe(
		"The longest an upstream access token may live to be kept: a duration with a unit, from 1s to 1d, e.g. 1h.",
	),
	/** A client may ask for fewer of the scopes. */
	"scope-subsets": z.boolean().prefault(false),
});

export const section = z.strictObject({
	page: page
		.optional()
		.describe(
			"The page that asks the user, on this deployment's origin: an https URL (http only on a loopback host).",
		),
	"login-page": page
		.optional()
		.describe(
			"Where a browser with no session is sent to log in, then back: an https URL (http only on a loopback host).",
		),
	"step-up-page": page
		.optional()
		.describe(
			"Where a session that falls short of a requirement is sent once to raise it, then back: an https URL (http only on a loopback host).",
		),
	connections: z
		.record(connectionName, connection)
		.prefault({})
		.describe(
			"What a grant may be for, by a name (a-z, 0-9 and -, at most 32): idp (a federation IdP that offers delegation), scopes (holding openid), resource, max-access-token-lifetime and scope-subsets.",
		),
	"default-lifetime": seconds(60, 31_536_000)
		.prefault("30d")
		.describe(
			"A grant's lifetime from its activation when a client asks for none: a duration with a unit, from 1m to 365d, e.g. 30d.",
		),
	"max-lifetime": seconds(60, 31_536_000)
		.prefault("30d")
		.describe(
			"The most a grant may live from its activation: a duration with a unit, from 1m to 365d, e.g. 90d.",
		),
	"connect-lifetime": seconds(60, 3600)
		.prefault("10m")
		.describe(
			"How long a connection may take, from the intent to the callback: a duration with a unit, from 1m to 1h, e.g. 10m.",
		),
	"refresh-before": seconds(0, 3600)
		.prefault("30s")
		.describe(
			"A token this close to its end is refreshed, once half its life is spent: a duration with a unit, from 0s to 1h, e.g. 30s.",
		),
	rotations: z
		.number()
		.int()
		.min(1)
		.max(1000)
		.prefault(24)
		.describe("Upstream refreshes a grant may take in each rotation-window, from 1 to 1000."),
	"rotation-window": seconds(1, 86_400)
		.prefault("1h")
		.describe(
			"The window a grant's upstream refreshes are counted in: a duration with a unit, from 1s to 1d, e.g. 1h.",
		),
	lodges: z
		.number()
		.int()
		.min(1)
		.max(100_000)
		.prefault(60)
		.describe(
			"Intents a client may lodge or renew in each lodge-window, together, whatever subject it names, from 1 to 100000.",
		),
	"lodge-window": seconds(1, 86_400)
		.prefault("1m")
		.describe(
			"The window a client's lodged and renewed intents are counted in: a duration with a unit, from 1s to 1d, e.g. 1m.",
		),
	"revocation-skew": seconds(0, 300)
		.prefault("1s")
		.describe(
			"How far apart hosts' clocks may be: a grant made this soon after its subject's revocation counts as revoked. A duration with a unit, from 0s to 5m, e.g. 1s.",
		),
	"sweep-interval": seconds(60, 86_400)
		.prefault("1h")
		.describe(
			"How often each host walks every grant kept, erasing the credentials of one past its end or ended by its subject's revocation though no request reads it: a duration with a unit, from 1m to 1d, e.g. 1h.",
		),
	"keep-on-subject-revocation": z
		.boolean()
		.prefault(false)
		.describe("Whether a subject's revocation may be asked to leave its established grants."),
	"identity-check": z
		.enum(["required", "none"])
		.prefault("required")
		.describe(
			"required refuses a callback whose upstream account another user holds; none does not check.",
		),
	requests: z
		.number()
		.int()
		.min(1)
		.max(1000)
		.prefault(60)
		.describe("Requests allowed per source in each window, on every route, from 1 to 1000."),
	window: seconds(1, 3600)
		.prefault("1m")
		.describe(
			"The window a source's requests are counted in, on every route: a duration with a unit, from 1s to 1h, e.g. 1m.",
		),
});

export type Settings = z.output<typeof section>;
export type Connection = Settings["connections"][string];
