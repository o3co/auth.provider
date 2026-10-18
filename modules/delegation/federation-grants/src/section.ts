import { setting } from "@mod/kernel";
import { urlSetting } from "@mod/url-setting";
import { z } from "zod";

export const name = "federation-grants";

/** A connection's name: its path segment, so it is one spelling. */
export const connectionName = z.string().regex(/^[a-z0-9][a-z0-9-]{0,31}$/);
/** A scope token (RFC 6749 §3.3). */
const scope = z.string().regex(/^[\x21\x23-\x5b\x5d-\x7e]+$/);
const page = urlSetting({ schemes: ["https"] });

/** A time read in whole seconds, written with its unit, within its bounds. */
const seconds = (min: number, max: number) =>
	setting.duration("s").pipe(z.number().int().min(min).max(max));

/** A key named before its unit was written: read in place of its new name while its writers move. */
const before = (min: number, max: number, instead: string) =>
	z
		.number()
		.int()
		.min(min)
		.max(max)
		.optional()
		.describe(`Deprecated: seconds, as a bare number; write \`${instead}\` with its unit instead.`);

/** Refuses a key given under both its names: the value in seconds would silently win or lose. */
const oneNameEach =
	<Raw>(renamed: Readonly<Record<string, string>>) =>
	(raw: Raw, context: z.RefinementCtx) => {
		if (typeof raw !== "object" || raw === null) return raw;
		for (const [old, now] of Object.entries(renamed)) {
			if (Object.hasOwn(raw, old) && Object.hasOwn(raw, now)) {
				context.addIssue({
					code: "custom",
					path: [old],
					message: `names ${now} again, in seconds; write ${now} alone`,
					input: raw,
				});
			}
		}
		return raw;
	};

const connectionKeys = z.strictObject({
	/** The IdP, by `federation`'s name, whose delegation it uses. */
	idp: connectionName,
	/** What the user may be asked for; `openid` among them. */
	scopes: z
		.array(scope)
		.min(1)
		.refine((all) => all.includes("openid"), "scopes must hold openid"),
	resource: z.url().optional(),
	"max-access-token-lifetime": seconds(1, 86_400)
		.optional()
		.describe(
			"The longest an upstream access token may live to be kept: a duration with a unit, from 1s to 1d, e.g. 1h. Required.",
		),
	/** A client may ask for fewer of the scopes. */
	"scope-subsets": z.boolean().prefault(false),
	"max-access-token-seconds": before(1, 86_400, "max-access-token-lifetime"),
});

/** One connection: what a grant may be for. */
const connection = z.preprocess(
	oneNameEach<z.input<typeof connectionKeys>>({
		"max-access-token-seconds": "max-access-token-lifetime",
	}),
	connectionKeys.transform(({ "max-access-token-seconds": inSeconds, ...read }, context) => {
		const lifetime = inSeconds ?? read["max-access-token-lifetime"];
		if (lifetime === undefined) {
			context.addIssue({
				code: "custom",
				path: ["max-access-token-lifetime"],
				message: "required: a duration with a unit, such as 1h",
				input: read,
			});
			return z.NEVER;
		}
		return { ...read, "max-access-token-lifetime": lifetime };
	}),
);

const keys = z.strictObject({
	/** The page that asks the user, on this deployment's origin. */
	page: page.optional(),
	/** Where a browser with no session is sent to log in, then back. */
	"login-page": page.optional(),
	/** Where a session that falls short of a requirement is sent once to raise it, then back. */
	"step-up-page": page.optional(),
	connections: z.record(connectionName, connection).prefault({}),
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
	/** Upstream refreshes a grant may take in each window. */
	rotations: z.number().int().min(1).max(1000).prefault(24),
	"rotation-window": seconds(1, 86_400)
		.prefault("1h")
		.describe(
			"The window a grant's upstream refreshes are counted in: a duration with a unit, from 1s to 1d, e.g. 1h.",
		),
	/** Intents a client may lodge in each window, whatever subject it names. */
	lodges: z.number().int().min(1).max(100_000).prefault(60),
	"lodge-window": seconds(1, 86_400)
		.prefault("1m")
		.describe(
			"The window a client's lodged intents are counted in: a duration with a unit, from 1s to 1d, e.g. 1m.",
		),
	"revocation-skew": seconds(0, 300)
		.prefault("1s")
		.describe(
			"How far apart hosts' clocks may be: a grant made this soon after its subject's revocation counts as revoked. A duration with a unit, from 0s to 5m, e.g. 1s.",
		),
	/** A subject's revocation may be asked to leave its established grants. */
	"keep-on-subject-revocation": z.boolean().prefault(false),
	/** Whether a callback refuses an upstream account another user holds. */
	"identity-check": z.enum(["required", "none"]).prefault("required"),
	/** Requests allowed per source in each window, on every route. */
	requests: z.number().int().min(1).max(1000).prefault(60),
	window: seconds(1, 3600)
		.prefault("1m")
		.describe(
			"The window a source's requests are counted in, on every route: a duration with a unit, from 1s to 1h, e.g. 1m.",
		),
	"default-seconds": before(60, 31_536_000, "default-lifetime"),
	"max-seconds": before(60, 31_536_000, "max-lifetime"),
	"connect-seconds": before(60, 3600, "connect-lifetime"),
	"refresh-before-seconds": before(0, 3600, "refresh-before"),
	"rotation-window-seconds": before(1, 86_400, "rotation-window"),
	"lodge-window-seconds": before(1, 86_400, "lodge-window"),
	"revocation-skew-seconds": before(0, 300, "revocation-skew"),
	"window-seconds": before(1, 3600, "window"),
});

/** Each name in seconds, and the name with a unit that replaces it. */
const renamed = {
	"default-seconds": "default-lifetime",
	"max-seconds": "max-lifetime",
	"connect-seconds": "connect-lifetime",
	"refresh-before-seconds": "refresh-before",
	"rotation-window-seconds": "rotation-window",
	"lodge-window-seconds": "lodge-window",
	"revocation-skew-seconds": "revocation-skew",
	"window-seconds": "window",
} as const;

export const section = z.preprocess(
	oneNameEach<z.input<typeof keys>>(renamed),
	keys.transform(
		({
			"default-seconds": defaultSeconds,
			"max-seconds": maxSeconds,
			"connect-seconds": connectSeconds,
			"refresh-before-seconds": refreshBeforeSeconds,
			"rotation-window-seconds": rotationWindowSeconds,
			"lodge-window-seconds": lodgeWindowSeconds,
			"revocation-skew-seconds": revocationSkewSeconds,
			"window-seconds": windowSeconds,
			...read
		}) => ({
			...read,
			"default-lifetime": defaultSeconds ?? read["default-lifetime"],
			"max-lifetime": maxSeconds ?? read["max-lifetime"],
			"connect-lifetime": connectSeconds ?? read["connect-lifetime"],
			"refresh-before": refreshBeforeSeconds ?? read["refresh-before"],
			"rotation-window": rotationWindowSeconds ?? read["rotation-window"],
			"lodge-window": lodgeWindowSeconds ?? read["lodge-window"],
			"revocation-skew": revocationSkewSeconds ?? read["revocation-skew"],
			window: windowSeconds ?? read.window,
		}),
	),
);

export type Settings = z.output<typeof section>;
export type Connection = Settings["connections"][string];
