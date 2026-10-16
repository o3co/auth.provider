import { urlSetting } from "@mod/url-setting";
import { z } from "zod";

export const name = "federation-grants";

/** A connection's name: its path segment, so it is one spelling. */
export const connectionName = z.string().regex(/^[a-z0-9][a-z0-9-]{0,31}$/);
/** A scope token (RFC 6749 §3.3). */
const scope = z.string().regex(/^[\x21\x23-\x5b\x5d-\x7e]+$/);
const page = urlSetting({ schemes: ["https"] });

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
	/** The longest an upstream access token may live to be kept. */
	"max-access-token-seconds": z.number().int().min(1).max(86_400),
	/** A client may ask for fewer of the scopes. */
	"scope-subsets": z.boolean().default(false),
});

export const section = z.strictObject({
	/** The page that asks the user, on this deployment's origin. */
	page: page.optional(),
	/** Where a browser with no session is sent to log in, then back. */
	"login-page": page.optional(),
	/** Where a session that falls short of a requirement is sent once to raise it, then back. */
	"step-up-page": page.optional(),
	connections: z.record(connectionName, connection).default({}),
	/** A grant's lifetime from its activation: what a client asks for none, and the most it may. */
	"default-seconds": z.number().int().min(60).max(31_536_000).default(2_592_000),
	"max-seconds": z.number().int().min(60).max(31_536_000).default(2_592_000),
	/** How long a connection may take, from the intent to the callback. */
	"connect-seconds": z.number().int().min(60).max(3600).default(600),
	/** A token this close to its end is refreshed, once half its life is spent. */
	"refresh-before-seconds": z.number().int().min(0).max(3600).default(30),
	/** Upstream refreshes a grant may take in each window. */
	rotations: z.number().int().min(1).max(1000).default(24),
	"rotation-window-seconds": z.number().int().min(1).max(86_400).default(3600),
	/** Intents a client may lodge in each window, whatever subject it names. */
	lodges: z.number().int().min(1).max(100_000).default(60),
	"lodge-window-seconds": z.number().int().min(1).max(86_400).default(60),
	/** How far apart hosts' clocks may be: a grant made this soon after its subject's revocation counts as revoked. */
	"revocation-skew-seconds": z.number().int().min(0).max(300).default(1),
	/** A subject's revocation may be asked to leave its established grants. */
	"keep-on-subject-revocation": z.boolean().default(false),
	/** Whether a callback refuses an upstream account another user holds. */
	"identity-check": z.enum(["required", "none"]).default("required"),
	/** Requests allowed per source in each window, on every route. */
	requests: z.number().int().min(1).max(1000).default(60),
	"window-seconds": z.number().int().min(1).max(3600).default(60),
});

export type Settings = z.output<typeof section>;
export type Connection = Settings["connections"][string];
