/**
 * A client's call and its answer in a line (`status word description`, or `200 <token>`), with the
 * reason a denial is audited with: none for `""`, unchecked when absent.
 */
export interface RouteCase {
	readonly name: string;
	/** The grant the call names, as the test sets it up; a lodging when no step is given. */
	readonly grant?: "pending" | "active" | "revoked" | "expired" | "unknown";
	/** A grant id written as is, in place of the grant's. */
	readonly id?: string;
	readonly step?: string;
	readonly body?: Readonly<Record<string, unknown>>;
	readonly as?: string;
	/** The worker may no longer use the connection. */
	readonly disallowed?: boolean;
	/** The IdP no longer offers its delegation. */
	readonly withdrawn?: boolean;
	readonly settings?: Readonly<Record<string, unknown>>;
	readonly said: string;
	readonly audited?: string;
}

const scopes = ["openid", "offline_access", "read"];
const conn = { idp: "corp", scopes, "max-access-token-seconds": 3600 };
const renewal = { redirect_uri: "https://worker.example/connected", state: "r" };

export const routeCases: readonly RouteCase[] = [
	{ name: "lodging: a public client", as: "spa", said: "401 invalid_client" },
	{ name: "lodging: an unknown client", as: "nobody", said: "401 invalid_client" },
	{
		name: "lodging: a connection the client may not use",
		settings: { connections: { cal: conn, mail: conn } },
		body: { connection: "mail" },
		said: "403 access_denied connection_not_permitted",
		audited: "connection_not_permitted",
	},
	{
		name: "lodging: a return URI not registered",
		body: { redirect_uri: "https://worker.example/connected/" },
		said: "400 invalid_request redirect_uri_not_registered",
		audited: "invalid_request",
	},
	{
		name: "lodging: no return URI",
		body: { redirect_uri: "" },
		said: "400 invalid_request redirect_uri_required",
	},
	{
		name: "lodging: no state",
		body: { state: "" },
		said: "400 invalid_request state_required",
		audited: "invalid_request",
	},
	{ name: "lodging: no subject", body: { sub: "" }, said: "400 invalid_request sub_required" },
	{
		name: "lodging: no connection",
		body: { connection: "" },
		said: "400 invalid_request connection_required",
	},
	{
		name: "lodging: a subject of another type",
		body: { sub: 7 },
		said: "400 invalid_request invalid_sub",
	},
	{
		name: "lodging: a name it does not take",
		body: { resource: "https://api.example/" },
		said: "400 invalid_request unexpected_parameter",
	},
	{
		name: "lodging: a scope wider than the connection's",
		body: { scope: "openid offline_access read write" },
		said: "400 invalid_scope scope_exceeded",
	},
	{
		name: "lodging: a scope that is no scope",
		body: { scope: "openid\toffline_access read" },
		said: "400 invalid_request invalid_scope",
	},
	{
		name: "lodging: a scope without offline_access",
		body: { scope: "openid read" },
		said: "400 invalid_scope offline_access_required",
	},
	{
		name: "lodging: fewer scopes where subsets are not allowed",
		body: { scope: "openid offline_access" },
		said: "400 invalid_scope scope_subsets_not_allowed",
	},
	{
		name: "lodging: a scope without openid",
		settings: { connections: { cal: { ...conn, "scope-subsets": true } } },
		body: { scope: "offline_access read" },
		said: "400 invalid_scope openid_required",
	},
	{
		name: "lodging: a lifetime below zero",
		body: { expires_in: -1 },
		said: "400 invalid_request invalid_expires_in",
	},
	{
		name: "lodging: a lifetime of zero",
		body: { expires_in: 0 },
		said: "400 invalid_request invalid_expires_in",
	},
	{
		name: "lodging: an IdP that no longer delegates",
		withdrawn: true,
		said: "503 temporarily_unavailable connection_not_configured",
	},
	{ name: "lodging: a client's own", said: "201" },

	{
		name: "token: an unknown grant",
		grant: "unknown",
		step: "token",
		said: "404 grant_not_found",
		audited: "grant_not_found",
	},
	{
		name: "token: no subject",
		grant: "active",
		step: "token",
		body: { sub: "" },
		said: "400 invalid_request sub_required",
		audited: "sub_required",
	},
	{
		name: "token: a name it does not take",
		grant: "active",
		step: "token",
		body: { audience: "x" },
		said: "400 invalid_request unexpected_parameter",
		audited: "unexpected_parameter",
	},
	{
		name: "token: a pending grant",
		grant: "pending",
		step: "token",
		said: "400 authorization_pending",
		audited: "authorization_pending",
	},
	{
		name: "token: a revoked grant",
		grant: "revoked",
		step: "token",
		said: "410 grant_revoked client",
		audited: "grant_revoked",
	},
	{
		name: "token: an expired grant",
		grant: "expired",
		step: "token",
		said: "410 grant_expired lifetime",
		audited: "grant_expired",
	},
	{
		name: "token: a client no longer allowed",
		grant: "active",
		step: "token",
		disallowed: true,
		said: "403 access_denied connection_not_permitted",
		audited: "connection_not_permitted",
	},
	{
		name: "token: another connection",
		grant: "active",
		step: "token",
		body: { connection: "mail" },
		said: "400 invalid_request connection_mismatch",
		audited: "connection_mismatch",
	},
	{
		name: "token: another resource",
		grant: "active",
		step: "token",
		body: { resource: "https://api.example/" },
		said: "400 invalid_target",
		audited: "invalid_target",
	},
	{
		name: "token: a scope wider than shown",
		grant: "active",
		step: "token",
		body: { scope: "openid write" },
		said: "400 invalid_scope",
		audited: "invalid_scope",
	},
	{
		name: "token: a scope that is no scope",
		grant: "active",
		step: "token",
		body: { scope: "openid\tread" },
		said: "400 invalid_scope",
		audited: "invalid_scope",
	},
	{
		name: "token: a min_ttl past the longest life",
		grant: "active",
		step: "token",
		body: { min_ttl: 3601 },
		said: "400 invalid_request min_ttl_out_of_range",
		audited: "min_ttl_out_of_range",
	},
	{
		name: "token: a min_ttl of the longest life",
		grant: "active",
		step: "token",
		body: { min_ttl: 3600 },
		said: "200 up-1",
		audited: "",
	},
	{
		name: "token: a narrower scope, answered with what is held",
		grant: "active",
		step: "token",
		body: { scope: "read" },
		said: "200 up-1",
	},
	{ name: "token: no grant id", id: "", step: "token", said: "404 not_found" },
	{ name: "token: more than a step", grant: "active", step: "token/more", said: "404 not_found" },
	...["constructor", "__proto__", "toString", "hasOwnProperty", "nothing"].map(
		(step): RouteCase => ({ name: `step: ${step}`, grant: "active", step, said: "404 not_found" }),
	),

	{ name: "status: a pending grant", grant: "pending", step: "status", said: "200" },
	{
		name: "status: a pending grant to a client no longer allowed",
		grant: "pending",
		step: "status",
		disallowed: true,
		said: "403 access_denied connection_not_permitted",
	},
	{
		name: "status: an active grant to a client no longer allowed",
		grant: "active",
		step: "status",
		disallowed: true,
		said: "200",
	},
	{
		name: "status: a name it does not take",
		grant: "pending",
		step: "status",
		body: { scope: "openid" },
		said: "400 invalid_request unexpected_parameter",
		audited: "",
	},
	{
		name: "status: an unknown grant",
		grant: "unknown",
		step: "status",
		said: "404 grant_not_found",
		audited: "",
	},
	{
		name: "revoke: an unknown grant",
		grant: "unknown",
		step: "revoke",
		said: "404 grant_not_found",
		audited: "",
	},
	{ name: "revoke: a pending grant", grant: "pending", step: "revoke", said: "204" },

	{
		name: "renewal: a pending grant",
		grant: "pending",
		step: "reauthorize",
		body: renewal,
		said: "400 authorization_pending",
	},
	{
		name: "renewal: a revoked grant",
		grant: "revoked",
		step: "reauthorize",
		body: renewal,
		said: "410 grant_revoked client",
	},
	{
		name: "renewal: a return not registered",
		grant: "active",
		step: "reauthorize",
		body: { ...renewal, redirect_uri: "https://worker.example/x" },
		said: "400 invalid_request redirect_uri_not_registered",
	},
	{
		name: "renewal: a client no longer allowed",
		grant: "active",
		step: "reauthorize",
		body: renewal,
		disallowed: true,
		said: "403 access_denied connection_not_permitted",
	},
	{
		name: "renewal: another connection",
		grant: "active",
		step: "reauthorize",
		body: { ...renewal, connection: "mail" },
		said: "400 invalid_request connection_mismatch",
	},
	{
		name: "renewal: the grant's connection",
		grant: "active",
		step: "reauthorize",
		body: { ...renewal, connection: "cal" },
		said: "201",
	},
];
