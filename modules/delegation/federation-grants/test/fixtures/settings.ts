const conn = { idp: "corp", scopes: ["openid"], "max-access-token-seconds": 3600 };

/** An operator section, and whether it is taken. */
export const sectionCases = [
	{ name: "a connection named in lower case", settings: { connections: { cal: conn } }, ok: true },
	{ name: "a connection name in upper case", settings: { connections: { Cal: conn } }, ok: false },
	{
		name: "a connection name starting with a dash",
		settings: { connections: { "-cal": conn } },
		ok: false,
	},
	{ name: "a page at http", settings: { page: "http://issuer.example/page" }, ok: false },
	{
		name: "an allowance for clocks of 300 seconds",
		settings: { "revocation-skew-seconds": 300 },
		ok: true,
	},
	{
		name: "an allowance for clocks past 300 seconds",
		settings: { "revocation-skew-seconds": 301 },
		ok: false,
	},
	{
		name: "an access token's longest life past a day",
		settings: { connections: { cal: { ...conn, "max-access-token-seconds": 86_401 } } },
		ok: false,
	},
	{ name: "a connection time under a minute", settings: { "connect-seconds": 59 }, ok: false },
	{ name: "a connection time past an hour", settings: { "connect-seconds": 3601 }, ok: false },
] as const;

/** A composition the boot refuses, and the refusal as `where: reason`. */
export const bootCases = [
	{
		name: "connections without the page that asks the user",
		settings: { page: undefined },
		refused: "federation-grants: connections need the page that asks the user",
	},
	{
		name: "connections without the public origin",
		origin: null,
		refused: "federation-grants: connections need the public origin",
	},
	{
		name: "a connection whose IdP offers no delegation",
		settings: { connections: { cal: { ...conn, idp: "other" } } },
		refused: "federation-grants.connections.cal: the IdP other offers no delegation",
	},
] as const;
