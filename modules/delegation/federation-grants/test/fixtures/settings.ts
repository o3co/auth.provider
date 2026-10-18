const conn = { idp: "corp", scopes: ["openid"], "max-access-token-lifetime": "1h" };

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
		settings: { "revocation-skew": "300s" },
		ok: true,
	},
	{
		name: "an allowance for clocks past 300 seconds",
		settings: { "revocation-skew": "301s" },
		ok: false,
	},
	{
		name: "an access token's longest life past a day",
		settings: { connections: { cal: { ...conn, "max-access-token-lifetime": "86401s" } } },
		ok: false,
	},
	{ name: "a connection time under a minute", settings: { "connect-lifetime": "59s" }, ok: false },
	{ name: "a connection time past an hour", settings: { "connect-lifetime": "3601s" }, ok: false },
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
	{
		name: "a window written as a bare number",
		// What an operator may write, though the section's input type takes a string.
		settings: { window: 60 } as never,
		refused: "federation-grants.window: written with its unit, such as 30s",
	},
	{
		name: "a window written as digits alone",
		settings: { window: "60" },
		refused: "federation-grants.window: duration must name its unit",
	},
	{
		name: "a window given under its name in seconds beside its name with a unit",
		settings: { "window-seconds": 60, window: "1m" },
		refused: "federation-grants.window-seconds: names window again, in seconds; write window alone",
	},
	{
		name: "a connection giving its longest access token life under both its names",
		settings: {
			connections: {
				cal: { ...conn, "max-access-token-seconds": 3600, "max-access-token-lifetime": "1h" },
			},
		},
		refused:
			"federation-grants.connections.cal.max-access-token-seconds: names max-access-token-lifetime again, in seconds; write max-access-token-lifetime alone",
	},
] as const;
