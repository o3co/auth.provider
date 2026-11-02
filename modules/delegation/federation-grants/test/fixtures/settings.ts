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
	// The browser half's, in federation-grants-connect's section since it moved out.
	...(["page", "login-page", "step-up-page", "identity-check"] as const).map((key) => ({
		name: `${key}, the browser half's`,
		settings: { [key]: key === "identity-check" ? "none" : "https://issuer.example/x" },
		ok: false,
	})),
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
		name: "no browser half to answer its browser routes",
		browserHalf: null,
		refused: "federation-grants.browsers: needs exactly one contribution (0)",
	},
	{
		name: "connections without the public origin",
		origin: null,
		refused: "federation-grants: connections need the public origin",
	},
	{
		name: "a connection whose IdP offers no delegation",
		settings: { connections: { cal: { ...conn, idp: "other" } } },
		refused: "federation-grants.connections.cal.idp: the IdP it names offers no delegation",
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
] as const;
