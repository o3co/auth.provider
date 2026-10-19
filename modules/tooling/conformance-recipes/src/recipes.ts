/** The generate command of each recipe, after the target directory: one constant shown and run. */
export const commands = {
	/** Password login, TOTP as the only second factor, users from an HTTP ledger, Redis. */
	"mfa-page": [
		"--pattern",
		"simple-web",
		"--axis",
		"@mod/store=@mod/redis",
		"--axis",
		"@mod/users=@mod/users-http",
		"--second-factor",
		"@mod/mfa,@mod/mfa-flows,@mod/mfa-totp",
	],
} as const satisfies Record<string, readonly string[]>;

/** The command as a reader types it, from the published entrance. */
export const shownCommand = (argv: readonly string[]) =>
	["npx @o3co/create-auth-provider@next my-provider", ...argv].join(" ");
