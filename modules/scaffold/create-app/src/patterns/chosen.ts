/** What each axis's choice asks of the deployment, told from the modules composed, not the pattern's default. */
const told: readonly (readonly [string, string])[] = [
	[
		"@mod/store",
		"Store in memory: one instance only (`kernel.deployment = single`), the memory store accepted (`store.accept-volatile = true`).",
	],
	["@mod/redis", "Store in Redis (`redis.url`, `redis.replication`)."],
	[
		"@mod/users-http",
		"Users from an outside ledger (`users-http.verify-url`, `users-http.credential`).",
	],
	[
		"@mod/audit-http",
		"Audit events posted to a receiver (`audit-http.url`, `audit.receivers = [http]`).",
	],
	[
		"@mod/mail-smtp",
		"Mail through an SMTP relay (`mail-smtp.host`, `mail-smtp.from`; `mail-smtp.user` and `mail-smtp.password` in the local layer when it asks).",
	],
	["@mod/mail", "No mail is sent (`mail.accept-unsent = true`)."],
];
/** Said when the owner is composed and no adapter of it is. */
const ownerOnly: readonly (readonly [string, string, string])[] = [
	["@mod/users", "@mod/users-http", "Users in the configuration (`users.registered`)."],
	["@mod/audit", "@mod/audit-http", "Audit events to the log (`audit.receivers = [log]`)."],
];

/** One line for each choice the composed modules show. */
export function chosenLines(modules: readonly string[]): string[] {
	return [
		...told.filter(([name]) => modules.includes(name)).map(([, line]) => `- ${line}`),
		...ownerOnly
			.filter(([owner, adapter]) => modules.includes(owner) && !modules.includes(adapter))
			.map(([, , line]) => `- ${line}`),
	];
}
