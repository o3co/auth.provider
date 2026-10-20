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
	["@mod/audit-http", "Audit events posted to a receiver (`audit-http.url`)."],
	[
		"@mod/mail-smtp",
		"Mail through an SMTP relay (`mail-smtp.host`, `mail-smtp.from`; `mail-smtp.user` and `mail-smtp.password` in the local layer when it asks).",
	],
	["@mod/mail", "No mail is sent (`mail.accept-unsent = true`)."],
];
/** Said when the owner is composed and no adapter of it is. */
const ownerOnly: readonly (readonly [string, string, string])[] = [
	["@mod/users", "@mod/users-http", "Users in the configuration (`users.registered`)."],
];

/** The receiver each audit adapter registers under. */
const receivers: readonly (readonly [string, string])[] = [
	["@mod/audit-http", "http"],
	["@mod/audit-stdout", "stdout"],
];

/** The receivers to name in `audit.receivers`: each composed adapter's, or audit's own `log` when none is. */
export function auditReceiversOf(composed: (module: string) => boolean): string[] {
	const named = receivers.filter(([module]) => composed(module)).map(([, name]) => name);
	return named.length > 0 ? named : ["log"];
}

/** The receivers `audit.receivers` names, as the README writes them. */
export function auditReceiversLine(modules: readonly string[]): string {
	return auditReceiversOf((m) => modules.includes(m))
		.map((name) =>
			name === "log" ? "`log`, audit's own, writing events to the log" : `\`${name}\``,
		)
		.join(", ");
}

/** One line for each choice the composed modules show. */
export function chosenLines(modules: readonly string[]): string[] {
	return [
		...told.filter(([name]) => modules.includes(name)).map(([, line]) => `- ${line}`),
		...ownerOnly
			.filter(([owner, adapter]) => modules.includes(owner) && !modules.includes(adapter))
			.map(([, , line]) => `- ${line}`),
		...(modules.includes("@mod/federation") && modules.includes("@mod/users-http")
			? [
					"- A federation login finds its user through the ledger's lookup by subject (`users-http.subject-url`), or by upstream identity (`users-http.upstream-url`).",
				]
			: []),
		...(modules.includes("@mod/federation") && modules.includes("@mod/mfa-flows")
			? [
					"- A federation login a second factor holds goes on at `federation.held-page`, a page on the public origin; without it, the browser stops at the factor's answer.",
				]
			: []),
		...(modules.includes("@mod/audit")
			? [
					`- Audit events named in \`audit.receivers = [${auditReceiversOf((m) => modules.includes(m)).join(", ")}]\`.`,
				]
			: []),
	];
}
