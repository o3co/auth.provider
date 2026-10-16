import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { a2a } from "./a2a.ts";
import { device } from "./device.ts";
import { mfaWeb } from "./mfa-web.ts";
import { nativeApp } from "./native-app.ts";
import type { Pattern } from "./pattern.ts";
import { simpleWeb } from "./simple-web.ts";
import { ssoFederated } from "./sso-federated.ts";

/** The patterns besides full, which is `combinations`' full template itself. */
const known: readonly Pattern[] = [simpleWeb, mfaWeb, device, nativeApp, a2a, ssoFederated];

export const fullName = "full";

/** A pattern's name, its use and the conformance areas run against its app. */
export interface PatternSummary {
	readonly name: string;
	readonly use: string;
	readonly areas: readonly string[];
	/** What conformance adds for the pattern's run; none when left out. */
	readonly conformanceAdd?: readonly string[];
}

const fullSummary: PatternSummary = {
	name: fullName,
	use:
		"Every feature that does not opt in, as the previous release composed by default, with its " +
		"store in Redis, users from an outside ledger and audit events posted to a receiver.",
	areas: [
		"keys",
		"identity",
		"code",
		"oauth",
		"second-factor",
		"device",
		"mtls",
		"passkey",
		"exchange",
		"ops",
	],
	conformanceAdd: [],
};

export function patterns(): PatternSummary[] {
	return [
		...known.map(({ name, use, areas, conformanceAdd }) => ({ name, use, areas, conformanceAdd })),
		fullSummary,
	];
}

/** The pattern of this name; one not known is refused, naming those that are. */
export function patternNamed(name: string): Pattern {
	const found = known.find((p) => p.name === name);
	if (!found) {
		const names = patterns().map((p) => p.name);
		throw new Error(`${name}: no such pattern (${names.join(", ")})`);
	}
	return found;
}

/** The pattern's card without its title: what it composes, and what the deployment provides. */
export async function cardOf(name: string): Promise<string> {
	const card = await readFile(join(import.meta.dirname, `${name}.md`), "utf8");
	return card.split("\n").slice(1).join("\n").trim();
}
