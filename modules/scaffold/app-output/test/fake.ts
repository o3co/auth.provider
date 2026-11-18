import type { Declaring } from "@mod/app-entries";
import {
	type Asked,
	type Card,
	fragmentsOf,
	type OutsideModules,
	type Packages,
	type Release,
} from "../src/contract.ts";

const fragmentTexts: Readonly<Record<string, string>> = {
	"@mod/kernel": "kernel { deployment = single }",
	"@mod/http": 'http { host = "127.0.0.1", port = 8080 }',
	"@mod/clients": 'clients { redirect-uris = ["https://app.example.invalid/cb"] }',
	"@mod/keys":
		'keys { signing { kid = "k1", private-key = """-----BEGIN PRIVATE KEY-----\nREPLACE\n-----END PRIVATE KEY-----""" } }',
};

/** What the modules above declare for the guide, as their manifests would. */
const declared: readonly Asked[] = [
	{
		name: "@mod/kernel",
		asks: [
			{
				line: "`kernel.deployment`: `single` for one instance, `multi` for several.",
				decides: true,
			},
		],
	},
	{
		name: "@mod/tokens",
		asks: [
			{
				line: "`tokens.revocation`: `denylist`, or `unsupported` to answer revocation as unsupported. With `unsupported`, a composed module that needs access tokens revocable refuses boot and says why.",
				decides: true,
			},
		],
	},
];

/** What packages standing for any declarer declare of the app's entries, one of each shape. */
const entries: readonly Declaring[] = [
	{
		name: "@mod/tool",
		appEntries: [{ script: "tool", shape: "call", contract: "toolRun", member: "run" }],
	},
	{
		name: "@mod/settler",
		appEntries: [
			{
				script: "settled",
				shape: "settle-subjects",
				contract: "settling",
				member: "settle",
				answers: ["done", "left"],
			},
		],
	},
	{
		name: "@mod/namer",
		appEntries: [{ script: "named", shape: "name-subjects", contract: "naming", member: "check" }],
	},
];

/** Packages as a caller would give them: the fragments above, published under `@o3co/x-`. */
export function fakePackages(
	release: Release = { version: "1.2.3" },
	asking: readonly string[] = [],
	outside?: OutsideModules,
): Packages {
	return {
		fragments: async (names) =>
			fragmentsOf(
				names.flatMap((name) => {
					const text = fragmentTexts[name];
					return text === undefined ? [] : [{ from: name, text }];
				}),
			),
		dependencies: (names) => Object.fromEntries(names.map((name) => [name, release.version])),
		importOf: (name) => name.replace("@mod/", "@o3co/x-"),
		cards: (names) =>
			names.map(
				(name): Card => ({
					name,
					card: `node_modules/${name}/README.md`,
					...(name === "@mod/http" ? { references: `node_modules/${name}/reference.conf` } : {}),
					...(asking.includes(name)
						? { deployment: `node_modules/${name}/README.md#deployment` }
						: {}),
				}),
			),
		release: () => release,
		...(outside ? { outside: () => outside } : {}),
		asks: (names) => declared.filter((d) => names.includes(d.name)),
		appEntries: (names) => entries.filter((d) => names.includes(d.name)),
	};
}
