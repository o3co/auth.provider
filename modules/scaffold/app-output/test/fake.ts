import {
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
};

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
	};
}
