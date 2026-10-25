import { join } from "node:path";
import type { AdapterCommand } from "../dialog/dialog.ts";

/** A flow an adapter runs, by the name its instruction gives. */
export const flows = [
	"login",
	"public-login",
	"refresh",
	"resource",
	"client-credentials",
	"revocation",
	"dpop",
	"device",
	"logout",
	"jwt-bearer",
	"token-exchange",
	"mtls",
	"backchannel-logout",
] as const;
export type Flow = (typeof flows)[number];

/** A client library the harness runs: its adapter, how it is built, and the flows it runs first-class. */
export interface Library {
	readonly name: string;
	readonly flows: readonly Flow[];
	/** Commands that build the adapter, run in order in the package's directory; none where it needs no build. */
	readonly build: readonly (readonly string[])[];
	/** How the adapter starts; it takes the front's certificate from its instruction. */
	adapter(): AdapterCommand;
}

const packageDir = join(import.meta.dirname, "..", "..");
const path = () => ({ PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "" });
const java = () => (process.env.JAVA_HOME ? join(process.env.JAVA_HOME, "bin", "java") : "java");

export const libraries: readonly Library[] = [
	{
		name: "openid-client",
		flows: [
			"login",
			"public-login",
			"refresh",
			"resource",
			"client-credentials",
			"revocation",
			"dpop",
			"device",
			"logout",
		],
		build: [],
		adapter: () => ({
			command: process.execPath,
			args: [join(packageDir, "adapters", "openid-client", "main.ts")],
			cwd: packageDir,
			env: path(),
		}),
	},
	{
		name: "nimbus",
		flows: [
			"login",
			"public-login",
			"refresh",
			"resource",
			"client-credentials",
			"revocation",
			"dpop",
			"device",
			"logout",
			"jwt-bearer",
			"token-exchange",
			"mtls",
			"backchannel-logout",
		],
		// The runtime jars are checked against their pins before anything is compiled or shaded from them.
		build: [
			[
				"mvn",
				"-B",
				"-q",
				"-f",
				join("adapters", "nimbus", "pom.xml"),
				"dependency:copy-dependencies",
			],
			[process.execPath, join("src", "main.ts"), "verify-jars", join("adapters", "nimbus")],
			["mvn", "-B", "-q", "-f", join("adapters", "nimbus", "pom.xml"), "package"],
		],
		adapter: () => ({
			command: java(),
			args: ["-jar", join(packageDir, "adapters", "nimbus", "target", "nimbus-adapter.jar")],
			cwd: packageDir,
			env: path(),
		}),
	},
];

/** The library of that name; any other is refused, naming those there are. */
export function libraryNamed(name: string | undefined): Library {
	const found = libraries.find((l) => l.name === name);
	if (!found)
		throw new Error(`${name}: no such library (${libraries.map((l) => l.name).join(", ")})`);
	return found;
}
