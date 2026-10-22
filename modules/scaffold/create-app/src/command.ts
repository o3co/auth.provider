import { parseArgs } from "node:util";
import { addable } from "@mod/combinations";
import { generate, type Plan } from "./generate.ts";
import { type Group, groups } from "./patterns/pattern.ts";

/** How a package outside the release is named on the command line. */
const npm = "npm:";

/** Runs the command on its arguments, writing to `io`: 0 once the project is written or `--help` or `--list` told, 64 for a usage error, 1 for a plan it cannot make. */
export async function run(
	args: readonly string[],
	io: { readonly out: (text: string) => void; readonly err: (text: string) => void } = {
		out: (text) => process.stdout.write(text),
		err: (text) => process.stderr.write(text),
	},
): Promise<number> {
	const usageText =
		"usage: create-auth-provider <target> [--workspace <root>] [--pattern <name>] [--add <feature>]...\n" +
		"         [--axis <owner>=<module>]... [--<group> <feature>,...]...\n" +
		`         groups: ${groups.join(", ")}; axes and groups need a pattern other than full\n` +
		"       create-auth-provider <target> [--workspace <root>] [--sink <package>] <package>...\n" +
		"       create-auth-provider --list   (each name --add takes)\n" +
		"       a package outside the release is named npm:<name> (a package, --add, an axis's module),\n" +
		"         read from --outside-from <project>, where pnpm installed it; --allow-fresh <name> lets\n" +
		"         one published within the last day be installed\n";
	const usage = (): number => {
		io.err(usageText);
		return 64;
	};

	const groupOptions = Object.fromEntries(
		groups.map((group) => [group, { type: "string" }]),
	) as Record<Group, { type: "string" }>;
	const options = {
		help: { type: "boolean", short: "h" },
		list: { type: "boolean" },
		workspace: { type: "string" },
		sink: { type: "string" },
		pattern: { type: "string" },
		add: { type: "string", multiple: true },
		axis: { type: "string", multiple: true },
		"outside-from": { type: "string" },
		"allow-fresh": { type: "string", multiple: true },
		...groupOptions,
	} as const;
	const parse = () => parseArgs({ args: [...args], allowPositionals: true, options });
	let parsed: ReturnType<typeof parse>;
	try {
		parsed = parse();
	} catch (error) {
		// An option not known, or one missing its value: told, then the usage.
		io.err(`${(error as Error).message}\n`);
		return usage();
	}
	const { values, positionals } = parsed;
	if (values.help) {
		io.out(usageText);
		return 0;
	}
	if (values.list) {
		if (positionals.length > 0) return usage();
		io.out(`${addable().join("\n")}\n`);
		return 0;
	}
	// A package outside the release is named `npm:<name>`; the plan takes the name, and reads it from the project given.
	const unprefixed = (name: string) => (name.startsWith(npm) ? name.slice(npm.length) : name);
	const [target, ...given] = positionals;
	const pattern = values.pattern ?? "full";
	const axisPairs = (values.axis ?? []).map((pair) => pair.split("="));
	// An axis given twice takes the last choice, as the plan does: only that one is a name the plan reads.
	const lastChoices = new Map(axisPairs.map((pair) => [pair[0] ?? "", pair]));
	const named = [
		...given,
		...(values.add ?? []),
		...[...lastChoices.values()].flatMap((pair) => pair.slice(1)),
	];
	const outsideNames = named.filter((name) => name.startsWith(npm)).map(unprefixed);
	const modules = given.map(unprefixed);
	const added = values.add?.map(unprefixed);
	const axes = axisPairs.map(([owner, ...rest]) => [owner ?? "", ...rest.map(unprefixed)]);
	const chosen = groups.flatMap((group) => {
		const listed = values[group];
		return typeof listed === "string" ? [[group, listed.split(",")] as const] : [];
	});
	// Packages listed make the app of those; none makes a pattern's, full when none is named.
	const listed = modules.length > 0;
	const patterned = values.add || values.pattern || axes.length > 0 || chosen.length > 0;
	const malformedAxis = axes.some((pair) => pair.length !== 2 || pair.includes(""));
	const emptyName = chosen.some(([, names]) => names.includes(""));
	const choiceForFull = pattern === "full" && (axes.length > 0 || chosen.length > 0);
	if (
		!target ||
		(listed && patterned) ||
		(!listed && values.sink) ||
		malformedAxis ||
		emptyName ||
		choiceForFull
	) {
		return usage();
	}
	const from = values["outside-from"];
	const fresh = values["allow-fresh"] ?? [];
	const misnamed = [
		...(outsideNames.includes("") ? [`${npm} names no package: write npm:<name>`] : []),
		...(outsideNames.length > 0 && from === undefined
			? [`${npm}<name> is read from --outside-from <project>`]
			: []),
		...(outsideNames.length === 0 && from !== undefined
			? ["--outside-from names no package: none is named npm:<name>"]
			: []),
		...(outsideNames.length > 0 && values.workspace
			? ["a linked workspace composes no package outside the release"]
			: []),
		...fresh
			.filter((name) => !outsideNames.includes(name))
			.map((name) => `--allow-fresh ${name}: not named npm:${name}`),
	];
	if (misnamed.length > 0) {
		io.err(`${misnamed.join("\n")}\n`);
		return usage();
	}
	const workspace = values.workspace ? { workspace: values.workspace } : {};
	const add = added ? { add: added } : {};
	const outside =
		from === undefined
			? {}
			: {
					outside: {
						from,
						names: [...new Set(outsideNames)],
						...(fresh.length > 0 ? { fresh } : {}),
					},
				};

	function planOf(target: string): Plan {
		if (listed)
			return {
				target,
				modules,
				...workspace,
				...outside,
				...(values.sink ? { sink: values.sink } : {}),
			};
		if (pattern === "full") return { target, template: "full", ...workspace, ...add, ...outside };
		return {
			target,
			template: pattern,
			...workspace,
			...add,
			...outside,
			...(axes.length > 0 ? { axes: Object.fromEntries(axes) } : {}),
			...(chosen.length > 0 ? { features: Object.fromEntries(chosen) } : {}),
		};
	}

	try {
		await generate(planOf(target ?? ""));
	} catch (error) {
		// A plan the workspace cannot make, told by its message alone.
		io.err(`${(error as Error).message}\n`);
		return 1;
	}
	io.out(`created ${target}\nnext: cd ${target} and follow its README.md\n`);
	return 0;
}
