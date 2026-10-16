import { parseArgs } from "node:util";
import { generate, type Plan } from "./generate.ts";
import { type Group, groups } from "./patterns/pattern.ts";

/** Runs the command on its arguments, writing to `io`: 0 once the project is written, 64 for a usage error. */
export async function run(
	args: readonly string[],
	io: { readonly out: (text: string) => void; readonly err: (text: string) => void } = {
		out: (text) => process.stdout.write(text),
		err: (text) => process.stderr.write(text),
	},
): Promise<number> {
	const usage = (): number => {
		io.err(
			"usage: create-app <target> [--workspace <root>] [--pattern <name>] [--add <feature>]...\n" +
				"         [--axis <owner>=<module>]... [--<group> <feature>,...]...\n" +
				`         groups: ${groups.join(", ")}; axes and groups need a pattern other than full\n` +
				"       create-app <target> [--workspace <root>] [--sink <package>] <package>...\n",
		);
		return 64;
	};

	const groupOptions = Object.fromEntries(
		groups.map((group) => [group, { type: "string" }]),
	) as Record<Group, { type: "string" }>;
	const { values, positionals } = parseArgs({
		args: [...args],
		allowPositionals: true,
		options: {
			workspace: { type: "string" },
			sink: { type: "string" },
			pattern: { type: "string" },
			add: { type: "string", multiple: true },
			axis: { type: "string", multiple: true },
			...groupOptions,
		},
	});
	const [target, ...modules] = positionals;
	const pattern = values.pattern ?? "full";
	const axes = (values.axis ?? []).map((given) => given.split("="));
	const chosen = groups.flatMap((group) => {
		const listed = values[group];
		return typeof listed === "string" ? [[group, listed.split(",")] as const] : [];
	});
	// Packages listed make the app of those; none makes a pattern's, full when none is named.
	const listed = modules.length > 0;
	const patterned = values.add || values.pattern || axes.length > 0 || chosen.length > 0;
	const malformedAxis = axes.some((pair) => pair.length !== 2 || pair.includes(""));
	const choiceForFull = pattern === "full" && (axes.length > 0 || chosen.length > 0);
	if (
		!target ||
		(listed && patterned) ||
		(!listed && values.sink) ||
		malformedAxis ||
		choiceForFull
	) {
		return usage();
	}
	const workspace = values.workspace ? { workspace: values.workspace } : {};
	const add = values.add ? { add: values.add } : {};

	function planOf(target: string): Plan {
		if (listed)
			return { target, modules, ...workspace, ...(values.sink ? { sink: values.sink } : {}) };
		if (pattern === "full") return { target, template: "full", ...workspace, ...add };
		return {
			target,
			template: pattern,
			...workspace,
			...add,
			...(axes.length > 0 ? { axes: Object.fromEntries(axes) } : {}),
			...(chosen.length > 0 ? { features: Object.fromEntries(chosen) } : {}),
		};
	}

	await generate(planOf(target ?? ""));
	io.out(
		listed
			? `created ${target}\nnext: cd ${target} && pnpm install && pnpm start\n`
			: `created ${target}\nnext: cd ${target} and follow its README.md\n`,
	);
	return 0;
}
