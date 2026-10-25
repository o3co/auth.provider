import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { type Command, systemCommand } from "../commands/commands.ts";

/** The label each container carries: the process that started it, so a suite whose owner is gone is known. */
export const ownerLabel = "o3co.oidf.owner";

/** Each step's own time. */
const budgetMs = { quick: 30_000, logs: 60_000, down: 120_000 } as const;

/** Whether a process of the pid runs here. */
const alive = (pid: number) => {
	try {
		process.kill(pid, 0);
		return true;
	} catch (error) {
		return (error as NodeJS.ErrnoException).code === "EPERM";
	}
};

/**
 * Takes down the suites whose owner no longer runs, as a run killed before its stop leaves them, on
 * the suite's fixed ports: each container's log kept in `logs` where given, then its containers,
 * their volumes and their networks removed. Answers the projects taken down; any step that fails is
 * told after every one was tried.
 */
export async function reclaimOrphans(
	command: Command = systemCommand,
	logs?: string,
	running: (pid: number) => boolean = alive,
): Promise<string[]> {
	const { stdout } = await command(
		"docker",
		[
			"ps",
			"--all",
			"--filter",
			`label=${ownerLabel}`,
			"--format",
			`{{.ID}}\t{{.Label "${ownerLabel}"}}\t{{.Label "com.docker.compose.project"}}\t{{.Names}}`,
		],
		{ timeoutMs: budgetMs.quick },
	);
	const orphans = new Map<string, { id: string; name: string }[]>();
	for (const line of stdout.split("\n").filter((l) => l.trim() !== "")) {
		const [id = "", owner = "", project = "", name = ""] = line.split("\t");
		if (running(Number(owner))) continue;
		orphans.set(project, [...(orphans.get(project) ?? []), { id, name }]);
	}
	const problems: unknown[] = [];
	const tried = async (step: () => Promise<unknown>) => {
		await step().catch((error: unknown) => problems.push(error));
	};
	if (logs !== undefined && orphans.size > 0) await mkdir(logs, { recursive: true });
	for (const [project, containers] of orphans) {
		for (const c of containers) {
			if (logs === undefined) continue;
			await tried(async () => {
				const { stdout: log } = await command("docker", ["logs", c.id], {
					timeoutMs: budgetMs.logs,
				});
				await writeFile(join(logs, `${project}-${c.name}.log`), log);
			});
		}
		await tried(() =>
			command("docker", ["rm", "--force", "--volumes", ...containers.map((c) => c.id)], {
				timeoutMs: budgetMs.down,
			}),
		);
		await tried(async () => {
			const { stdout: networks } = await command(
				"docker",
				["network", "ls", "--quiet", "--filter", `label=com.docker.compose.project=${project}`],
				{ timeoutMs: budgetMs.quick },
			);
			for (const network of networks.split("\n").filter((n) => n.trim() !== ""))
				await command("docker", ["network", "rm", network], { timeoutMs: budgetMs.quick });
		});
	}
	if (problems.length > 0)
		throw new AggregateError(problems, "a suite left behind could not be taken down");
	return [...orphans.keys()];
}
