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
 * the suite's fixed ports: each container's log, its stdout and its stderr, kept in `logs` where
 * given and where it can be made, then its containers,
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
	/** Runs `step`, telling whether it went; a failure is kept for after every step was tried. */
	const tried = (step: () => Promise<unknown>) =>
		step().then(
			() => true,
			(error: unknown) => {
				problems.push(error);
				return false;
			},
		);
	// A directory that cannot be made keeps no log, and the suites still go: they hold the fixed ports.
	const kept =
		logs !== undefined && orphans.size > 0 && (await tried(() => mkdir(logs, { recursive: true })))
			? logs
			: undefined;
	for (const [project, containers] of orphans) {
		for (const c of containers) {
			if (kept === undefined) continue;
			await tried(async () => {
				const { stdout, stderr = "" } = await command("docker", ["logs", c.id], {
					timeoutMs: budgetMs.logs,
				});
				// A container without a tty writes its stderr to the command's.
				await writeFile(
					join(kept, `${project}-${c.name}.log`),
					stderr === "" ? stdout : `${stdout}\n--- stderr ---\n${stderr}`,
				);
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
