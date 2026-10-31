import { DockerFailed } from "@mod/docker-client";

/**
 * Which of the images an `image rm` was to remove are still there, told with Docker's answer, by
 * Docker's listing after it; a listing that failed is told as such, its empty output never read as
 * nothing left. None where all went.
 */
export function notRemoved(
	images: readonly string[],
	answer: { readonly status: number | null; readonly stderr: string },
	listing: { readonly status: number | null; readonly stdout: string; readonly stderr: string },
): string | undefined {
	if (listing.status !== 0) {
		return `image: ${images.join(", ")} may not be removed: Docker's images could not be listed (${listing.stderr.trim()})`;
	}
	const listed = listing.stdout.split("\n");
	const left = images.filter((image) => listed.includes(image));
	if (left.length === 0) return undefined;
	const why =
		answer.status === 0 || answer.stderr.trim() === "" ? "" : ` (${answer.stderr.trim()})`;
	return `image: ${left.join(", ")} not removed${why}`;
}

/** A docker command's end as its status and streams, a failure answered; one past its time says so beside what was written. */
export const endOf = (command: Promise<string>) =>
	command.then(
		(stdout) => ({ status: 0, stdout, stderr: "" }),
		(error: unknown) => {
			if (!(error instanceof DockerFailed)) return { status: 1, stdout: "", stderr: String(error) };
			const told = error.told.trim();
			const stderr =
				error.kind === "timeout"
					? [told, error.message].filter(Boolean).join("\n")
					: told || error.message;
			return { status: error.code ?? 1, stdout: error.wrote, stderr };
		},
	);
