/** Which of the images an `image rm` was to remove are still there, told with Docker's answer; none where all went. */
export function notRemoved(
	images: readonly string[],
	answer: { readonly status: number | null; readonly stderr: string },
	listed: readonly string[],
): string | undefined {
	const left = images.filter((image) => listed.includes(image));
	if (left.length === 0) return undefined;
	const why =
		answer.status === 0 || answer.stderr.trim() === "" ? "" : ` (${answer.stderr.trim()})`;
	return `image: ${left.join(", ")} not removed${why}`;
}
