/** The type a warn line names for a thrown value: its name, or "unknown" where reading it throws. */
export function kindOf(error: unknown): string {
	try {
		return error instanceof Error ? String(error.name) : typeof error;
	} catch {
		// A revoked proxy, or a name whose getter throws: the line is still written.
		return "unknown";
	}
}
