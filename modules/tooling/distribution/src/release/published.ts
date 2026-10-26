/** Whether what is already published at this version is what this run packed, before anything more is published. */
import type { Packed } from "../packed/packed.ts";

/** What the registry answered for a name at this version: not there, there with an integrity, or no answer read. */
export type Lookup =
	| { readonly kind: "absent" }
	| { readonly kind: "present"; readonly integrity: string }
	| { readonly kind: "failed"; readonly why: string };

/**
 * Why publishing must not start: a package published at this version whose integrity is not this
 * run's tarball's, the index's own bundle and the entrances among them, or a name the registry gave
 * no answer for that can be read (an error, a malformed answer, no integrity), never taken as absent.
 */
export function publishedProblems(
	packed: readonly Packed[],
	lookups: ReadonlyMap<string, Lookup>,
): string[] {
	return packed.flatMap(({ name, version, integrity }) => {
		const lookup = lookups.get(name);
		if (lookup === undefined) return [`${name}@${version}: not looked up`];
		if (lookup.kind === "failed")
			return [`${name}@${version}: the registry's answer is unread (${lookup.why})`];
		if (lookup.kind === "present" && lookup.integrity !== integrity) {
			return [`${name}@${version}: published with another integrity than this run's tarball`];
		}
		return [];
	});
}

/** A registry's answer to `npm view <name>@<version> dist.integrity --json`, as a lookup. */
export function lookupOf(answer: { status: number; stdout: string; stderr: string }): Lookup {
	if (answer.status !== 0) {
		// Absent only as npm says it: its error code E404 (a name or version not in the registry).
		let code: unknown;
		try {
			code = (JSON.parse(answer.stdout) as { error?: { code?: unknown } }).error?.code;
		} catch {
			// npm's own error code line, as npm writes it: never E404 elsewhere in a message or a URL.
			code = /^npm (error|ERR!) code E404$/m.test(answer.stderr) ? "E404" : undefined;
		}
		return code === "E404"
			? { kind: "absent" }
			: { kind: "failed", why: `npm view exited ${answer.status}` };
	}
	let integrity: unknown;
	try {
		integrity = JSON.parse(answer.stdout);
	} catch {
		return { kind: "failed", why: "an answer that is no JSON" };
	}
	return typeof integrity === "string" && /^sha512-[A-Za-z0-9+/]+=*$/.test(integrity)
		? { kind: "present", integrity }
		: { kind: "failed", why: "no sha512 integrity in the answer" };
}
