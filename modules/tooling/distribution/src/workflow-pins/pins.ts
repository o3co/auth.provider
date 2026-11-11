/**
 * Every workflow, and every action this repository holds, held to running another repository's code
 * only at a commit, and an image only at its digest: a tag can move to other code, a commit and a
 * digest cannot. Which files are read is a rule, not a list.
 */
import { readdirSync } from "node:fs";
import { basename, join } from "node:path";
import { isMap, isScalar, isSeq, parseDocument } from "yaml";

const commit = /^[0-9a-f]{40}$/;
const digest = /@sha256:[0-9a-f]{64}$/;
/** The version a pin's comment names, as `# v4.4.0`. */
const version = /^\s*v\d\S*/;

/**
 * The files read, relative to `root`: every `.yml` and `.yaml` under `.github/workflows`, and every
 * `action.yml` and `action.yaml` under `.github` (an action this repository holds).
 */
export function pinFiles(root: string): string[] {
	let all: string[];
	try {
		all = readdirSync(join(root, ".github"), { recursive: true, encoding: "utf8" });
	} catch {
		return [];
	}
	return all
		.map((p) => join(".github", p))
		.filter(
			(p) =>
				(p.startsWith(join(".github", "workflows")) && /\.ya?ml$/.test(p)) ||
				/^action\.ya?ml$/.test(basename(p)),
		)
		.toSorted();
}

/** Each place in the file at `path`, its text `text`, that names code or an image by what can move. */
export function pinProblems(path: string, text: string): string[] {
	const doc = parseDocument(text);
	if (doc.errors.length > 0) return [`${path}: not YAML (${doc.errors[0]?.message})`];
	const problems: string[] = [];
	const told = (where: string, what: string) => problems.push(`${path}: ${where}: ${what}`);
	const scalar = (node: unknown, where: string) => {
		if (!isScalar(node) || typeof node.value !== "string") {
			told(where, "not written as a plain string");
			return undefined;
		}
		if (node.value.includes("${{")) {
			told(where, `${node.value} is an expression, which no review can read as a pin`);
			return undefined;
		}
		return node;
	};
	const uses = (node: unknown, where: string) => {
		const s = scalar(node, where);
		if (!s) return;
		const value = s.value as string;
		if (value.startsWith("./")) return;
		if (value.startsWith("docker://")) {
			if (!digest.test(value)) told(where, `${value} is not pinned to an image digest (@sha256:)`);
			return;
		}
		const ref = /^[^@\s]+@([^@\s]+)$/.exec(value)?.[1];
		if (ref === undefined || !commit.test(ref))
			told(where, `${value} is not pinned to a full commit`);
		else if (!version.test(s.comment ?? ""))
			told(where, `${value} names no version in its comment (# v…)`);
	};
	const image = (node: unknown, where: string) => {
		const s = scalar(node, where);
		if (s && !digest.test(s.value as string))
			told(where, `${s.value} is not pinned to an image digest (@sha256:)`);
	};
	const steps = (node: unknown, where: string) => {
		if (!isSeq(node)) return;
		node.items.forEach((step, i) => {
			if (isMap(step) && step.has("uses")) uses(step.get("uses", true), `${where}[${i}].uses`);
		});
	};

	const jobs = doc.get("jobs", true);
	if (isMap(jobs)) {
		for (const pair of jobs.items) {
			const job = pair.value;
			if (!isMap(job)) continue;
			const at = `jobs.${String(isScalar(pair.key) ? pair.key.value : pair.key)}`;
			if (job.has("uses")) uses(job.get("uses", true), `${at}.uses`);
			const container = job.get("container", true);
			if (container !== undefined)
				isMap(container)
					? image(container.get("image", true), `${at}.container.image`)
					: image(container, `${at}.container`);
			const services = job.get("services", true);
			if (isMap(services))
				for (const service of services.items)
					if (isMap(service.value))
						image(
							service.value.get("image", true),
							`${at}.services.${String(isScalar(service.key) ? service.key.value : service.key)}.image`,
						);
			steps(job.get("steps", true), `${at}.steps`);
		}
	}
	// An action this repository holds: a composite's steps, or the image a Docker action runs.
	const runs = doc.get("runs", true);
	if (isMap(runs)) {
		steps(runs.get("steps", true), "runs.steps");
		const ran = runs.get("image", true);
		if (isScalar(ran) && typeof ran.value === "string" && ran.value.startsWith("docker://"))
			image(ran, "runs.image");
	}
	return problems;
}
