import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { trialLayer } from "../src/contract.ts";
import { trialTree, workspaceTrials } from "../src/layer.ts";

/** An app whose entry imports these modules, as far as the trial reads it. */
function importing(imports: readonly string[]): string {
	const target = mkdtempSync(join(tmpdir(), "create-app-trial-"));
	mkdirSync(join(target, "src"));
	writeFileSync(
		join(target, "src", "main.ts"),
		`${imports.map((from, i) => `import m${i} from "${from}/module";`).join("\n")}\n`,
	);
	return target;
}

const redisUrl = "redis://127.0.0.1:1";
const tree = async (target: string, settings: Parameters<typeof trialLayer>[1] = { redisUrl }) =>
	JSON.parse(await trialLayer(target, settings));

describe("trialTree", () => {
	const owned = (text: string, depended: readonly string[] = []) => ({
		from: "a/trial.conf",
		text,
		own: "a",
		depended,
	});

	it("takes a module's own section, and appends to the lists of what it depends on", () => {
		const made = trialTree([
			{ from: "b/trial.conf", text: "b { list = [one] }", own: "b", depended: [] },
			owned("a { key = value }\nb.list += two", ["b"]),
		]);
		expect(made).toEqual({ a: { key: "value" }, b: { list: ["one", "two"] } });
	});

	it("refuses a section neither its own nor one of what it depends on, naming the file", () => {
		expect(() => trialTree([owned("c { key = value }", ["b"])])).toThrow(
			"a/trial.conf sets c, neither its own section nor one of what it depends on",
		);
	});

	it("refuses anything in a depended-on section but an append to a list", () => {
		expect(() => trialTree([owned("b { key = value }", ["b"])])).toThrow(
			"a/trial.conf may only append to b.key, a section of what it depends on",
		);
		expect(() => trialTree([owned("b { list = [two] }", ["b"])])).toThrow(
			"a/trial.conf may only append to b.list, a section of what it depends on",
		);
	});

	it("reads the caller's layer after the modules', so its appends join their lists", () => {
		const made = trialTree(
			[{ from: "b/trial.conf", text: "b { list = [one] }", own: "b", depended: [] }],
			'b.list += "two"\nc.key = 1',
		);
		expect(made).toEqual({ b: { list: ["one", "two"] }, c: { key: 1 } });
	});
});

describe("trialLayer", () => {
	it("makes each trial mark fresh at each call", async () => {
		const target = importing(["@mod/keys", "@mod/seal", "@mod/subject-revocation-http"]);
		const [one, other] = [await tree(target), await tree(target)];
		const pem = one.keys.signing["private-key"] as string;
		expect(pem).toMatch(/^-----BEGIN PRIVATE KEY-----\n/);
		expect(pem).not.toBe(other.keys.signing["private-key"]);
		expect(Buffer.from(one.seal.current.key, "base64")).toHaveLength(32);
		const credential = one["subject-revocation-http"].credential as string;
		expect(credential).toMatch(/^[A-Za-z0-9_-]{43}$/);
		expect(credential).not.toBe(other["subject-revocation-http"].credential);
	});

	it("gives the Redis URL the caller names", async () => {
		expect((await tree(importing(["@mod/redis"]))).redis.url).toBe(redisUrl);
	});

	it("puts a module's own values after those of what it depends on, whatever order the entry imports", async () => {
		const made = await tree(importing(["@mod/audit-http", "@mod/audit", "@mod/outbound"]));
		expect(made.audit.receivers).toEqual(["log", "http"]);
		expect(made.outbound.allow).toEqual(["audit.example.invalid"]);
	});

	it("always takes the kernel's, which the entry imports apart", async () => {
		expect((await tree(importing([]))).kernel).toEqual({ deployment: "single" });
	});

	it("drops the sections in leave, and reads the caller's layer last", async () => {
		const target = importing(["@mod/http", "@mod/subject-revocation-http"]);
		const made = await tree(target, {
			redisUrl,
			leave: ["subject-revocation-http"],
			layer: "http.port = 1234\nkernel.deployment = multi",
		});
		expect(made["subject-revocation-http"]).toBeUndefined();
		expect(made.http.port).toBe(1234);
		expect(made.http["trusted-proxies"]).toEqual(["192.0.2.1"]);
		expect(made.kernel.deployment).toBe("multi");
	});

	it("reads the modules an app composes from its entry, whatever names it imports them under", async () => {
		const made = await tree(
			importing(["@o3co/auth-provider-oauth/authorize", "@o3co/auth-provider-foundation/http"]),
		);
		expect(made.authorize["login-page"]).toMatch(/\.invalid\//);
		expect(made.http["public-origin"]).toMatch(/\.invalid$/);
		expect(made["users-http"]).toBeUndefined();
	});
});

it("finds every trial file in the workspace keeping to its own section and appends to what it depends on", async () => {
	const trials = await workspaceTrials();
	expect(trials.length).toBeGreaterThan(20);
	for (const trial of trials) expect(() => trialTree([trial]), trial.from).not.toThrow();
});
