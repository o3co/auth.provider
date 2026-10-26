import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { type Checklist, checklistFindings, parseItems } from "../src/checklist.ts";
import { faultNames } from "../src/guarantee/faults.ts";
import { guaranteeFindings, promisesIn } from "../src/guarantee/promises.ts";
import { repoFindings } from "../src/repo.ts";
import { staticStatus, type TestRef } from "../src/report.ts";
import { titlesIn } from "../src/titles.ts";

const model = readFileSync(join(import.meta.dirname, "fixtures", "promises.txt"), "utf8");
const source = "- source: docs/security-model.md#promises-across-modules";
const meanings = faultNames.map((name) => `- fault ${name}: what ${name} breaks.`).join("\n");
/** A guarantee file: its head (the source and every fault's meaning), then `body`. */
const file = (body: string, head = `${source}\n${meanings}`) =>
	`# Guarantees\n\n${head}\n\n${body}`;
const promised = (n: number) => promisesIn(model).promises.find((p) => p.number === n)?.title ?? "";
/** A body naming one item under each of the model's promises. */
const everyPromise = () =>
	promisesIn(model)
		.promises.map((p) => `## ${p.number} ${p.title}\n\n- **guarantee-${p.number}-a** MUST: kept.\n`)
		.join("\n");
const checklistOf = (text: string): Checklist => {
	const parsed = parseItems("guarantee", text);
	return {
		specs: [
			{
				spec: "guarantee",
				title: parsed.title,
				items: parsed.items,
				ledger: undefined,
				...(parsed.guarantee ? { guarantee: parsed.guarantee } : {}),
			},
		],
		decisions: new Map(),
		parsing: parsed.findings,
	};
};
const ref = (title: string, faults: readonly string[] = []): TestRef => ({
	pkg: "@mod/conformance-code",
	file: "src/x.faults.case.ts",
	title,
	path: [title],
	suite: false,
	faults,
});

describe("the security model's promises", () => {
	it("reads each of the ten as written, its title kept with its punctuation and code spans", () => {
		const read = promisesIn(model);
		expect(read.findings).toEqual([]);
		expect(read.promises.map((p) => p.number)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
		expect(promised(2)).toBe(
			"`prompt=login` and `max_age` are met only by a fresh authentication.",
		);
		expect(promisesIn(model.replaceAll("\n", "\r\n"))).toEqual(read);
	});

	it("refuses a section it cannot read whole, rather than reading fewer promises", () => {
		const broken = (from: string, to: string) => {
			expect(model.includes(from), from).toBe(true);
			return promisesIn(model.replace(from, to)).findings;
		};
		for (const [from = "", to = ""] of [
			["3. **A dependency", "3. __A dependency"],
			["3. **A dependency that cannot answer never grants anything.**", "3. A dependency"],
			["anything.**", "anything.\n   still the title**"],
			["10. **A `POST`", "10) **A `POST`"],
			["10. **A `POST`", "- **A `POST`"],
			["\n10. **A `POST`", "\n   10. **A `POST`"],
			["## Promises across modules", "## Promises across modules ##"],
			["## Promises across modules", "## Promises"],
			["## Promises across modules", "## Promises across modules\n\n## Promises across modules"],
			["2. **`prompt", "3. **`prompt"],
		]) {
			expect(broken(from, to), to).not.toEqual([]);
		}
		expect(promisesIn("## Promises across modules\n\nNone yet.\n").findings).not.toEqual([]);
	});
});

describe("a guarantee file", () => {
	it("holds its source, each fault's meaning, and its sections with their titles", () => {
		const read = parseItems(
			"guarantee",
			file(`## 5 ${promised(5)}\n\n- **guarantee-5-a** MUST: once.\n  faults: Lr, F\n`),
		);
		expect(read.findings).toEqual([]);
		expect(read.items[0]).toMatchObject({ id: "guarantee-5-a", faults: ["Lr", "F"] });
		expect(read.guarantee?.sources).toEqual(["docs/security-model.md#promises-across-modules"]);
		expect(read.guarantee?.sections.get("5")).toBe(promised(5));
	});

	it("refuses a section that is no promise's number, a heading closed by #, and faults it does not take", () => {
		for (const body of [
			"## 3.1 A dependency\n\n- **guarantee-3.1-a** MUST: x.\n",
			`## 3 ${promised(3)} ##\n\n- **guarantee-3-a** MUST: x.\n`,
			`## 3 ${promised(3)}\n\n- **guarantee-3-a** MUST: x.\n  faults: Xx\n`,
			`## 3 ${promised(3)}\n\n- **guarantee-3-a** MUST: x.\n  faults: F, F\n`,
			`## 3 ${promised(3)}\n\n- **guarantee-3-a** MUST: x.\n  faults: F\n  faults: C\n`,
		]) {
			expect(parseItems("guarantee", file(body)).findings, body).not.toEqual([]);
		}
		expect(
			parseItems("rfc9999", "## 2 X\n\n- **rfc9999-2-a** MUST: x.\n  faults: F\n").findings,
		).not.toEqual([]);
	});

	it("takes MUST and MUST NOT alone, noncompliant alone, and no updates or role", () => {
		for (const [line, mark] of [
			["SHOULD: x.", ""],
			["MUST: x.", "  deviates: D-1"],
			["MUST: x.", "  out-of-scope: no."],
			["MUST: x.", "  updates: rfc6749-4.1-a"],
			["MUST: x.", "  role: op"],
		]) {
			const c = checklistOf(
				file(`${everyPromise()}\n## 3 ${promised(3)}\n`).replace(
					"**guarantee-3-a** MUST: kept.",
					`**guarantee-3-a** ${line}\n${mark}`,
				),
			);
			expect(checklistFindings(c), `${line} ${mark}`).not.toEqual([]);
		}
		const noncompliant = file(everyPromise()).replace(
			"**guarantee-3-a** MUST: kept.",
			"**guarantee-3-a** MUST: kept.\n  noncompliant: #1",
		);
		expect(checklistFindings(checklistOf(noncompliant))).toEqual([]);
	});

	it("needs one source, one meaning for each fault and none for another, and no ledger", () => {
		expect(checklistFindings(checklistOf(file(everyPromise())))).toEqual([]);
		for (const head of [
			meanings,
			`${source}\n${source}\n${meanings}`,
			`- source: docs/security-model.md\n${meanings}`,
			`${source}\n${meanings.split("\n").slice(1).join("\n")}`,
			`${source}\n${meanings}\n- fault Xx: unknown.`,
			`${source}\n${meanings}\n- fault Lr: again.`,
		]) {
			expect(checklistFindings(checklistOf(file(everyPromise(), head))), head).not.toEqual([]);
		}
	});

	it("holds each section to the promise of its number, word for word, and every promise to an item", () => {
		const whole = checklistOf(file(everyPromise())).specs[0];
		if (!whole) throw new Error("no spec");
		const promises = promisesIn(model).promises;
		expect(guaranteeFindings(whole, promises)).toEqual([]);
		const without = (text: string) => checklistOf(text).specs[0] ?? whole;
		const wrongTitle = file(
			everyPromise().replace(
				promised(4),
				"A subject's revocation boundary refuses everything made before it",
			),
		);
		const missing = file(
			everyPromise().replace(/## 9 [^\n]*\n\n- \*\*guarantee-9-a\*\* MUST: kept\.\n/, ""),
		);
		const swapped = everyPromise().split("\n## ");
		for (const text of [
			wrongTitle,
			missing,
			file(`## 11 Eleven\n\n- **guarantee-11-a** MUST: x.\n${everyPromise()}`),
		]) {
			expect(guaranteeFindings(without(text), promises)).not.toEqual([]);
		}
		expect(swapped.length).toBeGreaterThan(1);
	});
});

describe("a test's fault marks", () => {
	it("reads {fault:<name>} in a title, and names every other mark it reserves as malformed", () => {
		const source = [
			'it("held [guarantee-5-a] {fault:Lr} {fault:F}", () => {});',
			'it("loose [guarantee-5-a] {fault Lr} {faults:Lr} {fault:} {FAULT:Lr} {fault:Xx} {fault:Lr} {fault:Lr}", () => {});',
			'it("unclosed [guarantee-5-a] {fault:Lr", () => {});',
			'it("marked alone {fault:C}", () => {});',
			'it("plain [guarantee-5-a] {faulty:true} { fault: null } {default}", () => {});',
		].join("\n");
		const read = titlesIn(source, true);
		expect(read.titles.map((t) => [t.faults, t.malformed])).toEqual([
			[["Lr", "F"], []],
			[["Lr"], ["{fault Lr}", "{faults:Lr}", "{fault:}", "{FAULT:Lr}", "{fault:Xx}", "{fault:Lr}"]],
			[[], ["{fault:Lr"]],
			[["C"], []],
			[[], []],
		]);
	});

	it("binds each mark to every guarantee its title names, each of whose faults must hold it", () => {
		const c = checklistOf(
			file(everyPromise())
				.replace("**guarantee-5-a** MUST: kept.", "**guarantee-5-a** MUST: kept.\n  faults: Lr, F")
				.replace("**guarantee-4-a** MUST: kept.", "**guarantee-4-a** MUST: kept.\n  faults: Lr"),
		);
		const w = (tests: [string, TestRef][]) => ({
			tests: new Map(tests.map(([id, r]) => [id, [r]] as const)),
			stray: [],
			marks: [],
		});
		const both = ref("[guarantee-5-a] [guarantee-4-a] {fault:Lr}", ["Lr"]);
		expect(
			repoFindings(
				c,
				w([
					["guarantee-5-a", both],
					["guarantee-4-a", both],
				]),
			),
		).toEqual([]);
		const fOnBoth = ref("[guarantee-5-a] [guarantee-4-a] {fault:F}", ["F"]);
		expect(
			repoFindings(
				c,
				w([
					["guarantee-5-a", fOnBoth],
					["guarantee-4-a", fOnBoth],
				]),
			),
		).toEqual([expect.objectContaining({ detail: expect.stringMatching(/guarantee-4-a: .*F/) })]);
		// An item with no faults line takes no mark: taking the line away never quietly loosens it.
		const onPlain = ref("[guarantee-9-a] {fault:F}", ["F"]);
		expect(repoFindings(c, w([["guarantee-9-a", onPlain]]))).not.toEqual([]);
	});
});

describe("a guarantee's static status", () => {
	it("is a hole while a fault it names has no test marked for it", () => {
		const c = checklistOf(
			file(everyPromise()).replace(
				"**guarantee-5-a** MUST: kept.",
				"**guarantee-5-a** MUST: kept.\n  faults: Lr, F",
			),
		);
		const item = c.specs[0]?.items.find((i) => i.id === "guarantee-5-a");
		if (!item) throw new Error("no item");
		const lrOnly = new Map([
			["guarantee-5-a", [ref("[guarantee-5-a] {fault:Lr}", ["Lr"]), ref("[guarantee-5-a] plain")]],
		]);
		expect(staticStatus(item, lrOnly)).toBe("hole");
		const both = new Map([
			["guarantee-5-a", [ref("[guarantee-5-a] {fault:Lr} {fault:F}", ["Lr", "F"])]],
		]);
		expect(staticStatus(item, both)).toBe("mapped");
	});
});
