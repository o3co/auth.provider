import type { Reading } from "@mod/metrics";
import { describe, expect, it } from "vitest";
import { textOf, unwritable } from "../text.ts";

const counterReading = (name: string, labels: string[] = []): Reading => ({
	kind: "counter",
	name,
	help: "",
	labels,
	series: [],
});
const histogramReading = (name: string, labels: string[] = []): Reading => ({
	kind: "histogram",
	name,
	help: "",
	labels,
	buckets: [1],
	series: [],
});

const written: [string, Reading[], string][] = [
	["nothing", [], ""],
	[
		"a counter with its series",
		[
			{
				kind: "counter",
				name: "c_total",
				help: "Counts.",
				labels: ["a", "b"],
				series: [
					{ labels: { a: "x", b: "y" }, value: 2 },
					{ labels: { a: "z", b: "y" }, value: 0.5 },
				],
			},
		],
		[
			"# HELP c_total Counts.",
			"# TYPE c_total counter",
			'c_total{a="x",b="y"} 2',
			'c_total{a="z",b="y"} 0.5',
			"",
		].join("\n"),
	],
	[
		"a counter with no labels and no series",
		[{ kind: "counter", name: "n", help: "None.", labels: [], series: [] }],
		"# HELP n None.\n# TYPE n counter\n",
	],
	[
		"a series with no labels, without braces except a histogram's le",
		[
			{ kind: "gauge", name: "g", help: "", labels: [], series: [{ labels: {}, value: 3 }] },
			{
				kind: "histogram",
				name: "h",
				help: "",
				labels: [],
				buckets: [1],
				series: [{ labels: {}, counts: [0, 1], sum: 2, count: 1 }],
			},
		],
		[
			"# HELP g ",
			"# TYPE g gauge",
			"g 3",
			"# HELP h ",
			"# TYPE h histogram",
			'h_bucket{le="1"} 0',
			'h_bucket{le="+Inf"} 1',
			"h_sum 2",
			"h_count 1",
			"",
		].join("\n"),
	],
	[
		"a gauge with its series, a value below zero among them",
		[
			{
				kind: "gauge",
				name: "g",
				help: "Up.",
				labels: ["part"],
				series: [
					{ labels: { part: "a" }, value: 1 },
					{ labels: { part: "b" }, value: -0.25 },
				],
			},
		],
		["# HELP g Up.", "# TYPE g gauge", 'g{part="a"} 1', 'g{part="b"} -0.25', ""].join("\n"),
	],
	[
		"a histogram, cumulative, with +Inf, sum and count",
		[
			{
				kind: "histogram",
				name: "h",
				help: "Times.",
				labels: ["r"],
				buckets: [0.005, 2.5],
				series: [{ labels: { r: "/a" }, counts: [1, 2, 3], sum: 4.5, count: 3 }],
			},
		],
		[
			"# HELP h Times.",
			"# TYPE h histogram",
			'h_bucket{r="/a",le="0.005"} 1',
			'h_bucket{r="/a",le="2.5"} 2',
			'h_bucket{r="/a",le="+Inf"} 3',
			'h_sum{r="/a"} 4.5',
			'h_count{r="/a"} 3',
			"",
		].join("\n"),
	],
	[
		"help and label values escaped",
		[
			{
				kind: "counter",
				name: "e",
				help: 'a\\b\nc "d"',
				labels: ["v"],
				series: [{ labels: { v: 'q"\\\nr' }, value: 1 }],
			},
		],
		[String.raw`# HELP e a\\b\nc "d"`, "# TYPE e counter", String.raw`e{v="q\"\\\nr"} 1`, ""].join(
			"\n",
		),
	],
];

describe("text", () => {
	it.each(written)("writes %s", (_, readings, text) => {
		expect(textOf(readings)).toBe(text);
	});

	it("tells the readings the format cannot hold, and why", () => {
		expect(
			unwritable(
				[
					histogramReading("h", ["le"]),
					counterReading("auth_provider_up"),
					histogramReading("x"),
					counterReading("x_count"),
					histogramReading("y"),
					counterReading("y_bucket"),
					histogramReading("p"),
					histogramReading("q"),
					counterReading("fine", ["le"]),
				],
				["auth_provider_up", "p", "q_sum"],
			),
		).toEqual([
			{ name: "h", reason: "a histogram label is named le" },
			{ name: "auth_provider_up", reason: "a name it takes is the process's" },
			{ name: "x", reason: "a name it takes is another instrument's" },
			{ name: "x_count", reason: "a name it takes is another instrument's" },
			{ name: "y", reason: "a name it takes is another instrument's" },
			{ name: "y_bucket", reason: "a name it takes is another instrument's" },
			{ name: "p", reason: "a name it takes is the process's" },
			{ name: "q", reason: "a name it takes is the process's" },
		]);
	});
});
