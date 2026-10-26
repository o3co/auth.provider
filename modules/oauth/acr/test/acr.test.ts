import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { type MetadataItem, metadata } from "@mod/issuer";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	kernelConfig,
	type Module,
} from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { amrSources } from "@mod/login-gates";
import gatesModule from "@mod/login-gates/module";
import { sessionStandIn } from "@mod/session/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { afterEach, expect, it } from "vitest";
import { acr, acrEntries } from "../src/contract.ts";
import acrModule from "../src/module.ts";
import { section } from "../src/section.ts";
import { acrConfig } from "../src/testing.ts";

const runtime = quietRuntime();
let stop = async () => {};
afterEach(() => stop());

const proving = (amr: string[]) =>
	defineModule({ name: "proving", takes: [] }, (m) => [
		m.contribute(amrSources).by(() => ({ name: "proving", amr })),
	]);
const published = contract<readonly MetadataItem[]>("published");
const reader = defineModule({ name: "reader", takes: [metadata] }, (m) => [
	m.provide(published).by((c) => c.collect(metadata)),
]);
const offering = (name: string, sets: string[][]) =>
	defineModule({ name: `offers-${name}`, takes: [] }, (m) => [
		m.contribute(acrEntries).by(() => ({ acr: name, sets })),
	]);

/** The assembly the tests serve: http, issuer, login-gates and acr, with this table and these modules. */
const assembly = (values: Record<string, string[][]>, extra: Module[]) => ({
	modules: [
		http,
		issuerModule,
		reader,
		sessionStandIn,
		subjectRevocationStandIn,
		gatesModule,
		acrModule,
		...extra,
	],
	config: {
		...kernelConfig(),
		...httpConfig(),
		...issuerConfig({ url: "https://as.example" }),
		...acrConfig(values),
	},
	runtime,
});

async function serve(values: Record<string, string[][]>, extra: Module[]) {
	const app = await assemble(assembly(values, extra));
	await app.start();
	stop = () => app.stop(1000);
	const listed = async () =>
		app.get(published).find((item) => item.name === "acr_values_supported")?.value;
	return { decided: app.get(acr), listed };
}

const table = {
	"urn:t:zz": [["pwd"]],
	"urn:t:aa": [["hwk"], ["pwd", "otp"]],
	"urn:t:both": [["pwd"]],
};
const offers = () => [
	proving(["pwd", "otp", "hwk"]),
	offering("urn:t:offered", [["otp"]]),
	offering("urn:t:both", [["hwk"]]),
];

it("knows the asked acr the table holds, in the order asked, by exact name", async () => {
	const { decided } = await serve(table, offers());
	expect(decided.known("urn:t:none urn:t:aa urn:t:zz")).toEqual(["urn:t:aa", "urn:t:zz"]);
	expect(decided.known("URN:T:AA constructor toString __proto__")).toEqual([]);
});

it("meets the first known acr whose one set the session holds whole", async () => {
	const { decided } = await serve(table, offers());
	expect(decided.met(["urn:t:aa", "urn:t:zz"], ["pwd"])).toBe("urn:t:zz");
	expect(decided.met(["urn:t:aa", "urn:t:zz"], ["pwd", "otp"])).toBe("urn:t:aa");
	expect(decided.met(["urn:t:aa"], ["otp"])).toBeUndefined();
	expect(decided.met(["constructor"], ["pwd"])).toBeUndefined();
});

it("answers the session's current acr: the first in the table's order its amr meet, none where they meet none", async () => {
	const { decided } = await serve(table, offers());
	expect(decided.current(["pwd"])).toBe("urn:t:zz");
	expect(decided.current(["hwk"])).toBe("urn:t:aa");
	// The operator's sets for the same acr, then the offered entries after the operator's own.
	expect(decided.current(["otp"])).toBe("urn:t:offered");
	expect(decided.current(["mfa"])).toBeUndefined();
	await stop();
	expect((await serve({}, [])).decided.current(["pwd"])).toBeUndefined();
});

it("takes the operator's sets over an offered entry for the same acr", async () => {
	const { decided } = await serve(table, offers());
	expect(decided.met(decided.known("urn:t:both"), ["pwd"])).toBe("urn:t:both");
	expect(decided.met(decided.known("urn:t:both"), ["hwk"])).toBeUndefined();
});

it("lists the operator's acr in written order, then the offered ones, and nothing for an empty table", async () => {
	const { listed } = await serve(table, offers());
	expect(await listed()).toEqual(["urn:t:zz", "urn:t:aa", "urn:t:both", "urn:t:offered"]);
	await stop();
	expect(await (await serve({}, [])).listed()).toBeUndefined();
});

it("refuses to start with an acr no declared way of logging in can meet: a configured one at its key, an offered one by its name", async () => {
	const refusals = (run: Promise<unknown>) =>
		run.then(
			() => [],
			(error) => (error instanceof BootRefused ? error.refusals : []),
		);
	expect(await refusals(serve({ "urn:t:hard": [["hwk"]] }, [proving(["pwd"])]))).toEqual([
		{ where: "acr.values.urn:t:hard", reason: "no declared way of logging in can meet it" },
	]);
	// A module's own acr is no configured value: it is told by its name.
	expect(
		await refusals(serve({}, [proving(["pwd"]), offering("urn:t:offered", [["hwk"]])])),
	).toEqual([
		{
			where: "acr",
			reason:
				"an acr a module offers has no declared way of logging in that can meet it: urn:t:offered",
		},
	]);
});

it("refuses to start with an offered entry whose sets are not each a non-empty set, in a non-empty list", async () => {
	for (const [name, sets] of Object.entries({ "an empty set": [[]], "no set": [] })) {
		const refused = await serve({}, [proving(["pwd"]), offering("urn:t:loose", sets)]).catch(
			(error) => error,
		);
		expect(refused, name).toBeInstanceOf(BootRefused);
		expect(JSON.stringify(refused.refusals), name).toMatch(/urn:t:loose/);
	}
});

it("reads an empty table when the operator sets nothing", () => {
	expect(section.parse({})).toEqual({ values: {} });
});

it("takes all it names, with a table and with none, offered entries or not", async () => {
	for (const [values, extra] of [
		[table, offers()],
		[{}, []],
		[{}, offers()],
	] as const) {
		// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
		expect(
			(await takesUnused(assembly(values, [...extra])))["acr"],
			JSON.stringify(values),
		).toBeUndefined();
	}
});
