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
import { quietRuntime } from "@mod/kernel/testing";
import { amrSources } from "@mod/login-gates";
import gatesModule from "@mod/login-gates/module";
import { sessionStandIn } from "@mod/session/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { afterEach, expect, it } from "vitest";
import { acr, acrEntries } from "../src/contract.ts";
import acrModule from "../src/module.ts";
import { acrConfig } from "../src/testing.ts";

const runtime = quietRuntime();
let stop = async () => {};
afterEach(() => stop());

const proving = (amr: string[]) =>
	defineModule({ name: "proving" }, (m) => [
		m.contribute(amrSources).by(() => ({ name: "proving", amr })),
	]);
const published = contract<readonly MetadataItem[]>("published");
const reader = defineModule({ name: "reader" }, (m) => [
	m.provide(published).by((c) => c.collect(metadata)),
]);
const offering = (name: string, sets: string[][]) =>
	defineModule({ name: `offers-${name}` }, (m) => [
		m.contribute(acrEntries).by(() => ({ acr: name, sets })),
	]);

async function serve(values: Record<string, string[][]>, extra: Module[]) {
	const app = await assemble({
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

it("refuses to start with an acr no declared way of logging in can meet", async () => {
	const reasons = (run: Promise<unknown>) =>
		run.then(
			() => "",
			(error) => (error instanceof BootRefused ? error.refusals.map((r) => r.reason).join() : ""),
		);
	expect(await reasons(serve({ "urn:t:hard": [["hwk"]] }, [proving(["pwd"])]))).toMatch(
		/urn:t:hard/,
	);
	expect(
		await reasons(serve({}, [proving(["pwd"]), offering("urn:t:offered", [["hwk"]])])),
	).toMatch(/urn:t:offered/);
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
