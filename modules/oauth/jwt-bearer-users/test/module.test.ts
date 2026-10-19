import {
	type LinkedIssuers,
	type LinkedSubjects,
	linkedIssuers,
	linkedSubjects,
} from "@mod/jwt-bearer";
import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	isUnavailable,
	kernelConfig,
	type Module,
	Unavailable,
} from "@mod/kernel";
import secretHashModule from "@mod/secret-hash/module";
import { type Ledger, ledgers, type UpstreamNames, upstreamNames, type Verified } from "@mod/users";
import usersModule from "@mod/users/module";
import { memoryUsersStores } from "@mod/users/testing";
import { expect, it } from "vitest";
import bridge from "../src/module.ts";

const devices = { upstream: "device", issuer: "app.devices" };
/** What the bridge contributed, read back for the test. */
const seen = contract<{ resolvers: readonly LinkedSubjects[]; names: readonly UpstreamNames[] }>(
	"seen",
);
const reader = defineModule({ name: "reader" }, (m) => [
	m.provide(seen).by(async (c) => ({
		resolvers: await c.collect(linkedSubjects),
		names: await c.collect(upstreamNames),
	})),
]);
/** Stands for jwt-bearer's list of linked issuers. */
const linked = (issuers: LinkedIssuers) =>
	defineModule({ name: "jwt-bearer" }, (m) => [m.provide(linkedIssuers).by(() => issuers)]);
const ledgerAnswering = (answer: () => Promise<Verified>): Ledger => ({
	verify: async () => ({ kind: "none" }),
	bySubject: async () => ({ kind: "none" }),
	byUpstream: answer,
});

async function boot(answer: () => Promise<Verified>, issuers = [devices], extra: Module[] = []) {
	const app = await assemble({
		modules: [
			usersModule,
			secretHashModule,
			memoryUsersStores().module,
			defineModule({ name: "ledger" }, (m) => [
				m.contribute(ledgers).by(() => ledgerAnswering(answer)),
			]),
			linked(issuers),
			bridge,
			reader,
			...extra,
		],
		config: { ...kernelConfig(), users: {} },
	});
	return app.get(seen);
}

it("resolves a linked signer to the subject of the user users finds, none where it finds none, unavailable where it cannot tell", async () => {
	let answer: () => Promise<Verified> = async () => ({
		kind: "user",
		user: { subject: "account-7", attributes: {} },
	});
	const { resolvers } = await boot(() => answer());
	const [resolver] = resolvers;
	expect(resolver?.declaredBy).toBe("jwt-bearer-users");
	expect(await resolver?.subjectOf("device", "thumb-1")).toEqual({
		kind: "subject",
		subject: "account-7",
	});
	answer = async () => ({ kind: "none" });
	expect(await resolver?.subjectOf("device", "thumb-1")).toEqual({ kind: "none" });
	answer = async () => {
		throw new Unavailable("ledger");
	};
	await expect(resolver?.subjectOf("device", "thumb-1")).rejects.toSatisfy(isUnavailable);
});

it("declares each linked issuer's name in one list, an empty one where none is linked", async () => {
	const none = async (): Promise<Verified> => ({ kind: "none" });
	expect((await boot(none)).names).toEqual([
		{ declaredBy: "jwt-bearer-users", names: [{ name: "device", issuer: "app.devices" }] },
	]);
	expect((await boot(none, [])).names).toEqual([{ declaredBy: "jwt-bearer-users", names: [] }]);
});

it("lets users refuse boot on a linked name another module declares for another issuer", async () => {
	const other = defineModule({ name: "federation" }, (m) => [
		m.contribute(upstreamNames).by(() => ({
			declaredBy: "federation",
			names: [{ name: "device", issuer: "https://elsewhere.example" }],
		})),
	]);
	const refused = await boot(async () => ({ kind: "none" }), [devices], [other]).catch((e) => e);
	expect(refused).toBeInstanceOf(BootRefused);
	// users names the modules that declare the name, never the name or an issuer.
	expect((refused as BootRefused).refusals.map((r) => r.reason).join("; ")).toContain(
		"jwt-bearer-users",
	);
});
