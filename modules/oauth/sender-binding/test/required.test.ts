import { type Client, clients } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import { clientsConfig, confidentialClient } from "@mod/clients/testing";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, BootRefused, defineModule, kernelConfig } from "@mod/kernel";
import secretHashModule from "@mod/secret-hash/module";
import { describe, expect, it } from "vitest";
import { type Binding, clientBindings, senderBindings } from "../src/contract.ts";
import senderBindingModule from "../src/module.ts";

/** A client whose `sender-binding` section holds these values, as clients reads it. */
const holding = (section: { required?: boolean; kinds?: string[] }): Client => ({
	id: "c",
	kind: "confidential",
	method: "client_secret_basic",
	registered: true,
	section: <T>() => ({ required: false, ...section }) as T,
});
const bound = (member: string): Binding => ({ member, confirmation: "k", tokenType: "T" });
/** A binding kind writing `member`, named for operators when `name` is given. */
const kind = (member: string, name?: string) =>
	defineModule({ name: `kind-${member}`, replicaSafe: true, takes: [] }, (m) => [
		m.contribute(senderBindings).by(() => ({
			member,
			tokenType: "T",
			...(name ? { name } : {}),
			read: async () => ({ kind: "absent" }),
		})),
	]);
const boot = (section: Readonly<Record<string, unknown>> = {}, kinds = [kind("jkt", "dpop")]) =>
	assemble({
		modules: [http, issuerModule, clientsModule, secretHashModule, senderBindingModule, ...kinds],
		config: {
			...kernelConfig(),
			...httpConfig(),
			...issuerConfig(),
			...clientsConfig([confidentialClient({ id: "c", sections: { "sender-binding": section } })]),
		},
	});

describe("what a client asks of the binding its token requests show", async () => {
	const app = await boot({}, [kind("jkt", "dpop"), kind("x5t", "mtls"), kind("other")]);
	const { refusalOf } = app.get(clientBindings);

	it("asks nothing of a client that says nothing", () => {
		expect([refusalOf(holding({}), undefined), refusalOf(holding({}), bound("jkt"))]).toEqual([
			undefined,
			undefined,
		]);
	});

	it("refuses a request with no binding from a client that requires one", () => {
		expect(refusalOf(holding({ required: true }), undefined)).toBe("required");
		expect(refusalOf(holding({ required: true }), bound("x5t"))).toBe(undefined);
		expect(refusalOf(holding({ required: true, kinds: ["dpop"] }), undefined)).toBe("required");
	});

	it("refuses a binding of a kind the client does not name, and takes one it does", () => {
		const dpopOnly = holding({ kinds: ["dpop"] });
		expect(refusalOf(dpopOnly, bound("x5t"))).toBe("kind");
		expect(refusalOf(dpopOnly, bound("other"))).toBe("kind");
		expect(refusalOf(dpopOnly, bound("jkt"))).toBe(undefined);
		expect(refusalOf(dpopOnly, undefined)).toBe(undefined);
	});
});

describe("the client metadata section", () => {
	it("holds a registered client's requirement, read by name, and requires nothing unwritten", async () => {
		const found = async (section: Readonly<Record<string, unknown>>) => {
			const app = await boot(section);
			const client = await app.get(clients).find("c");
			if (!client) throw new Error("no client");
			return app.get(clientBindings).refusalOf(client, undefined);
		};
		expect(await found({ required: true, kinds: ["dpop"] })).toBe("required");
		expect(await found({})).toBe(undefined);
	});

	it("refuses boot for a name no composed kind has, an empty list of kinds, or another key", async () => {
		for (const section of [
			{ kinds: ["mtls"] },
			{ kinds: ["jkt"] },
			{ required: true, kinds: [] },
			{ methods: [] },
		]) {
			await expect(boot(section), JSON.stringify(section)).rejects.toBeInstanceOf(BootRefused);
		}
	});

	it("refuses boot when two kinds share a name", async () => {
		await expect(boot({}, [kind("jkt", "dpop"), kind("x5t", "dpop")])).rejects.toBeInstanceOf(
			BootRefused,
		);
	});
});
