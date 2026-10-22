import { configuredUrl } from "@mod/url-setting/testing";
import { describe, expect, it } from "vitest";
import {
	DestinationRefused,
	policyOf,
	policySettings,
	type RefusalReason,
} from "../src/contract.ts";

const reasonOf = (run: () => unknown): RefusalReason | "admitted" => {
	try {
		run();
		return "admitted";
	} catch (error) {
		if (DestinationRefused.is(error)) return error.reason;
		throw error;
	}
};

/** The cloud metadata and platform addresses: inside the private networks, and Azure's public one. */
const cloud = [
	"fd00:ec2::254",
	"fd00:ec2::23",
	"fd20:ce::254",
	"fd00:a9fe:a9fe::1",
	"fd00:42::42",
	"fd00:c1::a9fe:a9fe",
	"100.100.100.200",
	"168.63.129.16",
	"::ffff:168.63.129.16",
];

/** Each way a name is let through, with an address it takes there, and how a request is narrowed. */
const reaches = [
	{
		how: "any public",
		settings: { "allow-any-public": true },
		url: "https://svc.example/x",
		taken: "93.184.216.34",
	},
	{
		how: "a named host",
		settings: { allow: ["svc.example"] },
		url: "https://svc.example/x",
		taken: "93.184.216.34",
	},
	{
		how: "internal-hosts",
		settings: { "allow-any-public": true, "internal-hosts": ["svc.internal"] },
		url: "https://svc.internal/x",
		taken: "fd12:3456::1",
		internal: true,
	},
	{
		how: "plain-internal",
		settings: { "allow-any-public": true, "plain-internal": ["svc.internal:9092"] },
		url: "http://svc.internal:9092/x",
		taken: "10.1.2.3",
		internal: true,
	},
];

describe("a cloud metadata or platform address", () => {
	for (const reach of reaches) {
		it(`is refused under ${reach.how}, alone or among the addresses a name answers`, () => {
			const policy = policyOf(policySettings.parse(reach.settings));
			const admitted = policy.admit(
				reach.url,
				reach.internal ? { internal: configuredUrl(reach.url) } : {},
			);
			expect(reasonOf(() => policy.admitAddresses([reach.taken], admitted))).toBe("admitted");
			for (const address of cloud) {
				expect(
					reasonOf(() => policy.admitAddresses([address], admitted)),
					address,
				).toBe("special-address");
				expect(
					reasonOf(() => policy.admitAddresses([reach.taken, address], admitted)),
					address,
				).toBe("special-address");
			}
		});
	}

	it("is refused written in a URL, by boot's check and by the request alike", () => {
		const policy = policyOf(policySettings.parse({ "allow-any-public": true }));
		for (const address of cloud) {
			const url = `https://${address.includes(":") ? `[${address}]` : address}/x`;
			expect(policy.explain(url)?.split(":")[0], address).toBe("special-address");
			expect(
				reasonOf(() => policy.admitAddresses([address], policy.admit(url))),
				address,
			).toBe("special-address");
		}
	});
});
