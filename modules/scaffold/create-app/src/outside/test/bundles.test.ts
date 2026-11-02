import { expect, it } from "vitest";
import { publishedIn } from "../../packages.ts";
import { bundlesIn } from "../contract.ts";

const [one, two, three] = ["one", "two", "three"].map((b) => `@o3co/auth-provider-${b}`) as [
	string,
	string,
	string,
];
const member = (name: string, bundle: string, dependencies: Record<string, string> = {}) => ({
	name,
	package: bundle,
	entry: `${bundle}/${name}`,
	manifest: { name, dependencies },
});
const members = [
	member("@mod/a", one, { "@mod/b": "workspace:*", "@mod/c": "workspace:*", zod: "4.6.7" }),
	member("@mod/b", one, { "@mod/d": "workspace:*" }),
	member("@mod/c", two, { "@mod/d": "workspace:*" }),
	member("@mod/d", three),
];

it("tells each bundle's dependencies on other bundles from its members' manifests", () => {
	expect(bundlesIn(members)).toEqual({ [one]: [two, three], [two]: [three] });
});

it("hands them on where the release seals its integrity, and nowhere else", () => {
	const sealed = {
		integrity: { [one]: "sha512-A", [two]: "sha512-B", [three]: "sha512-C" },
		zod: { version: "4.6.7", integrity: "sha512-Z" },
	};
	const index = { version: "0.19.0", packages: members };
	expect(publishedIn({ ...index, ...sealed }).release().bundles).toEqual(bundlesIn(members));
	expect(publishedIn(index).release().bundles).toBeUndefined();
});
