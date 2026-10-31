import { hostList, pairOf } from "@mod/host-entries";
import { setting } from "@mod/kernel";
import { z } from "zod";
import { isListEntry, isPair } from "./policy.ts";

const hostEntries = z.array(z.string().refine(isListEntry, "not a host")).prefault([]);

/** The destination policy and caps an operator sets, the keys a section takes as its own. */
export const policySettings = z
	.strictObject({
		allow: hostEntries.describe(
			"The hosts requests may reach by name; `.name` covers the name and the names under it.",
		),
		"allow-any-public": z
			.boolean()
			.prefault(false)
			.describe(
				"Whether requests may reach any host at a public address, instead of naming hosts in `allow`.",
			),
		deny: hostEntries.describe(
			"The hosts requests never reach, checked before `allow`; `.name` covers the name and the names under it. An address listed is refused also where a name resolves to it.",
		),
		"plain-loopback": z
			.array(z.string().refine(isPair, "not a host:port pair"))
			.prefault([])
			.describe("The `host:port` pairs plain http may reach at loopback addresses."),
		"plain-internal": z
			.array(z.string().refine(isPair, "not a host:port pair"))
			.prefault([])
			.describe(
				"The `host:port` pairs plain http may reach for a URL of the operator's own configuration, at private or loopback addresses alone (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7, 127/8, ::1, never a metadata address); every answer must be private or loopback, and the host is still checked against `deny` and `allow`. What goes there, passwords, tokens, credentials and keys, is in the clear: list only peers on a network trusted against reading and changing it.",
			),
		"max-response-size": setting
			.size()
			.pipe(z.number().int().min(1).max(16_777_216))
			.prefault("64KiB")
			.describe("The largest response body a request takes, from 1B to 16MiB."),
		"signed-max-response-size": setting
			.size()
			.pipe(z.number().int().min(1).max(16_777_216))
			.prefault("1MiB")
			.describe("The largest response body a request for signed material takes, from 1B to 16MiB."),
		timeout: setting
			.duration("ms")
			.pipe(z.number().int().min(1).max(60_000))
			.prefault("5s")
			.describe(
				"The one deadline covering a request's resolving, connecting, headers and body, from 1ms to 1m.",
			),
		"internal-hosts": hostList.describe(
			"The hosts a URL from the operator's own configuration may reach at a private address (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7); `.name` covers the name and the names under it.",
		),
	})
	.refine((s) => !(s["allow-any-public"] && s.allow.length > 0), {
		message: "allow-any-public reaches any public address; name hosts in allow or set it, not both",
	})
	.refine(
		(s) => {
			const loopback = new Set(s["plain-loopback"].map(pairOf));
			return !s["plain-internal"].some((pair) => loopback.has(pairOf(pair)));
		},
		{
			message:
				"a host:port is named in one plain list alone: plain-loopback for loopback, or plain-internal for private or loopback addresses",
			path: ["plain-internal"],
		},
	);

export type PolicySettings = z.output<typeof policySettings>;
