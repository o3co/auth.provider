import { jsonObjectOf, type OutboundResponse } from "@mod/outbound";
import { type UpstreamProfile, UpstreamRefused } from "@mod/upstreams";

/** A profile claim UserInfo gives as text that is not empty; any other value is none. */
const textOf = (value: unknown) => (typeof value === "string" && value !== "" ? value : undefined);

/**
 * A UserInfo answer (OpenID Connect Core §5.3.2) for the login whose checked id_token names
 * `subject`: a JSON object of a 200 as `application/json`, whose `sub` is exactly the subject; its
 * profile, the email verified only by the boolean `true`. Any other answer, a signed or encrypted
 * one among them, is the upstream refusing, and none of its values is used.
 */
export function userinfoProfileOf(
	answer: OutboundResponse,
	subject: string,
): UpstreamProfile | undefined {
	const type = answer.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase();
	if (answer.status !== 200 || type !== "application/json") throw new UpstreamRefused();
	const read = jsonObjectOf(answer);
	if (read.kind !== "object" || read.value.sub !== subject) throw new UpstreamRefused();
	const email = textOf(read.value.email);
	const name = textOf(read.value.name);
	const picture = textOf(read.value.picture);
	const profile = {
		...(email === undefined ? {} : { email, emailVerified: read.value.email_verified === true }),
		...(name === undefined ? {} : { name }),
		...(picture === undefined ? {} : { picture }),
	};
	return Object.keys(profile).length > 0 ? profile : undefined;
}

/**
 * A login's profile with UserInfo's: what the id_token says first, judged by its checked claims as
 * given (a claim present with no usable value is still the id_token's), UserInfo's only for a claim
 * the id_token leaves out; the email always with the verification of the answer that gave it.
 */
export function withUserinfo(
	token: {
		readonly claims: Readonly<Record<string, unknown>>;
		readonly profile?: UpstreamProfile | undefined;
	},
	userinfo: UpstreamProfile | undefined,
): UpstreamProfile | undefined {
	const own = token.profile ?? {};
	const other = userinfo ?? {};
	const said = (claim: string) => Object.hasOwn(token.claims, claim);
	const email = said("email") ? own : other;
	const name = said("name") ? own.name : other.name;
	const picture = said("picture") ? own.picture : other.picture;
	const profile = {
		...(email.email === undefined
			? {}
			: { email: email.email, emailVerified: email.emailVerified === true }),
		...(name === undefined ? {} : { name }),
		...(picture === undefined ? {} : { picture }),
	};
	return Object.keys(profile).length > 0 ? profile : undefined;
}
