import { clientAllowance } from "@mod/client-allowance";
import type { GrantInput, GrantOutcome } from "@mod/grants";
import { resourceRefusal } from "@mod/resource-indicators";
import type { Exchanged } from "../contract.ts";

type Refusal = Extract<GrantOutcome, { kind: "error" }>;
/** What an exchange issues for: its scope and its one audience. */
export interface Target {
	readonly scope: readonly string[];
	readonly audience: readonly [string];
}

const refused = (description: string, error: string): Refusal => ({
	kind: "error",
	error,
	description,
});

/** The refusal of the `resource` asked, where one is and it is not the audience issued; none otherwise. */
const resourceMismatch = (param: GrantInput["param"], audience: string): Refusal | undefined => {
	const resource = param("resource");
	// RFC 8693 §2.1: an absolute URI without a fragment, read as resource-indicators reads one.
	const malformed = resource ? resourceRefusal(resource) : undefined;
	if (malformed) return refused(malformed, "invalid_target");
	if (resource && resource !== audience) {
		return refused("resource is not the audience issued", "invalid_target");
	}
	return undefined;
};

/** The target of an exchange at `issuer`, from the request and the subject token. */
export function targetWith(issuer: string) {
	/** The scope and the one audience asked for, within the client's allowance alone. */
	const clientTargetOf = ({ client, param }: GrantInput): Target | Refusal => {
		const allowed = clientAllowance.allowedIssuance(client, param("scope"), issuer);
		if (allowed.kind === "error") {
			return refused(allowed.description ?? "scope is not within the client's", allowed.error);
		}
		const audience = param("audience") || allowed.audience[0];
		if (audience === undefined || !clientAllowance.allowsAudience(client, audience, issuer)) {
			return refused("audience is not one the client may be issued", "invalid_target");
		}
		const mismatch = resourceMismatch(param, audience);
		if (mismatch) return mismatch;
		return { scope: [...allowed.scope], audience: [audience] };
	};

	/** The scope and the one audience asked for, within the subject token's and the client's. */
	const targetOf = (input: GrantInput, subject: Exchanged): Target | Refusal => {
		if (subject.kind === "foreign") return clientTargetOf(input);
		const { client, param } = input;
		const allows = (scope: string) => clientAllowance.allowsScope(client, scope);
		const asked = clientAllowance.parseScope(param("scope"));
		const ceiling = [...new Set(subject.scope.filter(allows))];
		if (!asked || asked.some((s) => !ceiling.includes(s))) {
			return refused("scope is not within the subject token's and the client's", "invalid_scope");
		}
		const held = subject.audience.filter((a) => clientAllowance.allowsAudience(client, a, issuer));
		const audience = param("audience") || (held.length === 1 ? held[0] : undefined);
		if (audience === undefined || !held.includes(audience)) {
			return refused("audience is not one the subject token and the client hold", "invalid_target");
		}
		const mismatch = resourceMismatch(param, audience);
		if (mismatch) return mismatch;
		return { scope: asked.length > 0 ? [...new Set(asked)] : ceiling, audience: [audience] };
	};

	return { targetOf };
}
