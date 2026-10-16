import { targetRules } from "@mod/grants";
import { defineModule } from "@mod/kernel";

export default defineModule({ name: "resource-indicators", replicaSafe: true }, (m) => [
	m.contribute(targetRules).by(() => ({
		target: ({ param, audience, within }) => {
			const resource = param("resource");
			// An empty value asks nothing, as one left out.
			if (!resource) return { kind: "audience", audience };
			// Compared as a string with what the issuance may have, never parsed as a URI (RFC 8707 §2):
			// only an exact match narrows, so its form cannot widen anything.
			if (within(resource)) return { kind: "audience", audience: [resource] };
			// A fixed text: the value asked is not echoed in the answer.
			return {
				kind: "error",
				error: "invalid_target",
				description: "resource is not an audience this client may be issued",
			};
		},
		// RFC 8707 §2: a resource the grant cannot honour is refused, never silently dropped.
		untargeted: ({ param }) =>
			param("resource")
				? { kind: "error", error: "invalid_target", description: "this grant takes no resource" }
				: undefined,
		// RFC 8707 §2 lets a request name several resources; one audience is issued, so more are refused.
		repeated: (name) =>
			name === "resource"
				? { kind: "error", error: "invalid_target", description: "one resource at most" }
				: undefined,
	})),
]);
