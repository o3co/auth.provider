import { type Audit, declaredAudit } from "@mod/audit";
import { type HttpRequest, jsonAnswer, type Route } from "@mod/http";
import { isLabel } from "@mod/labels";
import type { Registrations } from "@mod/passkeys";
import events from "../audit-events.ts";
import { type Exchange, invalid, sourced } from "../exchange/exchange.ts";

export interface ManagingParts {
	readonly exchange: Exchange;
	readonly registrations: Registrations;
	readonly audit: Audit;
}

/** One of the subject's passkeys a body names, by `id`; none for another body. */
const idIn = (request: HttpRequest) => {
	const id = request.json?.id;
	return typeof id === "string" && id !== "" ? id : undefined;
};

/** The routes that list, rename and remove the session's subject's passkeys. */
export function managingRoutes(p: ManagingParts): {
	readonly list: Route;
	readonly rename: Route;
	readonly remove: Route;
} {
	const audited = declaredAudit(p.audit, events);
	const list: Route = {
		method: "GET",
		changesState: false,
		path: "/oauth/webauthn/registrations",
		handle: p.exchange.entered(async (_request, subject) => {
			const listed = await p.registrations.listed(subject);
			return jsonAnswer(200, {
				passkeys: listed.map((passkey) => ({
					credentialId: passkey.id,
					...(passkey.nickname ? { nickname: passkey.nickname } : {}),
					...(passkey.transports ? { transports: passkey.transports } : {}),
					backupEligible: passkey.backupEligible,
					backedUp: passkey.backedUp,
					...(passkey.at === undefined ? {} : { createdAt: passkey.at }),
				})),
			});
		}),
	};

	const rename = p.exchange.post(
		"/oauth/webauthn/registrations/rename",
		async (request, subject) => {
			const id = idIn(request);
			const { nickname } = request.json ?? {};
			if (id === undefined) return invalid("id must be a credential id");
			if (typeof nickname !== "string" || !isLabel(nickname)) return invalid("invalid nickname");
			if ((await p.registrations.renamed(subject, id, nickname)) === "unknown") {
				return jsonAnswer(404, { error: "not_found" });
			}
			audited.record("passkey.renamed", { subject, attributes: sourced(request) });
			return jsonAnswer(200, {});
		},
	);

	const remove = p.exchange.post(
		"/oauth/webauthn/registrations/remove",
		async (request, subject) => {
			const id = idIn(request);
			if (id === undefined) return invalid("id must be a credential id");
			const removed = await p.registrations.removed(subject, id);
			if (!removed.removed) return jsonAnswer(404, { error: "not_found" });
			audited.record("passkey.removed", { subject, attributes: sourced(request) });
			return jsonAnswer(200, { last: removed.empty });
		},
	);

	return { list, rename, remove };
}
