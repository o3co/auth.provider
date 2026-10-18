import { type Audit, audit, declaredAudit } from "@mod/audit";
import { type HttpRequest, type HttpResponse, jsonAnswer } from "@mod/http";
import type { BuildContext, Runtime } from "@mod/kernel";
import { attemptLimit, type RateLimit } from "@mod/rate-limit";
import { determinedSource } from "@mod/request-source";
import { type Sessions, sessions } from "@mod/session";
import { answeringUnavailable, oauthError } from "@mod/token-endpoint";
import { type Tokens, tokens } from "@mod/tokens";
import events from "../audit-events.ts";
import { normalized } from "../codes.ts";
import { deviceGrantType } from "../contract.ts";
import { type Device, fromStored, rewriteAt } from "../record.ts";
import type { Settings } from "../section.ts";
import { type DeviceStore, deviceStore, type UserCodes, userCodes } from "../store.ts";

export interface Verifying {
	readonly sessions: Sessions;
	readonly attempts: RateLimit;
	readonly audit: Audit;
	readonly devices: DeviceStore;
	readonly userCodes: UserCodes;
	readonly runtime: Runtime;
	readonly settings: Settings;
	readonly tokens: Pick<Tokens, "admits">;
}

/**
 * RFC 8628 §3.3, as an interface for the deployment's page: a signed-in user looks up a code, and
 * approves or denies it once. Every decision counts against the subject, so codes cannot be guessed.
 */
export function verificationWith(v: Verifying) {
	const window = {
		limit: v.settings.attempts,
		ms: v.settings["attempts-window"] * 1000,
	};
	/** The device a typed user code names; a code outside the alphabet asks no store. */
	const deviceNamed = async (typed: string | undefined) => {
		const code = normalized(typed ?? "");
		if (code === undefined) return undefined;
		const name = await v.userCodes.read(code);
		if (name === undefined) return undefined;
		const device = fromStored(await v.devices.read(name));
		return device && { name, device };
	};
	const answer = async (request: HttpRequest): Promise<HttpResponse> => {
		const field = (name: string) => request.fields.single(name);
		const action = field("action");
		if (action !== "lookup" && action !== "approve" && action !== "deny") {
			return oauthError(400, "invalid_request", "action is lookup, approve or deny");
		}
		// Approving grants the device what the session holds; looking and refusing grant nothing.
		const entry = await v.sessions.enterFor(request, action === "approve" ? "use" : "none");
		if (entry.kind === "absent") return oauthError(401, "login_required");
		if (entry.kind === "short") {
			const { requirement } = entry;
			return jsonAnswer(403, { error: "step_up_required", requirement, answer: entry.answer });
		}
		const { context } = entry.session;
		const from = determinedSource(request);
		const source = from === undefined ? {} : { source: from };
		const audited = (kind: keyof typeof events, attributes: Record<string, string>) =>
			declaredAudit(v.audit, events).record(kind, {
				subject: context.subject,
				attributes: { ...attributes, ...source },
			});
		const counted = await v.attempts.hit("device-grant.verification", context.subject, window);
		if (counted.kind === "limited") {
			audited("device.rate_limited", { action });
			// attempts-exceeded: RFC 8628 has no word for it, so it is answered as a poll's slow_down.
			const limited = oauthError(429, "slow_down");
			const seconds = String(Math.ceil(counted.retryAfterMs / 1000));
			return { ...limited, headers: { ...limited.headers, "retry-after": seconds } };
		}
		const found = await deviceNamed(field("user_code"));
		if (!found) return oauthError(404, "invalid_user_code");
		const { name, device } = found;
		const now = v.runtime.clock.now();
		if (device.expiresAt <= now) return oauthError(410, "expired_token");
		if (action === "lookup") {
			return jsonAnswer(200, {
				client_id: device.clientId,
				scope: device.scope.join(" "),
				expires_at: new Date(device.expiresAt).toISOString(),
			});
		}
		if (action === "approve") {
			// Asked before the approval is kept, so the user sees a refusal the poll would meet.
			const admitted = await v.tokens.admits({
				grant: {
					subject: context.subject,
					issuedTo: device.clientId,
					audience: device.audience,
					scope: device.scope,
					amr: [...context.amr],
					authenticatedAt: context.authenticatedAt,
					...(context.authenticatedAtUnknown ? { authenticatedAtUnknown: true as const } : {}),
				},
				grantType: deviceGrantType,
				session: entry.session.id,
			});
			if (admitted.kind === "refused") {
				const { policy, reason } = admitted;
				audited("device.approval_refused", { client: device.clientId, policy, reason });
				return jsonAnswer(403, {
					error: "access_denied",
					error_description: admitted.description,
				});
			}
		}
		const decision: Pick<Device, "state" | "approval"> =
			action === "approve"
				? {
						state: "approved",
						approval: {
							subject: context.subject,
							approvedAt: now,
							amr: [...context.amr],
							authenticatedAt: context.authenticatedAt,
							...(context.authenticatedAtUnknown ? { authenticatedAtUnknown: true as const } : {}),
							session: entry.session.id,
						},
					}
				: { state: "denied" };
		// Each run of the rewrite reads the clock, so a code that ends meanwhile is not decided.
		const decided = await rewriteAt(v.devices, name, v.runtime.clock, (held, at) =>
			held.state === "pending" && held.expiresAt > at ? { ...held, ...decision } : undefined,
		).catch((error: unknown) => {
			// The write may or may not have landed.
			audited("device.decision_outcome_unknown", { action, client: device.clientId });
			throw error;
		});
		if (decided && decided.before.expiresAt <= decided.at) return oauthError(410, "expired_token");
		// Decided once: a decision made first, here or elsewhere, stands.
		if (decided?.before.state !== "pending") {
			return oauthError(409, "already_decided");
		}
		audited(action === "approve" ? "device.approved" : "device.denied", {
			client: device.clientId,
			scope: device.scope.join(" "),
		});
		const status = action === "approve" ? "approved" : "denied";
		return jsonAnswer(200, { status, client_id: device.clientId });
	};
	return answeringUnavailable(answer, (_request, { what }) => {
		v.runtime.log.warn("device-grant.unavailable", { what, route: "verification" });
	});
}

/** The handler over the contracts the assembly gives. */
export const verificationOver = async (c: BuildContext<Settings>) =>
	verificationWith({
		sessions: await c.get(sessions),
		attempts: await c.get(attemptLimit),
		audit: await c.get(audit),
		devices: await c.get(deviceStore),
		userCodes: await c.get(userCodes),
		runtime: c,
		settings: c.section,
		tokens: await c.get(tokens),
	});
