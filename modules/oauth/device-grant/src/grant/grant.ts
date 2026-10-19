import type { Grant, GrantOutcome, OAuthError } from "@mod/grants";
import type { BuildContext, Runtime } from "@mod/kernel";
import { type Sessions, sessions } from "@mod/session";
import { type SubjectRevocation, subjectRevocation } from "@mod/subject-revocation";
import { deviceGrantType } from "../contract.ts";
import { type Approval, type Device, fromStored, rewriteAt } from "../record.ts";
import { type DeviceStore, deviceStore } from "../store.ts";

/** RFC 8628 §3.5's answers to a poll, owned by this grant beside OAuth's own. */
type PollError = "authorization_pending" | "slow_down" | "access_denied" | "expired_token";

/** What a poll decides, in this grant's own words. */
type Poll = "not-yours" | "expired" | "poll-too-soon" | "pending" | "denied" | "issue";

/** Each refusal as the token endpoint answers it. */
const answered: Readonly<Record<Exclude<Poll, "issue">, OAuthError | PollError>> = {
	"not-yours": "invalid_grant",
	expired: "expired_token",
	"poll-too-soon": "slow_down",
	pending: "authorization_pending",
	denied: "access_denied",
};

/** RFC 8628 §3.5: a poll that comes before its interval is over widens the interval by this. */
const slowerBy = 5000;

/** What a poll by `clientId` decides on the record it reads, and what it writes there; another client's writes nothing. */
function polled(
	device: Device,
	clientId: string,
	now: number,
): { readonly answer: Poll; readonly left?: Device } {
	if (device.clientId !== clientId || device.state === "taken") return { answer: "not-yours" };
	if (device.expiresAt <= now) return { answer: "expired" };
	const seen = { ...device, lastPollAt: now };
	if (device.lastPollAt !== undefined && now - device.lastPollAt < device.intervalMs) {
		return { answer: "poll-too-soon", left: { ...seen, intervalMs: device.intervalMs + slowerBy } };
	}
	switch (device.state) {
		case "pending":
			return { answer: "pending", left: seen };
		case "approved":
			return { answer: "issue", left: { ...seen, state: "taken" } };
		case "denied":
			return { answer: "denied", left: { ...seen, state: "taken" } };
	}
}

/** The access a device's approval grants its client. */
const grantOf = (device: Device, approval: Approval) => ({
	subject: approval.subject,
	issuedTo: device.clientId,
	audience: device.audience,
	scope: device.scope,
	amr: approval.amr,
	authenticatedAt: approval.authenticatedAt,
	...(approval.authenticatedAtUnknown ? { authenticatedAtUnknown: true as const } : {}),
});

/** The approving session, for the issuance policies, when the approval kept one. */
const sessionOf = (approval: Approval) => (approval.session ? { session: approval.session } : {});

/** The device code grant: a device polls until its code is approved, denied or ends. */
export function grantWith(
	devices: DeviceStore,
	revocation: SubjectRevocation,
	open: Pick<Sessions, "entryOf">,
	runtime: Runtime,
): Grant {
	const refused = (error: OAuthError | PollError): GrantOutcome => ({ kind: "error", error });
	/** A token is answered only while the approving session enters at use, as a code redemption is. */
	const stillOpen = async (approval: Approval) =>
		approval.session === undefined || (await open.entryOf(approval.session)).kind === "entered";
	return {
		grantType: deviceGrantType,
		handle: async ({ client, param, admits, issue }) => {
			const code = param("device_code");
			if (!code)
				return { kind: "error", error: "invalid_request", description: "device_code is required" };
			const name = devices.nameOf(code);
			// Asked before the poll takes the approval, so a refusal leaves the code to a later poll.
			const seen = fromStored(await devices.read(name));
			if (seen?.state === "approved" && seen.approval && seen.clientId === client.id) {
				if (!(await stillOpen(seen.approval))) return refused("invalid_grant");
				const admitted = await admits(grantOf(seen, seen.approval), sessionOf(seen.approval));
				if (admitted.kind === "refused") return admitted;
			}
			const read = await rewriteAt(devices, name, runtime.clock, (held, at) => {
				return polled(held, client.id, at).left;
			});
			if (!read) return refused("invalid_grant");
			const { before, at } = read;
			const { answer } = polled(before, client.id, at);
			if (answer !== "issue") return refused(answered[answer]);
			const approval = before.approval;
			if (!approval) return refused("invalid_grant");
			if ((await revocation.check(approval.subject, approval.authenticatedAt)) === "revoked") {
				return refused("invalid_grant");
			}
			const judged = await issue(grantOf(before, approval), sessionOf(approval));
			if (judged.kind === "refused") return judged;
			// A logout that came while the token was being made: it is never answered, so reaches no one.
			if (!(await stillOpen(approval))) return refused("invalid_grant");
			const issued = judged.access;
			return {
				kind: "issued",
				body: {
					access_token: issued.token,
					token_type: issued.tokenType,
					expires_in: issued.expiresIn,
					scope: before.scope.join(" "),
				},
			};
		},
	};
}

/** The grant over the contracts the assembly gives. */
export const grantOver = async (c: BuildContext<unknown>) =>
	grantWith(await c.get(deviceStore), await c.get(subjectRevocation), await c.get(sessions), c);
