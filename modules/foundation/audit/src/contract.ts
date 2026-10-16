import { contract, extensionPoint } from "@mod/kernel";

/** What an emitter records. The kind and the attributes are the emitter's vocabulary. */
export interface AuditRecord {
	readonly kind: string;
	readonly subject?: string;
	readonly attributes?: Readonly<Record<string, string>>;
}

/** A record as receivers get it, stamped with `kernel`'s clock (epoch ms). */
export interface AuditEvent extends AuditRecord {
	readonly at: number;
}

export interface Audit {
	/** Hands the event to the receivers and returns at once; their failures never reach the caller. */
	record(event: AuditRecord): void;
	/** The events each named receiver did not take since boot (failed or past its pending limit). */
	lost(): Readonly<Record<string, number>>;
}

export const audit = contract<Audit>("audit");

/** A place audit events go. Keeping and retrying them are its own. */
export interface AuditReceiver {
	readonly name: string;
	receive(event: AuditEvent): Promise<void>;
}

export const auditReceivers = extensionPoint<AuditReceiver>("audit.receivers", {
	multiplicity: "keyed",
	keyOf: (receiver) => receiver.name,
});

/** An event a module records: the attributes it may carry, and when it is recorded. */
export interface AuditEventDeclaration {
	readonly attributes: readonly string[];
	readonly when: string;
}

/** The events a module declares, by kind; its `./audit-events` exports them for the audit event reference. */
export const auditEvents = <const E extends Readonly<Record<string, AuditEventDeclaration>>>(
	events: E,
): E => Object.freeze(events);

/** Records only the kinds declared, with only their attributes; an undeclared one throws. */
export function declaredAudit<const E extends Readonly<Record<string, AuditEventDeclaration>>>(
	recorder: Pick<Audit, "record">,
	events: E,
) {
	return {
		record<K extends keyof E & string>(
			kind: K,
			event: {
				readonly subject?: string;
				readonly attributes?: Partial<Record<E[K]["attributes"][number], string>>;
			} = {},
		): void {
			const declared = events[kind];
			if (!declared) throw new Error(`${kind} is not declared`);
			for (const name of Object.keys(event.attributes ?? {})) {
				if (!declared.attributes.includes(name))
					throw new Error(`${kind} does not declare ${name}`);
			}
			recorder.record({
				kind,
				...(event.subject === undefined ? {} : { subject: event.subject }),
				...(event.attributes === undefined
					? {}
					: { attributes: event.attributes as Readonly<Record<string, string>> }),
			});
		},
	};
}
