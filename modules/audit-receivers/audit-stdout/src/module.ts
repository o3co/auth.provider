import { auditReceivers } from "@mod/audit";
import { defineModule } from "@mod/kernel";

export default defineModule({ name: "audit-stdout", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(auditReceivers).by(() => ({
		name: "stdout",
		receive: (event) =>
			new Promise<void>((done, failed) => {
				// The callback form, so a write that fails rejects instead of being lost unseen.
				process.stdout.write(`${JSON.stringify(event)}\n`, (error) =>
					error ? failed(error) : done(),
				);
			}),
	})),
]);
