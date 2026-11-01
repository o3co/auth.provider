import { auditReceivers } from "@mod/audit";
import { defineModule } from "@mod/kernel";

export default defineModule({ name: "audit-stdout", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(auditReceivers).by(() => {
		const out = process.stdout;
		// Once its reader has gone, a write fails and the stream's 'error' is heard by kernel: the write's
		// own callback carries the failure to `audit`, and every later write fails as one.
		return {
			name: "stdout",
			receive: (event) =>
				new Promise<void>((done, failed) => {
					// The callback form, so a write that fails rejects instead of being lost unseen.
					out.write(`${JSON.stringify(event)}\n`, (error) => (error ? failed(error) : done()));
				}),
		};
	}),
]);
