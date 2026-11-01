import { auditReceivers } from "@mod/audit";
import { defineModule } from "@mod/kernel";

/** The streams this receiver has listened to, so however many compositions start, each gets one listener. */
const heard = new WeakSet<NodeJS.WritableStream>();

export default defineModule({ name: "audit-stdout", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(auditReceivers).by(() => {
		const out = process.stdout;
		// Once its reader has gone, a write fails and the stream emits 'error', which unheard would end
		// the process. Heard, the write's own callback carries the failure to `audit`, and every later
		// write fails as one.
		if (!heard.has(out)) {
			heard.add(out);
			out.on("error", () => {});
		}
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
