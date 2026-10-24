import { fakeHttp, type Party } from "@mod/conformance";
import { passkeyWitnessLedger } from "@mod/ledger-fakes";

/**
 * A ledger answering passkey-witness-http's calls as ledger-fakes plays them: a mark per subject,
 * set only where none is, read with its token, and withdrawn only by its token; and the section that
 * points an app at it.
 */
export async function witnessLedger(): Promise<Party> {
	const witness = passkeyWitnessLedger();
	// Anything but a call it holds is unavailable, so a wrong set-up shows.
	const ledger = await fakeHttp((asked) => witness.answer(asked) ?? { status: 404 });
	const urls = witness.urls(ledger.base);
	return {
		base: ledger.base,
		config: {
			"passkey-witness-http": {
				"read-url": urls.read,
				"enroll-url": urls.enroll,
				"withdraw-url": urls.withdraw,
				credential: witness.credential,
			},
		},
		stop: ledger.stop,
	};
}
