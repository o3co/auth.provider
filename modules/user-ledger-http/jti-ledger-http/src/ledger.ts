import type { JtiLedger } from "@mod/jwt-bearer";
import { type LogFields, Unavailable } from "@mod/kernel";
import { type Narrower, type Outbound, postJson } from "@mod/outbound";

export interface LedgerParts {
	readonly issuer: string;
	readonly url: string;
	readonly out: Outbound;
	/** The credential, a Bearer token unless `credentialHeader` names the header it goes as; none sends none. */
	readonly credential: string | undefined;
	readonly credentialHeader: string | undefined;
	readonly narrower: Narrower;
	readonly warn: (event: string, fields: LogFields) => void;
}

/** The longest jti the ledger records, in UTF-8 bytes. */
const jtiBytesMax = 256;

/** One issuer's jti ledger, asked over HTTP on every assertion, by the status of its answer alone. */
export function ledgerAt(parts: LedgerParts): JtiLedger {
	const { issuer, url, out, credential, credentialHeader, narrower, warn } = parts;
	/** Logs why the ledger failed, by its kind or status alone, and answers unavailable. */
	const failed = (why: { reason: string } | { status: number }) => {
		warn("jti-ledger-http.ledger_failed", why);
		return new Unavailable("jti-ledger-http");
	};
	return {
		issuer,
		async spend({ jti, keepUntil }) {
			// The ledger refuses a longer one with a 400: told the same, without sending it.
			if (Buffer.byteLength(jti, "utf8") > jtiBytesMax) throw failed({ reason: "jti-too-long" });
			// Its own two members alone: the jti as sent, and until when it stays used, in whole seconds.
			const body = { jti, exp: Math.ceil(keepUntil / 1000) };
			const answer = await postJson(
				out,
				{ url, body, credential, credentialHeader, narrower },
				(reason) => failed({ reason }),
			);
			// By the status alone: the body is never read, so nothing the ledger says is told on.
			if (answer.status === 204) return "first";
			if (answer.status === 409) return "replayed";
			throw failed({ status: answer.status });
		},
	};
}
