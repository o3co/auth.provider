import { z } from "zod";

const headerName = z.string().regex(/^[a-z0-9-]+$/);

const headerText =
	"The header holding the client's certificate: lower-case letters, digits and `-`; `pem` has no default header.";
const dialectText =
	"The form a trusted proxy forwards the client's certificate in: `rfc9440` (byte sequences) with `header` and `chain-header`, `pem` (one PEM block, URL-encoded or not) with `header`, or `xfcc` (Envoy's form, the chain in the same header) with `header`.";

/** Where a trusted proxy forwards the client's certificate, and in what form. */
export const certificateSettings = z.discriminatedUnion("dialect", [
	z.strictObject({
		dialect: z.literal("rfc9440").describe(dialectText),
		header: headerName.default("client-cert").describe(headerText),
		"chain-header": headerName
			.default("client-cert-chain")
			.describe(
				"The header holding the chain behind the certificate, for `rfc9440`: lower-case letters, digits and `-`.",
			),
	}),
	z.strictObject({
		dialect: z.literal("pem").describe(dialectText),
		header: headerName.describe(headerText),
	}),
	z.strictObject({
		dialect: z.literal("xfcc").describe(dialectText),
		header: headerName.default("x-forwarded-client-cert").describe(headerText),
	}),
]);
