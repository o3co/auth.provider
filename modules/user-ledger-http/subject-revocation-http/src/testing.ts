import type { z } from "zod";
import type { section } from "./section.ts";

export type SubjectRevocationHttpSettings = z.input<typeof section>;

/** A credential for tests: 32 bytes of key material as base64url, of many byte values. */
export const testCredential = "Kq3vX9pLm2Rt7Yw4Nc8Bz1Hd6Fj0Gs5Ua-Ve_Io2LxM";

/** The section of a test's configuration: the test credential, from documentation's 198.51.100.0/24. */
export function subjectRevocationHttpConfig(settings: Partial<SubjectRevocationHttpSettings> = {}) {
	return {
		"subject-revocation-http": {
			credential: testCredential,
			sources: ["198.51.100.0/24"],
			...settings,
		},
	};
}
