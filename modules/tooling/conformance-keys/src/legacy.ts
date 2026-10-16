import { onLegacy } from "@mod/conformance-legacy";
import { type KeysPart, keysArea } from "./area.ts";

const hocon = (value: string) => `"""${value}"""`;

/** The legacy build reads its keys from a key-store block of its configuration file. */
function keyStore(part: KeysPart): string {
	const lines: string[] = [];
	const s = part.signing;
	if (s?.alg === "HS256") {
		lines.push(
			`algorithm = "HS256"`,
			`kid = ${JSON.stringify(s.kid)}`,
			`secret = "${s.secretHex}"`,
		);
	} else if (s) {
		lines.push(
			`algorithm = "${s.alg}"`,
			`kid = ${JSON.stringify(s.kid)}`,
			`privateKey = ${hocon(s.privatePem)}`,
			`publicKey = ${hocon(s.publicPem)}`,
		);
	}
	if (part.previous) {
		const entries = part.previous.map(
			(p) =>
				`{ kid = ${JSON.stringify(p.kid)}, publicKey = ${hocon(p.publicPem)}, expiresAt = "${p.expiresAt}" }`,
		);
		lines.push(`previousKeys = [${entries.join(", ")}]`);
	}
	if (part.unknownSetting) lines.push("notASetting = 1");
	return `key-store { local { ${lines.join("\n")} } }\n`;
}

onLegacy(keysArea, { map: (part) => ({ settings: keyStore(part) }) });
