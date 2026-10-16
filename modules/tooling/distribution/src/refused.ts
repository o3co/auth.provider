/** Every refusal a refused app wrote, one per `refused <where>: <reason>` line, past any log line. */
export const refusalsIn = (output: string): string[] =>
	output
		.split("\n")
		.filter((line) => line.startsWith("refused "))
		.map((line) => line.slice("refused ".length));
