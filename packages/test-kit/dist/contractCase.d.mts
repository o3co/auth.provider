/**
 * What a suite of the kit answers: its cases, each a name and a run that
 * rejects when the implementation under test breaks the rule the name
 * states. Run each with any test runner's `it`.
 */
export interface ContractCase {
    readonly name: string;
    readonly run: () => Promise<void>;
}
//# sourceMappingURL=contractCase.d.mts.map