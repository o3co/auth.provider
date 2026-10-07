/**
 * The actions admission is asked about: the grades, a closed vocabulary core
 * owns, and the actions, a vocabulary the consumers contribute. A consumer
 * registers each action it admits under `contributes.admissionActions`, keyed
 * by the action's name, with one of the grades; a requirement decides by the
 * grade alone, so its table is exhaustive over `ADMISSION_GRADES` and names no
 * consumer's action. This file is the one home of the name grammar and of what
 * a registration may declare.
 */
/**
 * The grades, each deciding how a requirement treats an action: `use`
 * exercises the session; `grants_nothing` reads or refuses and gives nothing
 * to anyone, so a requirement may meet it on a session a record carries (the
 * MFA requirement does), while a token carrier is judged on the token's own
 * `amr` whatever the grade; `credential_change` adds or removes a way into
 * the account;
 * `remediation` is a requirement's own route, by which the session meets that
 * requirement, issued by core to the requirement that declared it.
 */
export declare const ADMISSION_GRADES: readonly ["use", "grants_nothing", "credential_change", "remediation"];
/** One of {@link ADMISSION_GRADES}. */
export type AdmissionGrade = (typeof ADMISSION_GRADES)[number];
/**
 * The grades an action registers with: every grade but `remediation`, which
 * only a requirement declares, for its own routes. `grants_nothing` exempts an
 * admission a record carries (a cookie, a code, a link) from a requirement's
 * baseline, never a token's.
 */
export type ActionGrade = Exclude<AdmissionGrade, "remediation">;
/** What the consumer is about to let the session do, as the requirements are asked about it: a name and a grade. */
export interface AdmissionAction {
    readonly name: string;
    readonly grade: AdmissionGrade;
}
/** What a consumer registers for one action under `contributes.admissionActions`, keyed by the action's name. */
export interface AdmissionActionDeclaration {
    readonly grade: ActionGrade;
}
/** Whether `name` is an action's name as registration admits it. */
export declare const isAdmissionActionName: (name: unknown) => name is string;
/**
 * What is wrong with registering `declaration` as the action `name`, or
 * `undefined` when nothing is: the name grammar, a declaration that is an
 * object, and a grade an action may register with.
 */
export declare function admissionActionProblem(name: string, declaration: unknown): string | undefined;
/**
 * `declaration` registered as the action `name`: the frozen `{ name, grade }`
 * the requirements are handed. The grade is read once, into the object that is
 * checked and registered. A `RangeError` names what
 * {@link admissionActionProblem} finds.
 */
export declare function registeredAdmissionAction(name: string, declaration: unknown): AdmissionAction;
//# sourceMappingURL=actions.d.mts.map