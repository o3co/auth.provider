/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
 * to anyone; `credential_change` adds or removes a way into the account;
 * `remediation` is a requirement's own route, by which the session meets that
 * requirement, issued by core to the requirement that declared it.
 */
export const ADMISSION_GRADES = Object.freeze([
	"use",
	"grants_nothing",
	"credential_change",
	"remediation",
] as const);

/** One of {@link ADMISSION_GRADES}. */
export type AdmissionGrade = (typeof ADMISSION_GRADES)[number];

/** The grades an action registers with: every grade but `remediation`, which only a requirement declares, for its own routes. */
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

/** An action's name: two lower-case identifiers joined by a dot, the consumer's and the verb's (`acme.export`). */
const ACTION_NAME = /^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/;

/** Whether `name` is an action's name as registration admits it. */
export const isAdmissionActionName = (name: unknown): name is string =>
	typeof name === "string" && ACTION_NAME.test(name);

/** Whether `grade` is one an action may register with. */
const isActionGrade = (grade: unknown): grade is ActionGrade =>
	grade !== "remediation" && (ADMISSION_GRADES as readonly unknown[]).includes(grade);

const isDeclaration = (value: unknown): value is { readonly grade?: unknown } =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * What is wrong with registering `declaration` as the action `name`, or
 * `undefined` when nothing is: the name grammar, a declaration that is an
 * object, and a grade an action may register with.
 */
export function admissionActionProblem(name: string, declaration: unknown): string | undefined {
	if (!isAdmissionActionName(name)) {
		return `an action's name is two lower-case identifiers joined by a dot, the consumer's and the verb's (acme.export), not ${JSON.stringify(name)}`;
	}
	if (!isDeclaration(declaration)) return "a declaration is an object, { grade }";
	const grade = declaration.grade;
	if (grade === "remediation") {
		return "remediation is not an action's grade: a requirement declares its own remediations, and core issues them to it";
	}
	if (!isActionGrade(grade)) {
		return `its grade must be one of ${ADMISSION_GRADES.filter((g) => g !== "remediation").join(", ")}, not ${JSON.stringify(grade) ?? String(grade)}`;
	}
	return undefined;
}

/**
 * `declaration` registered as the action `name`: the frozen `{ name, grade }`
 * the requirements are handed. The grade is read once, into the object that is
 * checked and registered. A `RangeError` names what
 * {@link admissionActionProblem} finds.
 */
export function registeredAdmissionAction(name: string, declaration: unknown): AdmissionAction {
	const read = isDeclaration(declaration) ? { grade: declaration.grade } : declaration;
	const problem = admissionActionProblem(name, read);
	if (problem !== undefined) {
		throw new RangeError(`admission action ${JSON.stringify(name)}: ${problem}`);
	}
	return Object.freeze({ name, grade: (read as AdmissionActionDeclaration).grade });
}
