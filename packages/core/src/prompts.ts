/**
 * Everything the core needs from the user, as an interface: the CLI answers in the terminal,
 * a bot or a GUI answers its own way. Every question carries a stable `id` (to answer it
 * programmatically) and an English `message` (to show it). Messages carry no colors and no
 * trailing punctuation: formatting is up to the implementation.
 */

export type QuestionId =
  // sign-in
  | "my-telegram-org-code"
  | "api-id"
  | "api-hash"
  | "phone-code"
  | "cloud-password"
  // local password
  | "local-password"
  | "new-local-password"
  | "repeat-local-password"
  | "weak-password"
  // unlock
  | "unlock-method"
  | "yubikey-pin-entry"
  | "yubikey-pin"
  // YubiKey setup
  | "yubikey-serial"
  | "yubikey-new-pin"
  | "yubikey-repeat-pin"
  | "yubikey-change-puk"
  | "yubikey-new-puk"
  | "yubikey-repeat-puk"
  | "yubikey-replace-management-key"
  | "yubikey-management-key"
  | "yubikey-use-retired-slot";

export interface Question {
  id: QuestionId;
  message: string;
}

export interface ConfirmQuestion extends Question {
  default: boolean;
}

export interface ChoiceQuestion<T> extends Question {
  options: { value: T; label: string }[];
  default: T;
}

/**
 * - title: a heading before a group of messages or questions
 * - info: plain information
 * - hint: secondary details
 * - action: the user has to do something outside the program (touch a key, confirm a dialog)
 * - success / warning / error: outcomes
 */
export type NoticeLevel = "title" | "info" | "hint" | "action" | "success" | "warning" | "error";

export interface Prompts {
  notice(level: NoticeLevel, ...lines: string[]): void;
  /** A visible answer, trimmed. */
  text(question: Question): Promise<string>;
  /** A hidden answer (password, PIN), returned as typed. */
  secret(question: Question): Promise<string>;
  confirm(question: ConfirmQuestion): Promise<boolean>;
  /** Returns the value of one of the options. */
  choose<T>(question: ChoiceQuestion<T>): Promise<T>;
}
