/**
 * tg-secret-core: Telegram secret chats for Node.js.
 * Start with TgSecret.open(); everything else here is what its API hands out or needs.
 */

// must come first: prepares the Node.js environment before teleproto loads
import "./nodeCompat.js";

// session
export { TgSecret, type OpenOptions, type TgSecretEvents } from "./tgSecret.js";
export type { ChoiceQuestion, ConfirmQuestion, NoticeLevel, Prompts, Question, QuestionId } from "./prompts.js";
export { platformDataRoot, resolveDataDir, SEPARATE_DIR_NAME, SHARED_DIR_NAME, type DataDirOptions } from "./dataDir.js";
export { isNetworkError, silent, type DebugLogger } from "./net/client.js";

// accounts
export {
  accountInUse,
  AccountLockedError,
  accountsDir,
  listAccounts,
  normalizePhone,
  openAccount,
  type Account,
  type AccountListItem,
  type AccountState,
} from "./account.js";

// secret chats
export {
  errorText,
  LockedError,
  previewText,
  SecretChatManager,
  type ChatMessage,
  type SecretChatEvents,
  type SendStatus,
} from "./secret/manager.js";
export type { SecretChat } from "./secret/store.js";
export type { DecryptedMedia, FileKind, FileMedia } from "./secret/media.js";
export { keyVisualizationBytes } from "./secret/crypto.js";
export { isDangerous } from "./media/files.js";

// local encryption and unlock methods
export { AccessManager } from "./security/access.js";
export { describeSlot } from "./security/unlock.js";
export { checkPassword, MIN_PASSWORD_LENGTH, TooManyAttemptsError, UNLOCK_ATTEMPTS } from "./security/password.js";
export { WrongPasswordError, type HelloSlot, type PasswordSlot, type PivSlot, type Slot } from "./security/vault.js";
