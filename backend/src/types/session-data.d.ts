import 'express-session';

declare module 'express-session' {
  interface SessionData {
    code_verifier?: string;
    code_challenge?: string;
  }
}
