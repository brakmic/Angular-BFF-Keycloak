import 'express-session';

declare module 'express-session' {
  export interface SessionData {
    code_verifier?: string;
    code_challenge?: string;
    oauthState?: string;
    user?: any;
    initTimestamp?: number;
  }
}
