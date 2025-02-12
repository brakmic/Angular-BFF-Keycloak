import 'passport';

declare module 'passport' {
  export interface AuthenticateOptions {
    scope?: string | string[];
    code_challenge?: string;
    code_challenge_method?: string;
    state?: string;
  }
}
