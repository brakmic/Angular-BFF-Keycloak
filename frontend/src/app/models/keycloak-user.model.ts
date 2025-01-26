export interface KeycloakUser {
  provider: string;
  id: string;
  displayName: string;
  username: string;
  emails: Array<{ value: string }>;
  _raw: string;
  _json: {
    sub: string;
    email_verified: boolean;
    name: string;
    preferred_username: string;
    given_name: string;
    family_name: string;
    email: string;
  };
  _id_token: string;
}
