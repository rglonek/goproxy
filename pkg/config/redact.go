package config

// Redacted returns a copy of the config with every secret replaced, so that it
// can be printed by the admin listener without handing out credentials.
func Redacted(c *Config) *Config {
	if c == nil {
		return nil
	}
	copied := *c
	copied.Auth = make(map[string]*Auth, len(c.Auth))
	for name, auth := range c.Auth {
		if auth == nil {
			continue
		}
		redacted := *auth
		if auth.Basic != nil {
			basic := *auth.Basic
			basic.Users = make([]User, len(auth.Basic.Users))
			for i, user := range auth.Basic.Users {
				if user.Password != "" {
					user.Password = "REDACTED"
				}
				if user.PasswordHash != "" {
					user.PasswordHash = "REDACTED"
				}
				basic.Users[i] = user
			}
			redacted.Basic = &basic
		}
		if auth.Token != nil {
			token := *auth.Token
			token.Tokens = make([]Token, len(auth.Token.Tokens))
			for i, t := range auth.Token.Tokens {
				if t.Value != "" {
					t.Value = "REDACTED"
				}
				token.Tokens[i] = t
			}
			redacted.Token = &token
		}
		copied.Auth[name] = &redacted
	}
	return &copied
}
