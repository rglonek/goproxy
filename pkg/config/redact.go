package config

// redacted is what a secret is replaced with.
const redacted = "REDACTED"

// Redacted returns a copy of the config with every secret replaced, so that it
// can be printed by the admin listener without handing out credentials. The
// original is not modified.
//
// A value read through value_env, value_file or password_file never enters the
// config at all - only the variable's name or the file's path does - so there
// is nothing of it to redact. What is redacted is the literal secrets: basic
// passwords and hashes, token values, and the value of any header whose name
// says it is a credential (see SensitiveHeader).
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
		redactedAuth := *auth
		if auth.Basic != nil {
			basic := *auth.Basic
			basic.Users = make([]User, len(auth.Basic.Users))
			for i, user := range auth.Basic.Users {
				if user.Password != "" {
					user.Password = redacted
				}
				if user.PasswordHash != "" {
					user.PasswordHash = redacted
				}
				basic.Users[i] = user
			}
			redactedAuth.Basic = &basic
		}
		if auth.Token != nil {
			token := *auth.Token
			token.Tokens = make([]Token, len(auth.Token.Tokens))
			for i, t := range auth.Token.Tokens {
				if t.Value != "" {
					t.Value = redacted
				}
				token.Tokens[i] = t
			}
			redactedAuth.Token = &token
		}
		copied.Auth[name] = &redactedAuth
	}

	if c.Rules != nil {
		copied.Rules = make([]*Rule, len(c.Rules))
	}
	for i, rule := range c.Rules {
		if rule == nil {
			continue
		}
		redactedRule := *rule
		if rule.Proxy != nil {
			proxy := *rule.Proxy
			proxy.RequestHeaders = redactHeaders(rule.Proxy.RequestHeaders)
			proxy.ResponseHeaders = redactHeaders(rule.Proxy.ResponseHeaders)
			redactedRule.Proxy = &proxy
		}
		if rule.Respond != nil {
			respond := *rule.Respond
			respond.Headers = redactHeaderMap(rule.Respond.Headers)
			redactedRule.Respond = &respond
		}
		copied.Rules[i] = &redactedRule
	}
	return &copied
}

func redactHeaders(h *Headers) *Headers {
	if h == nil {
		return nil
	}
	copied := *h
	if h.Set != nil {
		copied.Set = make(map[string]HeaderValue, len(h.Set))
	}
	for name, value := range h.Set {
		// the prefix ("Bearer ") is no secret; the literal behind it is
		if value.Value != "" && SensitiveHeader(name) {
			value.Value = redacted
		}
		copied.Set[name] = value
	}
	return &copied
}

func redactHeaderMap(headers map[string]string) map[string]string {
	if headers == nil {
		return nil
	}
	copied := make(map[string]string, len(headers))
	for name, value := range headers {
		if value != "" && SensitiveHeader(name) {
			value = redacted
		}
		copied[name] = value
	}
	return copied
}
