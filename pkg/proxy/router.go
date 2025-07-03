package proxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"slices"
	"strings"
)

func (p *proxy) setRouter() error {
	for _, rule := range p.config.Rules {
		if rule.ProxyRule != nil {
			remote, err := url.Parse(rule.ProxyRule.ProxyURL)
			if err != nil {
				return err
			}
			rule.ProxyRule.proxy = httputil.NewSingleHostReverseProxy(remote)
			if rule.ProxyRule.ProxyTargetAcceptSelfSigned {
				rule.ProxyRule.proxy.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
			}
		}
	}
	return nil
}

type handler struct {
	proxy *proxy
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rule, index := h.proxy.config.Rules.Match(r.Host, r.URL.Path)
	if rule == nil {
		h.proxy.log.Info("Client=%s Host=%s Path=%s Mod=NotFound", r.RemoteAddr, r.Host, r.URL.Path)
		http.NotFound(w, r)
		return
	}

	authType := "None"

	// try token auth if enabled
	if rule.TokenAuth != nil {
		token := ""
		if rule.TokenAuth.TokenAuthHeader != "" {
			token = r.Header.Get(rule.TokenAuth.TokenAuthHeader)
		} else {
			token = r.Header.Get("X-TOKEN")
		}
		idx := slices.Index(rule.TokenAuth.Tokens, token)
		if token == "" || idx == -1 {
			h.proxy.log.Info("Client=%s Host=%s Path=%s Mod=TokenAuth Rule=%d Failed ReqToken=%s", r.RemoteAddr, r.Host, r.URL.Path, index, token)
			if rule.BasicAuth == nil {
				// token auth failed, and no basic auth is enabled, so we need to return 401
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		} else {
			// token auth succeeded, so we can continue
			authType = "Token"
			h.proxy.log.Info("Client=%s Host=%s Path=%s Mod=TokenAuth Rule=%d Success TokenIdx=%d", r.RemoteAddr, r.Host, r.URL.Path, index, idx)
		}
	}

	// try basic auth if enabled and token auth did not succeed
	if authType == "None" && rule.BasicAuth != nil {
		authType = "Basic"
		user, pass, ok := r.BasicAuth()
		if !ok || user != rule.BasicAuth.User || pass != rule.BasicAuth.Pass {
			h.proxy.log.Info("Client=%s Host=%s Path=%s Mod=BasicAuth User=%s Rule=%d Failed", r.RemoteAddr, r.Host, r.URL.Path, user, index)
			w.Header().Set("WWW-Authenticate", "Basic")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		h.proxy.log.Info("Client=%s Host=%s Path=%s Mod=BasicAuth User=%s Rule=%d Success", r.RemoteAddr, r.Host, r.URL.Path, user, index)
	}

	if rule.RedirectRule != nil {
		h.proxy.log.Info("Client=%s Host=%s Path=%s AuthType=%s Mod=Redirect Target=%s Rule=%d", r.RemoteAddr, r.Host, r.URL.Path, authType, rule.RedirectRule.RedirectURL, index)
		http.Redirect(w, r, rule.RedirectRule.RedirectURL, rule.RedirectRule.RedirectStatusCode)
		return
	}

	if rule.ServeRule != nil {
		h.proxy.log.Info("Client=%s Host=%s Path=%s AuthType=%s Mod=Serve LocalDir=%s Rule=%d", r.RemoteAddr, r.Host, r.URL.Path, authType, rule.ServeRule.ServeLocalDir, index)
		if strings.HasPrefix(rule.PathMatch, "^") {
			r.URL.Path = rule.pathRegex.ReplaceAllString(r.URL.Path, "")
		} else {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, rule.PathMatch)
		}
		http.FileServer(http.Dir(rule.ServeRule.ServeLocalDir)).ServeHTTP(w, r)
		return
	}

	if rule.RespondRule != nil {
		if rule.RespondRule.RespondBodyFile != "" {
			fh, err := os.Open(rule.RespondRule.RespondBodyFile)
			if err != nil {
				h.proxy.log.Error("Client=%s Host=%s Path=%s Mod=Respond Error=%s Rule=%d", r.RemoteAddr, r.Host, r.URL.Path, err, index)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer fh.Close()
			h.proxy.log.Info("Client=%s Host=%s Path=%s AuthType=%s Mod=Respond StatusCode=%d File=%s Rule=%d", r.RemoteAddr, r.Host, r.URL.Path, authType, rule.RespondRule.RespondStatusCode, rule.RespondRule.RespondBodyFile, index)
			w.WriteHeader(rule.RespondRule.RespondStatusCode)
			io.Copy(w, fh)
		} else {
			h.proxy.log.Info("Client=%s Host=%s Path=%s AuthType=%s Mod=Respond StatusCode=%d Body=%s Rule=%d", r.RemoteAddr, r.Host, r.URL.Path, authType, rule.RespondRule.RespondStatusCode, rule.RespondRule.RespondBody, index)
			http.Error(w, rule.RespondRule.RespondBody, rule.RespondRule.RespondStatusCode)
		}
		return
	}

	if rule.ProxyRule != nil {
		h.proxy.log.Info("Client=%s Host=%s Path=%s AuthType=%s Mod=Proxy Target=%s Rule=%d", r.RemoteAddr, r.Host, r.URL.Path, authType, rule.ProxyRule.ProxyURL, index)
		if rule.ProxyRule.ProxyRewriteHostHeader != "" {
			r.Host = rule.ProxyRule.ProxyRewriteHostHeader
		}
		if authType == "Token" && !rule.TokenAuth.ForwardHeader {
			headerName := rule.TokenAuth.TokenAuthHeader
			if headerName == "" {
				headerName = "X-TOKEN"
			}
			r.Header.Del(headerName)
		}
		if authType == "Basic" {
			r.Header.Del("Authorization")
			if rule.BasicAuth.SetUserHeader != nil {
				r.Header.Set(*rule.BasicAuth.SetUserHeader, rule.BasicAuth.User)
			}
			if rule.BasicAuth.SetUserGETVar != nil {
				q := r.URL.Query()
				q.Set(*rule.BasicAuth.SetUserGETVar, rule.BasicAuth.User)
				r.URL.RawQuery = q.Encode()
			}
		}
		if !rule.ProxyRule.ProxyAppendPath {
			if strings.HasPrefix(rule.PathMatch, "^") {
				r.URL.Path = rule.pathRegex.ReplaceAllString(r.URL.Path, "")
			} else {
				r.URL.Path = strings.TrimPrefix(r.URL.Path, rule.PathMatch)
			}
		}
		for idx, header := range rule.ProxyRule.ProxyRemoveHeaders {
			rx := rule.ProxyRule.proxyRemoveHeadersRegex[idx]
			if rx != nil {
				for k := range r.Header {
					if rx.MatchString(k) {
						r.Header.Del(k)
					}
				}
			} else {
				r.Header.Del(header)
			}
		}
		for key, value := range rule.ProxyRule.ProxySetHeaders {
			r.Header.Set(key, value)
		}
		rule.ProxyRule.proxy.ServeHTTP(w, r)
		return
	}
}
