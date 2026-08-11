package proxy

import (
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

// respond answers with the canned status, body and headers of a respond_rule.
//
// v0.1.0 used http.Error here, which forces Content-Type: text/plain, adds
// X-Content-Type-Options: nosniff and appends a newline to the body, so a
// custom HTML error page could not be served.
func (h *handler) respond(w http.ResponseWriter, r *http.Request, rule *Rule, id identity) {
	rr := rule.RespondRule
	body := rule.respondBody
	if rr.RespondBodyFile != "" && rr.RespondBodyFileReload {
		reloaded, err := os.ReadFile(rr.RespondBodyFile)
		if err != nil {
			h.log.Error("Client=%s Host=%s Path=%s Mod=Respond Error=%s Rule=%s", h.clientIP(r), r.Host, r.URL.Path, err, rule)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		body = reloaded
	}

	if rr.RespondBodyFile != "" {
		h.log.Info("Client=%s Host=%s Path=%s AuthType=%s Mod=Respond StatusCode=%d File=%s Rule=%s", h.clientIP(r), r.Host, r.URL.Path, id.authType(), rr.RespondStatusCode, rr.RespondBodyFile, rule)
	} else {
		h.log.Info("Client=%s Host=%s Path=%s AuthType=%s Mod=Respond StatusCode=%d Rule=%s", h.clientIP(r), r.Host, r.URL.Path, id.authType(), rr.RespondStatusCode, rule)
	}

	header := w.Header()
	for key, value := range rr.RespondHeaders {
		header.Set(key, value)
	}
	if header.Get("Content-Type") == "" {
		if contentType := respondContentType(rr, body); contentType != "" {
			header.Set("Content-Type", contentType)
		}
	}
	if bodyAllowed(rr.RespondStatusCode) {
		header.Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(rr.RespondStatusCode)
		if r.Method != http.MethodHead {
			w.Write(body)
		}
		return
	}
	w.WriteHeader(rr.RespondStatusCode)
}

func respondContentType(rr *RespondRule, body []byte) string {
	if rr.RespondContentType != "" {
		return rr.RespondContentType
	}
	if rr.RespondBodyFile != "" {
		if byExtension := mime.TypeByExtension(filepath.Ext(rr.RespondBodyFile)); byExtension != "" {
			return byExtension
		}
	}
	if len(body) == 0 {
		return ""
	}
	return http.DetectContentType(body)
}

// bodyAllowed reports whether a response with this status may carry a body.
func bodyAllowed(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == http.StatusNoContent, status == http.StatusNotModified:
		return false
	}
	return true
}
