package main

import (
	"fmt"
	"net/http"

	"github.com/lithammer/shortuuid"
	"github.com/rglonek/logger"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		uuid := shortuuid.New()
		log := logger.NewLogger().WithPrefix(uuid + " " + r.RemoteAddr + " ")
		// Log request details
		log.Info("Path=%s Method=%s Host=%s", r.URL.Path, r.Method, r.Host)

		// Log headers
		log.Info("  Headers:")
		for name, values := range r.Header {
			for _, value := range values {
				log.Info("    %s: %s", name, value)
			}
		}

		// Log GET variables
		log.Info("  GET variables:")
		for key, values := range r.URL.Query() {
			for _, value := range values {
				log.Info("    %s: %s", key, value)
			}
		}

		// Parse form data to access POST variables
		if err := r.ParseForm(); err != nil {
			log.Error("  Error parsing form: %s", err)
		}

		// Log POST variables
		log.Info("  POST variables:")
		for key, values := range r.PostForm {
			for _, value := range values {
				log.Info("    %s: %s", key, value)
			}
		}

		w.Write([]byte("OK"))
	})

	fmt.Println("Starting server on :8081")
	if err := http.ListenAndServe(":8081", nil); err != nil {
		panic(err)
	}

}
