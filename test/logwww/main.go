package main

import (
	"fmt"
	"net/http"
	"strconv"
	"sync/atomic"

	"github.com/rglonek/logger"
)

// requests numbers the requests: an id that sorts in arrival order is more
// useful in a log than a random one.
var requests atomic.Uint64

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		id := strconv.FormatUint(requests.Add(1), 10)
		log := logger.NewLogger().WithPrefix(id + " " + r.RemoteAddr + " ")
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
