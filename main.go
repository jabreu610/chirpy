package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sync/atomic"
)

const metricsTemplate = `<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`

type errorBody struct {
	Error string `json:"error"`
}

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (c *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		c.fileserverHits.Add(1)
		next.ServeHTTP(w, req)
	})
}

func (c *apiConfig) handlerMetric(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	msg := fmt.Sprintf(metricsTemplate, c.fileserverHits.Load())
	io.WriteString(w, msg)
}

func (c *apiConfig) handlerMetricReset(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	c.fileserverHits.Swap(0)
	w.WriteHeader(200)
}

func cleanChirp(msg string) string {
	replacement := "****"
	blockList := []string{"kerfuffle", "fornax", "sharbert"}
	result := msg
	for _, old := range blockList {
		re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(old))
		result = re.ReplaceAllString(result, replacement)
	}
	return result
}

func processError(msg string, w http.ResponseWriter) {
	respErr := errorBody{
		Error: msg,
	}
	d, err := json.Marshal(respErr)
	if err != nil {
		fmt.Printf("error marshalling JSON: %v", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(400)
	w.Write(d)
}

func handlerValidateChirp(w http.ResponseWriter, req *http.Request) {
	type requestBody struct {
		Body string `json:"body"`
	}
	type successResp struct {
		CleanedBody string `json:"cleaned_body"`
	}
	var body requestBody
	dec := json.NewDecoder(req.Body)
	if err := dec.Decode(&body); err != nil {
		processError("Something went wrong", w)
		return
	}
	if len(body.Body) > 140 {
		processError("Chirp is too long", w)
		return
	}
	respBody := successResp{
		CleanedBody: cleanChirp(body.Body),
	}
	d, err := json.Marshal(respBody)
	if err != nil {
		fmt.Printf("error marshalling JSON: %v", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(200)
	w.Write(d)
}

func handlerHealth(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	io.WriteString(w, "OK")
}

func main() {
	mux := http.NewServeMux()
	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}
	config := apiConfig{}
	fileserverHandler := http.StripPrefix("/app", http.FileServer(http.Dir(".")))
	mux.Handle("/app/", config.middlewareMetricsInc(fileserverHandler))
	mux.HandleFunc("GET /api/healthz", handlerHealth)
	mux.HandleFunc("POST /api/validate_chirp", handlerValidateChirp)
	mux.HandleFunc("GET /admin/metrics", config.handlerMetric)
	mux.HandleFunc("POST /admin/reset", config.handlerMetricReset)
	server.ListenAndServe()
}
