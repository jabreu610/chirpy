package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jabreu610/chirpy/internal/auth"
	"github.com/jabreu610/chirpy/internal/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

const metricsTemplate = `<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`

type chirpResponse struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

type userResponseBody struct {
	ID          uuid.UUID `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Email       string    `json:"email"`
	IsChirpyRed bool      `json:"is_chirpy_red"`
}

type authRequestPayload struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type errorBody struct {
	Error string `json:"error"`
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

func processError(msg string, code int, w http.ResponseWriter) {
	respErr := errorBody{
		Error: msg,
	}
	d, err := json.Marshal(respErr)
	if err != nil {
		fmt.Printf("error marshalling JSON: %v", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(code)
	w.Write(d)
}

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	env            string
	authSecret     string
	polkaAPIKey    string
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

func (c *apiConfig) handlerReset(w http.ResponseWriter, req *http.Request) {
	if c.env != "dev" {
		processError("Fobidden", 403, w)
		return
	}
	if err := c.db.UsersDBReset(req.Context()); err != nil {
		errMsg := fmt.Sprintf("Error occured while processing reset: %v", err)
		processError(errMsg, 500, w)
		return
	}
	c.fileserverHits.Swap(0)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
}

func (c *apiConfig) handlerPolkaWebhooks(w http.ResponseWriter, req *http.Request) {
	apiKey, err := auth.GetAPIKey(req.Header)
	if err != nil || apiKey != c.polkaAPIKey {
		processError("Unauthorized", 401, w)
		return
	}

	type polkaWebhookBody struct {
		Event string `json:"event"`
		Data  struct {
			UserID string `json:"user_id"`
		}
	}
	var reqBody polkaWebhookBody
	dec := json.NewDecoder(req.Body)
	if err := dec.Decode(&reqBody); err != nil {
		processError("Something went wrong while processing request body", 400, w)
		return
	}

	if reqBody.Event != "user.upgraded" {
		w.WriteHeader(204)
		return
	}

	if len(reqBody.Data.UserID) < 1 {
		errMsg := "Something went wrong handling the request, expected user id in request"
		processError(errMsg, 400, w)
		return
	}
	uid, err := uuid.Parse(reqBody.Data.UserID)
	if err != nil {
		errMsg := fmt.Sprintf("Something went wrong when processing the user ID: %v", err)
		processError(errMsg, 400, w)
		return
	}

	if err := c.db.UpgradeUser(req.Context(), uid); err != nil {
		errMsg := fmt.Sprintf("Something went wrong when upgrading your user: %v", err)
		errorCode := 500
		if errors.Is(err, sql.ErrNoRows) {
			errorCode = 404
		}
		processError(errMsg, errorCode, w)
		return
	}
	w.WriteHeader(204)
}

func (c *apiConfig) handlerCreateUser(w http.ResponseWriter, req *http.Request) {
	var reqBody authRequestPayload
	dec := json.NewDecoder(req.Body)
	if err := dec.Decode(&reqBody); err != nil {
		processError("Something went wrong while processing request body", 400, w)
		return
	}

	h, err := auth.HashPassword(reqBody.Password)
	if err != nil {
		errMsg := fmt.Sprintf("Something went wrong while processing your request: %v", err)
		processError(errMsg, 400, w)
		return
	}

	params := database.CreateUserParams{
		Email:          reqBody.Email,
		HashedPassword: h,
	}

	u, err := c.db.CreateUser(req.Context(), params)
	if err != nil {
		errMsg := fmt.Sprintf("Unable to create user: %v", err)
		processError(errMsg, 500, w)
		return
	}

	out := userResponseBody{
		ID:          u.ID,
		CreatedAt:   u.CreatedAt,
		UpdatedAt:   u.UpdatedAt,
		Email:       u.Email,
		IsChirpyRed: u.IsChirpyRed,
	}
	d, err := json.Marshal(out)
	if err != nil {
		errMsg := fmt.Sprintf("Something went wrong while processing repsone: %v", err)
		processError(errMsg, 500, w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	w.Write(d)
}

func (c *apiConfig) handlerUpdateUser(w http.ResponseWriter, req *http.Request) {
	type userCredentialsUpdateBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		errMsg := fmt.Sprintf("Something went wrong while authenticating your request: %v", err)
		processError(errMsg, 401, w)
		return
	}
	uid, err := auth.ValidateJWT(token, c.authSecret)
	if err != nil {
		errMsg := fmt.Sprintf("Something went wrong while authenticating your request: %v", err)
		processError(errMsg, 401, w)
		return
	}

	var reqBody userCredentialsUpdateBody
	dec := json.NewDecoder(req.Body)
	if err := dec.Decode(&reqBody); err != nil {
		processError("Something went wrong while processing request body", 400, w)
		return
	}

	h, err := auth.HashPassword(reqBody.Password)
	if err != nil {
		errMsg := fmt.Sprintf("Something went wrong while processing your request: %v", err)
		processError(errMsg, 400, w)
		return
	}

	params := database.UpdateUserCredentialsParams{
		Email:          reqBody.Email,
		HashedPassword: h,
		ID:             uid,
	}
	u, err := c.db.UpdateUserCredentials(req.Context(), params)
	if err != nil {
		errMsg := fmt.Sprintf("Unable to update user: %v", err)
		processError(errMsg, 500, w)
		return
	}

	out := userResponseBody{
		ID:          u.ID,
		CreatedAt:   u.CreatedAt,
		UpdatedAt:   u.UpdatedAt,
		Email:       u.Email,
		IsChirpyRed: u.IsChirpyRed,
	}
	d, err := json.Marshal(out)
	if err != nil {
		errMsg := fmt.Sprintf("Something went wrong while processing repsone: %v", err)
		processError(errMsg, 500, w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(d)
}

func (c *apiConfig) handlerLogin(w http.ResponseWriter, req *http.Request) {
	var reqBody authRequestPayload
	dec := json.NewDecoder(req.Body)
	if err := dec.Decode(&reqBody); err != nil {
		processError("Something went wrong while processing request body", 400, w)
		return
	}

	u, err := c.db.GetUserByEmail(req.Context(), reqBody.Email)
	if err != nil {
		processError("Incorrect email or password", 401, w)
		return
	}

	isAuthenticated, err := auth.CheckPasswordHash(reqBody.Password, u.HashedPassword)
	if err != nil || !isAuthenticated {
		processError("Incorrect email or password", 401, w)
		return
	}

	token, err := auth.MakeJWT(u.ID, c.authSecret, 3600*time.Second)
	if err != nil {
		processError("Incorrect email or password", 401, w)
		return
	}

	type loginResponseBody struct {
		userResponseBody
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		processError("Incorrect email or password", 401, w)
		return
	}
	params := database.StoreRefreshTokenParams{
		Token:  refreshToken,
		UserID: u.ID,
	}
	if _, err := c.db.StoreRefreshToken(req.Context(), params); err != nil {
		processError("Incorrect email or password", 401, w)
		return
	}

	resp := loginResponseBody{
		userResponseBody: userResponseBody{
			ID:          u.ID,
			CreatedAt:   u.CreatedAt,
			UpdatedAt:   u.UpdatedAt,
			Email:       u.Email,
			IsChirpyRed: u.IsChirpyRed,
		},
		Token:        token,
		RefreshToken: refreshToken,
	}
	d, err := json.Marshal(resp)
	if err != nil {
		processError("Incorrect email or password", 401, w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(d)
}

func (c *apiConfig) handlerRefreshAuth(w http.ResponseWriter, req *http.Request) {
	refreshTokenInput, err := auth.GetBearerToken(req.Header)
	if err != nil {
		errMsg := fmt.Sprintf("Something went wrong while authenticating your request: %v", err)
		processError(errMsg, 401, w)
		return
	}

	r, err := c.db.GetRefreshToken(req.Context(), refreshTokenInput)
	if err != nil || r.RevokedAt.Valid || r.ExpiresAt.Before(time.Now()) {
		processError("Refresh token is expired", 401, w)
		return
	}

	token, err := auth.MakeJWT(r.UserID, c.authSecret, 3600*time.Second)
	if err != nil {
		errMsg := fmt.Sprintf("Something went wrong while authenticating your request: %v", err)
		processError(errMsg, 401, w)
		return
	}

	type authRefreshResponseBody struct {
		Token string `json:"token"`
	}

	resp := authRefreshResponseBody{
		Token: token,
	}
	d, err := json.Marshal(resp)
	if err != nil {
		errMsg := fmt.Sprintf("Something went wrong while authenticating your request: %v", err)
		processError(errMsg, 401, w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(d)
}

func (c *apiConfig) handlerRevoke(w http.ResponseWriter, req *http.Request) {
	refreshTokenInput, err := auth.GetBearerToken(req.Header)
	if err != nil {
		errMsg := fmt.Sprintf("Something went wrong while processing your request: %v", err)
		processError(errMsg, 401, w)
		return
	}

	if err := c.db.RevokeRefreshToken(req.Context(), refreshTokenInput); err != nil {
		errMsg := fmt.Sprintf("Something went wrong while processing your request: %v", err)
		processError(errMsg, 401, w)
		return
	}
	w.WriteHeader(204)
}

func (c *apiConfig) handlerCreateChirp(w http.ResponseWriter, req *http.Request) {
	type requestBody struct {
		Body string `json:"body"`
	}

	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		errMsg := fmt.Sprintf("Something went wrong while authenticating your request: %v", err)
		processError(errMsg, 401, w)
		return
	}
	uid, err := auth.ValidateJWT(token, c.authSecret)
	if err != nil {
		errMsg := fmt.Sprintf("Something went wrong while authenticating your request: %v", err)
		processError(errMsg, 401, w)
		return
	}

	var body requestBody
	dec := json.NewDecoder(req.Body)
	if err := dec.Decode(&body); err != nil {
		processError("Something went wrong", 400, w)
		return
	}
	if len(body.Body) > 140 {
		processError("Chirp is too long", 400, w)
		return
	}

	chirpParams := database.CreateChirpParams{
		Body:   cleanChirp(body.Body),
		UserID: uid,
	}
	ch, err := c.db.CreateChirp(req.Context(), chirpParams)
	if err != nil {
		errMsg := fmt.Sprintf("Something went wrong while creating chirp: %v", err)
		processError(errMsg, 500, w)
		return
	}

	respBody := chirpResponse{
		ID:        ch.ID,
		CreatedAt: ch.CreatedAt,
		UpdatedAt: ch.UpdatedAt,
		Body:      ch.Body,
		UserID:    ch.UserID,
	}
	d, err := json.Marshal(respBody)
	if err != nil {
		fmt.Printf("error marshalling JSON: %v", err)
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	w.Write(d)
}

func (c *apiConfig) handlerGetChirps(w http.ResponseWriter, req *http.Request) {
	var respBody []chirpResponse

	ch, err := c.db.GetAllChirps(req.Context())
	if err != nil {
		errMsg := fmt.Sprintf("Something went wrong while retrieving chirps: %v", err)
		processError(errMsg, 500, w)
		return
	}

	for _, chirp := range ch {
		entry := chirpResponse{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		}
		respBody = append(respBody, entry)
	}

	d, err := json.Marshal(respBody)
	if err != nil {
		errMsg := fmt.Sprintf("Something went wrong while building response: %v", err)
		processError(errMsg, 500, w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(d)
}

func (c *apiConfig) handlerGetChirpByID(w http.ResponseWriter, req *http.Request) {
	chirpID := req.PathValue("chirpID")
	if len(chirpID) < 1 {
		errMsg := "Something went wrong handling the request, expected chirp id in request path"
		processError(errMsg, 400, w)
		return
	}
	parsedChirpID, err := uuid.Parse(chirpID)
	if err != nil {
		errMsg := fmt.Sprintf("Something went wrong when processing the chirp ID: %v", err)
		processError(errMsg, 400, w)
		return
	}

	ch, err := c.db.GetChirpByID(req.Context(), parsedChirpID)
	if err != nil {
		errMsg := fmt.Sprintf("Something went wrong when fetching the chirp: %v", err)
		errorCode := 500
		if errors.Is(err, sql.ErrNoRows) {
			errorCode = 404
		}
		processError(errMsg, errorCode, w)
		return
	}

	resp := chirpResponse{
		ID:        ch.ID,
		CreatedAt: ch.CreatedAt,
		UpdatedAt: ch.UpdatedAt,
		Body:      ch.Body,
		UserID:    ch.UserID,
	}
	d, err := json.Marshal(resp)
	if err != nil {
		errMsg := fmt.Sprintf("Something went wrong while building the response: %v", err)
		processError(errMsg, 500, w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(d)
}

func (c *apiConfig) handlerDeleteChirpByID(w http.ResponseWriter, req *http.Request) {
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		errMsg := fmt.Sprintf("Something went wrong while authenticating your request: %v", err)
		processError(errMsg, 401, w)
		return
	}
	uid, err := auth.ValidateJWT(token, c.authSecret)
	if err != nil {
		errMsg := fmt.Sprintf("Something went wrong while authenticating your request: %v", err)
		processError(errMsg, 401, w)
		return
	}

	chirpID := req.PathValue("chirpID")
	if len(chirpID) < 1 {
		errMsg := "Something went wrong handling the request, expected chirp id in request path"
		processError(errMsg, 400, w)
		return
	}
	parsedChirpID, err := uuid.Parse(chirpID)
	if err != nil {
		errMsg := fmt.Sprintf("Something went wrong when processing the chirp ID: %v", err)
		processError(errMsg, 400, w)
		return
	}

	ch, err := c.db.GetChirpByID(req.Context(), parsedChirpID)
	if err != nil {
		errMsg := fmt.Sprintf("Something went wrong when fetching the chirp: %v", err)
		errorCode := 500
		if errors.Is(err, sql.ErrNoRows) {
			errorCode = 404
		}
		processError(errMsg, errorCode, w)
		return
	}

	if ch.UserID != uid {
		processError("Operation only available to the chirp author", 403, w)
		return
	}

	if err := c.db.DeleteChirpByID(req.Context(), ch.ID); err != nil {
		processError("Delete operation failed", 500, w)
		return
	}

	w.WriteHeader(204)
}

func handlerHealth(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	io.WriteString(w, "OK")
}

func main() {
	config := apiConfig{}
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	env := os.Getenv("PLATFORM")
	authSecret := os.Getenv("JWT_SECRET")
	polkaAPIKey := os.Getenv("POLKA_KEY")

	config.env = env
	config.polkaAPIKey = polkaAPIKey

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Printf("Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	dbQueries := database.New(db)
	config.db = dbQueries

	config.authSecret = authSecret

	mux := http.NewServeMux()
	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}
	fileserverHandler := http.StripPrefix("/app", http.FileServer(http.Dir(".")))

	mux.Handle("/app/", config.middlewareMetricsInc(fileserverHandler))

	mux.HandleFunc("GET /api/healthz", handlerHealth)
	mux.HandleFunc("POST /api/polka/webhooks", config.handlerPolkaWebhooks)
	mux.HandleFunc("POST /api/users", config.handlerCreateUser)
	mux.HandleFunc("PUT /api/users", config.handlerUpdateUser)
	mux.HandleFunc("POST /api/login", config.handlerLogin)
	mux.HandleFunc("POST /api/refresh", config.handlerRefreshAuth)
	mux.HandleFunc("POST /api/revoke", config.handlerRevoke)
	mux.HandleFunc("POST /api/chirps", config.handlerCreateChirp)
	mux.HandleFunc("GET /api/chirps", config.handlerGetChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", config.handlerGetChirpByID)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", config.handlerDeleteChirpByID)

	mux.HandleFunc("GET /admin/metrics", config.handlerMetric)
	mux.HandleFunc("POST /admin/reset", config.handlerReset)

	server.ListenAndServe()
}
