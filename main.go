package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jjboykin/chirpy/internal/auth"
	"github.com/jjboykin/chirpy/internal/database"
	"github.com/joho/godotenv"

	_ "github.com/lib/pq"
)

// type apiHandler struct{}
// func (apiHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	jwtSecret      string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)

		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) middlewareLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

type User struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
}

func main() {
	godotenv.Load()

	platform := os.Getenv("PLATFORM")
	dbURL := os.Getenv("DB_URL")
	jwtSecret := os.Getenv("JWT_SECRET")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(errors.New(err.Error()))
		return
	}
	dbQueries := database.New(db)
	apiCfg := apiConfig{}
	apiCfg.db = dbQueries
	apiCfg.jwtSecret = jwtSecret

	filepathRoot := "."
	port := "8080"
	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	fsHandler := http.FileServer(http.Dir(filepathRoot))
	appHandler := http.StripPrefix("/app/", fsHandler)
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(appHandler))

	mux.HandleFunc("GET /api/chirps", func(w http.ResponseWriter, req *http.Request) {
		chirps, err := apiCfg.db.GetChirps(req.Context())
		if err != nil {
			respondWithError(w, 400, "Error returning chirps")
			return
		}

		respBody := []Chirp{}
		for _, chirp := range chirps {
			newChirp := Chirp{
				ID:        chirp.ID,
				CreatedAt: chirp.CreatedAt,
				UpdatedAt: chirp.UpdatedAt,
				Body:      chirp.Body,
				UserID:    chirp.UserID,
			}
			respBody = append(respBody, newChirp)
		}

		respondWithJSON(w, 200, respBody)
	})

	mux.HandleFunc("GET /api/chirps/{chirpID}", func(w http.ResponseWriter, req *http.Request) {
		param := req.PathValue("chirpID")
		uuid, err := uuid.Parse(param)
		if err != nil {
			respondWithError(w, 400, "Invalid chirpID")
			return
		}
		chirp, err := apiCfg.db.GetChirp(req.Context(), uuid)
		if err != nil {
			respondWithError(w, 404, fmt.Sprintf("Chirp with id=%s not found.", uuid.String()))
			return
		}

		respBody := Chirp{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		}

		respondWithJSON(w, 200, respBody)
	})

	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "OK\n")
	})

	mux.HandleFunc("GET /admin/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, fmt.Sprintf(
			`<html>
	<body>
		<h1>Welcome, Chirpy Admin</h1>
		<p>Chirpy has been visited %d times!</p>
	</body>
</html>`,
			apiCfg.fileserverHits.Load()))
	})

	mux.HandleFunc("POST /admin/reset", func(w http.ResponseWriter, r *http.Request) {
		if platform != "dev" {
			respondWithError(w, 403, "Forbidden")
			return
		}
		err := apiCfg.db.DeleteAllUsers(r.Context())
		if err != nil {
			respondWithError(w, 400, "Error deleting users")
			return
		}
		apiCfg.fileserverHits.Store(0)
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		type parameters struct {
			Body string `json:"body"`
		}

		decoder := json.NewDecoder(r.Body)
		params := parameters{}
		err := decoder.Decode(&params)
		if err != nil {
			// an error will be thrown if the JSON is invalid or has the wrong types
			// any missing fields will simply have their values in the struct set to their zero value
			log.Printf("Error decoding parameters: %s", err)
			respondWithError(w, 500, "Something went wrong")
			return
		}

		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			respondWithError(w, 401, "No valid auth token")
			return
		}
		userID, err := auth.ValidateJWT(token, apiCfg.jwtSecret)
		if err != nil {
			respondWithError(w, 401, "Error validating user token")
			return
		}

		if len(params.Body) > 140 {
			respondWithError(w, 400, "Chirp is too long")
			return
		}

		result := profanityFilter(params.Body)
		chirpParams := database.CreateChirpParams{
			Body:   result,
			UserID: userID,
		}
		chirp, err := apiCfg.db.CreateChirp(r.Context(), chirpParams)
		if err != nil {
			respondWithError(w, 400, "Error creating user")
			return
		}

		respBody := Chirp{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		}
		respondWithJSON(w, 201, respBody)
	})

	mux.HandleFunc("DELETE /api/chirps/{chirpID}", func(w http.ResponseWriter, req *http.Request) {
		token, err := auth.GetBearerToken(req.Header)
		if err != nil {
			respondWithError(w, 401, "No valid auth token")
			return
		}
		userID, err := auth.ValidateJWT(token, apiCfg.jwtSecret)
		if err != nil {
			respondWithError(w, 401, "Error validating user token")
			return
		}

		param := req.PathValue("chirpID")
		uuid, err := uuid.Parse(param)
		if err != nil {
			respondWithError(w, 400, "Invalid chirpID")
			return
		}
		chirp, err := apiCfg.db.GetChirp(req.Context(), uuid)
		if err != nil {
			respondWithError(w, 404, fmt.Sprintf("Chirp with id=%s not found.", uuid.String()))
			return
		}

		if chirp.UserID != userID {
			respondWithError(w, 403, "User is not the author of this chirp")
			return
		}

		err = apiCfg.db.DeleteChirp(req.Context(), chirp.ID)
		if err != nil {
			respondWithError(w, 404, fmt.Sprintf("Chirp with id=%s not found.", uuid.String()))
			return
		}

		w.WriteHeader(204)

	})

	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		type parameters struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		decoder := json.NewDecoder(r.Body)
		params := parameters{}
		err := decoder.Decode(&params)
		if err != nil {
			// an error will be thrown if the JSON is invalid or has the wrong types
			// any missing fields will simply have their values in the struct set to their zero value
			log.Printf("Error decoding parameters: %s", err)
			respondWithError(w, 500, "Something went wrong")
			return
		}

		user, err := apiCfg.db.GetUser(r.Context(), params.Email)
		if err != nil {
			respondWithError(w, 401, "Incorrect email or password")
			return
		}
		err = auth.CheckPasswordHash(user.HashedPassword, params.Password)
		if err != nil {
			respondWithError(w, 401, "Incorrect email or password")
			return
		}

		expiresIn := time.Duration(60) * time.Minute
		tokenString, err := auth.MakeJWT(user.ID, apiCfg.jwtSecret, expiresIn)
		if err != nil {
			respondWithError(w, 401, err.Error())
			return
		}

		refreshTokenString, err := auth.MakeRefreshToken()
		if err != nil {
			respondWithError(w, 401, err.Error())
			return
		}
		refreshTokenParams := database.CreateRefreshTokenParams{
			Token:     refreshTokenString,
			UserID:    user.ID,
			ExpiresAt: time.Now().Add(60 * 24 * time.Hour),
		}

		refreshToken, err := apiCfg.db.CreateRefreshToken(r.Context(), refreshTokenParams)
		if err != nil {
			respondWithError(w, 400, "Error creating refresh token")
			return
		}

		respBody := User{
			ID:           user.ID,
			CreatedAt:    user.CreatedAt,
			UpdatedAt:    user.UpdatedAt,
			Email:        user.Email,
			Token:        tokenString,
			RefreshToken: refreshToken.Token,
		}
		respondWithJSON(w, 200, respBody)

	})

	mux.HandleFunc("POST /api/refresh", func(w http.ResponseWriter, r *http.Request) {

		refreshTokenString, err := auth.GetBearerToken(r.Header)
		if err != nil {
			respondWithError(w, 401, "no bearer auth in header")
			return
		}

		refreshToken, err := apiCfg.db.GetRefreshToken(r.Context(), refreshTokenString)
		if err != nil {
			respondWithError(w, 401, "no refesh token found")
			return
		}

		expiresIn := time.Duration(60) * time.Minute
		tokenString, err := auth.MakeJWT(refreshToken.UserID, apiCfg.jwtSecret, expiresIn)
		if err != nil {
			respondWithError(w, 401, err.Error())
			return
		}

		type accessToken struct {
			Token string `json:"token"`
		}
		respBody := accessToken{
			Token: tokenString,
		}
		respondWithJSON(w, 200, respBody)

	})

	mux.HandleFunc("POST /api/revoke", func(w http.ResponseWriter, r *http.Request) {

		refreshTokenString, err := auth.GetBearerToken(r.Header)
		if err != nil {
			respondWithError(w, 401, "no bearer auth in header")
			return
		}
		refreshToken, err := apiCfg.db.GetRefreshToken(r.Context(), refreshTokenString)
		if err != nil {
			respondWithError(w, 401, "no refesh token found")
			return
		}

		apiCfg.db.RevokeRefreshToken(r.Context(), refreshToken.Token)
		w.WriteHeader(204)
	})

	mux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("POST /api/users handler called")
		type parameters struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		decoder := json.NewDecoder(r.Body)
		params := parameters{}
		err := decoder.Decode(&params)
		if err != nil {
			// an error will be thrown if the JSON is invalid or has the wrong types
			// any missing fields will simply have their values in the struct set to their zero value
			log.Printf("Error decoding parameters: %s", err)
			respondWithError(w, 500, "Something went wrong")
			return
		}

		hashedPassword, err := auth.HashPassword(params.Password)
		if err != nil {
			respondWithError(w, 400, "Error creating user")
			return
		}
		userParams := database.CreateUserParams{
			Email:          params.Email,
			HashedPassword: hashedPassword,
		}

		user, err := apiCfg.db.CreateUser(r.Context(), userParams)
		if err != nil {
			respondWithError(w, 400, "Error creating user")
			return
		}

		respBody := User{
			ID:        user.ID,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
			Email:     user.Email,
		}
		respondWithJSON(w, 201, respBody)
	})

	mux.HandleFunc("PUT /api/users", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("PUT /api/users handler called")
		type parameters struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		decoder := json.NewDecoder(r.Body)
		params := parameters{}
		err := decoder.Decode(&params)
		if err != nil {
			// an error will be thrown if the JSON is invalid or has the wrong types
			// any missing fields will simply have their values in the struct set to their zero value
			log.Printf("Error decoding parameters: %s", err)
			respondWithError(w, 500, "Something went wrong")
			return
		}

		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			respondWithError(w, 401, "No valid auth token")
			return
		}
		userID, err := auth.ValidateJWT(token, apiCfg.jwtSecret)
		if err != nil {
			respondWithError(w, 401, "Error validating user token")
			return
		}

		hashedPassword, err := auth.HashPassword(params.Password)
		if err != nil {
			respondWithError(w, 400, "Error creating user")
			return
		}
		userParams := database.UpdateUserParams{
			ID:             userID,
			Email:          params.Email,
			HashedPassword: hashedPassword,
		}

		user, err := apiCfg.db.UpdateUser(r.Context(), userParams)
		if err != nil {
			respondWithError(w, 400, "Error updating user data")
			return
		}

		respBody := User{
			ID:        user.ID,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
			Email:     user.Email,
		}
		respondWithJSON(w, 200, respBody)
	})

	log.Printf("Serving files from %s/ on port: %s\n", filepathRoot, port)
	log.Fatal(server.ListenAndServe())
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	type returnError struct {
		Error string `json:"error"`
	}
	errs := returnError{
		Error: msg,
	}
	dat, err := json.Marshal(errs)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(dat)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	dat, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		respondWithError(w, 500, fmt.Sprintf("Error marshalling JSON: %s", err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(dat)
}

func profanityFilter(body string) string {
	var cleaned_words []string
	words := strings.Fields(body)
	for _, word := range words {
		if strings.ToLower(word) == "kerfuffle" ||
			strings.ToLower(word) == "sharbert" ||
			strings.ToLower(word) == "fornax" {
			cleaned_words = append(cleaned_words, "****")
		} else {
			cleaned_words = append(cleaned_words, word)
		}
	}
	return strings.Join(cleaned_words, " ")
}
