package api

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/Leugard/connect-backend/service/upload"
	"github.com/Leugard/connect-backend/service/user"
	"github.com/gorilla/mux"
)

type APIServer struct {
	addr string
	db   *sql.DB
}

func NewAPIServer(addr string, db *sql.DB) *APIServer {
	return &APIServer{
		addr: addr,
		db:   db,
	}
}

func (s *APIServer) Run() error {
	router := mux.NewRouter()
	subrouter := router.PathPrefix("/api/v1").Subrouter()

	userStore := user.NewStore(s.db)
	cloudName := os.Getenv("CLOUDINARY_CLOUD_NAME")
	apiKey := os.Getenv("CLOUDINARY_API_KEY")
	apiSecret := os.Getenv("CLOUDINARY_API_SECRET")
	uploadStore, err := upload.NewCloudinaryService(cloudName, apiKey, apiSecret)
	if err != nil {
		log.Fatalf("failed to initialize Cloudinary service: %v", err)
	}
	userHandler := user.NewHandler(userStore, uploadStore)
	userHandler.RegisterRoutes(subrouter)

	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if err := s.db.Ping(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	log.Println("listening on", s.addr)
	return http.ListenAndServe(s.addr, router)
}
