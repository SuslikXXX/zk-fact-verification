package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

var cfg AppConfig

type AppConfig struct {
	Port                string
	EthereumRPC         string
	FactRegistryAddress string
	IssuerRegistryAddress string
	VerifierID          string
	VerifierIDHash      string
}

func main() {
	_ = godotenv.Load()

	cfg = AppConfig{
		Port:                getEnv("PORT", "8080"),
		EthereumRPC:         getEnv("ETHEREUM_RPC_URL", "http://127.0.0.1:8545"),
		FactRegistryAddress: getEnv("FACT_REGISTRY_ADDRESS", ""),
		IssuerRegistryAddress: getEnv("ISSUER_REGISTRY_ADDRESS", ""),
		VerifierID:          getEnv("VERIFIER_ID", "did:web:shop.example.com"),
		VerifierIDHash:      getEnv("VERIFIER_ID_HASH", ""),
	}

	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/health", handleHealth)
	mux.HandleFunc("/api/lookup", handleLookupFact)
	mux.HandleFunc("/api/config", handleConfig)

	// Serve static frontend (./frontend in Docker, ../frontend locally)
	frontendDir := getEnv("FRONTEND_DIR", "../frontend")
	fs := http.FileServer(http.Dir(frontendDir))
	mux.Handle("/", fs)

	// CORS wrapper
	handler := corsMiddleware(mux)

	fmt.Printf("Verifier backend on :%s\n", cfg.Port)
	fmt.Printf("  RPC: %s\n", cfg.EthereumRPC)
	fmt.Printf("  FactRegistry: %s\n", cfg.FactRegistryAddress)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, handler))
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"status": "ok"})
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{
		"verifier_id":           cfg.VerifierID,
		"verifier_id_hash":      cfg.VerifierIDHash,
		"fact_registry_address": cfg.FactRegistryAddress,
		"ethereum_rpc":          cfg.EthereumRPC,
	})
}

func handleLookupFact(w http.ResponseWriter, r *http.Request) {
	subjectTag := r.URL.Query().Get("subject_tag")
	factTypeHash := r.URL.Query().Get("fact_type_hash")
	verifierIDHash := r.URL.Query().Get("verifier_id_hash")

	if subjectTag == "" || factTypeHash == "" {
		http.Error(w, `{"error":"subject_tag and fact_type_hash required"}`, http.StatusBadRequest)
		return
	}
	if verifierIDHash == "" {
		verifierIDHash = cfg.VerifierIDHash
	}

	if cfg.FactRegistryAddress == "" {
		writeJSON(w, map[string]interface{}{
			"error": "FACT_REGISTRY_ADDRESS not configured",
		})
		return
	}

	fact, err := lookupFactOnChain(cfg.EthereumRPC, cfg.FactRegistryAddress, verifierIDHash, subjectTag, factTypeHash)
	if err != nil {
		writeJSON(w, map[string]interface{}{
			"exists": false,
			"error":  err.Error(),
		})
		return
	}

	writeJSON(w, fact)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return strings.TrimSpace(val)
	}
	return fallback
}
