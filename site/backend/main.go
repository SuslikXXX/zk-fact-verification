package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	http.HandleFunc("/api/request", handleCreateRequest)
	http.HandleFunc("/api/status", handleCheckStatus)

	// Serve static frontend
	http.Handle("/", http.FileServer(http.Dir("../frontend")))

	fmt.Printf("Verifier backend listening on :%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleCreateRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// TODO: generate verification_request.json and return it
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "created",
		"message": "Verification request created (stub)",
	})
}

func handleCheckStatus(w http.ResponseWriter, r *http.Request) {
	subjectTag := r.URL.Query().Get("subject_tag")
	factTypeHash := r.URL.Query().Get("fact_type_hash")
	verifierIDHash := r.URL.Query().Get("verifier_id_hash")

	if subjectTag == "" || factTypeHash == "" || verifierIDHash == "" {
		http.Error(w, "Missing query params: subject_tag, fact_type_hash, verifier_id_hash", http.StatusBadRequest)
		return
	}

	// TODO: call FactRegistry.isFactValid() via ethclient
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"subject_tag":     subjectTag,
		"fact_type_hash":  factTypeHash,
		"verifier_id_hash": verifierIDHash,
		"fact_valid":      false,
		"message":         "On-chain lookup not yet implemented",
	})
}
