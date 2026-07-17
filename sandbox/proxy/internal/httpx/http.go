package httpx

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
)

func DecodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "request body must contain one JSON value", http.StatusBadRequest)
		return false
	}
	return true
}

func WriteJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func RequireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func ParsePositiveInt(value string, fallback int) int {
	number, err := strconv.Atoi(value)
	if err != nil || number <= 0 {
		return fallback
	}
	return number
}
