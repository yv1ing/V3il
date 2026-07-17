package control

import (
	"net/http"

	"sandbox-proxy/internal/httpx"
)

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	return httpx.DecodeJSON(w, r, target)
}

func writeJSON(w http.ResponseWriter, payload any) {
	httpx.WriteJSON(w, payload)
}

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	return httpx.RequireMethod(w, r, method)
}

func parseInt(value string, fallback int) int {
	return httpx.ParsePositiveInt(value, fallback)
}
