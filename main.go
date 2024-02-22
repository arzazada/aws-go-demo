package main

import (
	"log"
	"net/http"
)

func main() {

	// Defer DB connection
	defer db.Close()

	// Create table for storing user log data
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS userLog (
			id SERIAL PRIMARY KEY,
			ip TEXT,
			email TEXT,
			timestamp TIMESTAMP
		)
	`)
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/", mainHandler)
	http.HandleFunc("/health", healthCheck)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/signup", signUpHandler)
	http.HandleFunc("/confirm", confirmHandler)
	http.HandleFunc("/forgot_password", forgotPasswordHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/reset", resetPasswordHandler)
	http.HandleFunc("/log", logHandler)

	err = http.ListenAndServe(":80", nil)
	if err != nil {
		log.Println(err)
	} else {
		log.Println("listening on port 80...")
	}
}
