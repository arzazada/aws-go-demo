package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	_ "github.com/lib/pq"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

func getMetadata(path string) string {
	resp, err := http.Get("http://169.254.169.254/latest/meta-data/" + path)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(body)
}

func getLastRecords(db *sql.DB, n int) []struct {
	Ip        string
	Timestamp time.Time
	Email     string
} {
	rows, err := db.Query(`
		SELECT ip, timestamp, email
		FROM userLog
		ORDER BY id DESC
		LIMIT $1
	`, n)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	var records []struct {
		Ip        string
		Timestamp time.Time
		Email     string
	}

	for rows.Next() {
		var record struct {
			Ip        string
			Timestamp time.Time
			Email     string
		}
		if err := rows.Scan(&record.Ip, &record.Timestamp, &record.Email); err != nil {
			panic(err)
		}
		records = append(records, record)
	}

	if err := rows.Err(); err != nil {
		panic(err)
	}

	return records
}

func renderTemplate(w http.ResponseWriter, name string, data interface{}) {
	tmpl, err := templates.Lookup(name).Clone()
	if err != nil {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func mainHandler(w http.ResponseWriter, r *http.Request) {

	// Session cookie AccessToken validation - check user authentication
	session, err := sessionStore.Get(r, "userSession")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if session.Values["accessToken"] != nil {
		sessionAccessToken := session.Values["accessToken"].(string)
		params := &cognitoidentityprovider.GetUserInput{
			AccessToken: aws.String(sessionAccessToken),
		}
		_, err = cognitoClient.GetUser(params)
		if err != nil {
			log.Println("Error getting user:", err)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
	} else if session.Values["accessToken"] == nil {
		log.Println("Info, cannot load user:", "accessToken is nil")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	email := session.Values["email"].(string)

	data := struct {
		Email      string
		InstanceId string
		PrivateIp  string
		Records    []struct {
			Ip        string
			Timestamp time.Time
			Email     string
		}
	}{
		Email:      email,
		InstanceId: getMetadata("instance-id"),
		PrivateIp:  getMetadata("local-ipv4"),
		Records:    getLastRecords(db, 5),
	}
	renderTemplate(w, "index.html", data)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := sessionStore.Get(r, "userSession")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	email := session.Values["email"].(string)

	// delete session cookie
	session.Options.MaxAge = -1
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else {
		log.Printf("Info: User %s logged out", email)
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func createSecretHash(username, clientID, clientSecret string) string {
	message := []byte(username + clientID)
	key := []byte(clientSecret)
	h := hmac.New(sha256.New, key)
	_, err := h.Write(message)
	if err != nil {
		return ""
	}
	hash := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return hash
}

func signUpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		email := r.FormValue("email")
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirm_password")

		if password != confirmPassword {
			log.Printf("Passwords do not match, signup event for %s\n", email)
			data := struct {
				Error string
			}{
				Error: "Passwords do not match",
			}
			renderTemplate(w, "signup.html", data)
			return
		}

		// Calculate the SecretHash
		secretHash := createSecretHash(email, appClientID, appClientSecret)

		// Create the user in Cognito
		_, err := cognitoClient.SignUp(&cognitoidentityprovider.SignUpInput{
			ClientId:   &appClientID,
			Username:   &email,
			Password:   &password,
			SecretHash: &secretHash,
			UserAttributes: []*cognitoidentityprovider.AttributeType{
				{
					Name:  aws.String("email"),
					Value: &email,
				},
			},
		})
		if err != nil {
			log.Println(err.Error())
			data := struct {
				Error string
			}{
				Error: err.Error(),
			}
			renderTemplate(w, "signup.html", data)
			return
		} else {
			log.Printf("Successful signup! user: %s", email)
		}

		// Render the confirmation code form
		renderTemplate(w, "confirm.html", map[string]interface{}{
			"email": email,
		})
	} else {
		// Render the sign-up form
		renderTemplate(w, "signup.html", nil)
	}
}

func confirmHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		email := r.FormValue("email")
		conformationCode := r.FormValue("confirmation_code")

		// Calculate the SecretHash
		secretHash := createSecretHash(email, appClientID, appClientSecret)

		_, err := cognitoClient.ConfirmSignUp(&cognitoidentityprovider.ConfirmSignUpInput{
			ClientId:         &appClientID,
			Username:         &email,
			ConfirmationCode: &conformationCode,
			SecretHash:       &secretHash,
		})
		if err != nil {
			data := struct {
				Error error
			}{
				Error: err,
			}
			renderTemplate(w, "confirm.html", data)
			return
		}
		// TODO: success screen with back button
		fmt.Fprintf(w, "Confirmation successful! ")

	} else {
		// Render the confirmation form
		renderTemplate(w, "confirm.html", nil)
	}
}

func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		email := r.FormValue("email")
		newPassword := r.FormValue("new_password")
		code := r.FormValue("code")

		secretHash := createSecretHash(email, appClientID, appClientSecret)
		// Confirm the forgot password request in Cognito
		_, err := cognitoClient.ConfirmForgotPassword(&cognitoidentityprovider.ConfirmForgotPasswordInput{
			ClientId:         &appClientID,
			Username:         &email,
			Password:         &newPassword,
			ConfirmationCode: &code,
			SecretHash:       &secretHash,
		})

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			log.Println("Error: ", err)
			return
		}
		log.Printf("Password reset successful! user: %s", email)
		fmt.Fprintf(w, "Password reset successful!")
	} else {
		// Render the reset password form
		renderTemplate(w, "reset_password.html", nil)
	}
}

func forgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		email := r.FormValue("email")

		secretHash := createSecretHash(email, appClientID, appClientSecret)
		// Initiate the forgot password flow in Cognito
		_, err := cognitoClient.ForgotPassword(&cognitoidentityprovider.ForgotPasswordInput{
			ClientId:   &appClientID,
			Username:   &email,
			SecretHash: &secretHash,
		})

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			log.Println("Error: ", err)
			return
		}
		http.Redirect(w, r, "/reset", http.StatusSeeOther)

	} else {
		// Render the forgot password form
		renderTemplate(w, "forgot_password.html", nil)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

	// Session cookie AccessToken validation - check user authentication
	session, err := sessionStore.Get(r, "userSession")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if session.Values["accessToken"] != nil {
		sessionAccessToken := session.Values["accessToken"].(string)

		params := &cognitoidentityprovider.GetUserInput{
			AccessToken: aws.String(sessionAccessToken),
		}

		resp, err := cognitoClient.GetUser(params)
		if err != nil {
			log.Println("Error getting user:", err)
		} else {
			http.Redirect(w, r, "/", http.StatusFound)
			log.Printf("Info: Successfull user login. Response output:\n%v", resp)
			// Getting attributes and Group from user
			//userAttributes := resp.UserAttributes
			//groups := resp.GroupMembership
			return
		}
	}

	// Get form data
	email := r.FormValue("email")
	password := r.FormValue("password")

	// Validate form data
	if email == "" || password == "" {
		data := struct {
			Error string
		}{
			Error: "Please enter your email and password",
		}
		renderTemplate(w, "login.html", data)
		return
	}

	// Calculate the SecretHash
	secretHash := createSecretHash(email, appClientID, appClientSecret)

	// Authenticate user
	authParams := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: aws.String("USER_PASSWORD_AUTH"),
		AuthParameters: map[string]*string{
			"USERNAME":    aws.String(email),
			"PASSWORD":    aws.String(password),
			"SECRET_HASH": aws.String(secretHash),
		},
		ClientId: aws.String(appClientID),
	}

	authResult, err := cognitoClient.InitiateAuth(authParams)
	if err != nil {
		data := struct {
			Error string
		}{
			Error: err.Error(),
		}
		renderTemplate(w, "login.html", data)
		log.Printf("Incorrect username or password. email:%s ", email)
		return
	}

	// Set session cookie
	session.Values["email"] = email
	session.Values["accessToken"] = *authResult.AuthenticationResult.AccessToken
	//session.Values["idToken"] = authResult.AuthenticationResult.IdToken

	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func logHandler(w http.ResponseWriter, r *http.Request) {

	// Session cookie AccessToken validation - check user authentication
	session, err := sessionStore.Get(r, "userSession")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if session.Values["accessToken"] != nil {
		sessionAccessToken := session.Values["accessToken"].(string)
		params := &cognitoidentityprovider.GetUserInput{
			AccessToken: aws.String(sessionAccessToken),
		}
		_, err = cognitoClient.GetUser(params)
		if err != nil {
			log.Println("Error getting user:", err)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
	} else if session.Values["accessToken"] == nil {
		log.Println("Info, cannot load user:", "accessToken is nil")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	email := session.Values["email"].(string)

	// If instance is behind an ALB/PROXY use X-Forwarded-For header instead
	//  ip := r.RemoteAddr
	ip := r.Header.Get("X-Forwarded-For")

	timestamp := time.Now().UTC()

	_, err = db.Exec("INSERT INTO userLog (ip, timestamp, email) VALUES ($1, $2, $3)", ip, timestamp, email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		Ip        string
		Timestamp time.Time
		Email     string
	}{
		Ip:        ip,
		Timestamp: timestamp,
		Email:     email,
	}

	renderTemplate(w, "log.html", data)
	log.Printf("Logged record from %s at %s by %s", ip, timestamp, email)
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
