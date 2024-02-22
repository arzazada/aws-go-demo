package main

import (
	"database/sql"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"log"
	"os"
	"text/template"
)

var (
	region          string = getMetadata("placement/region")
	appClientID     string
	appClientSecret string
	sessionStore    *sessions.CookieStore
	templates       *template.Template
	db              *sql.DB
	cognitoClient   *cognitoidentityprovider.CognitoIdentityProvider
)

func getParam(name string) (value string, err error) {

	ssmSession := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Config: aws.Config{
			Region: aws.String(region),
		},
	}))

	ssmSvc := ssm.New(ssmSession)

	param, err := ssmSvc.GetParameter(&ssm.GetParameterInput{
		Name:           aws.String(name),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return "", err
	}

	return *param.Parameter.Value, nil
}

func init() {

	var err error

	// Loading .env file
	err = godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	ssmPath := os.Getenv("SSM_SECRET_PATH")

	appClientID, err = getParam(ssmPath + "APP_CLIENT_ID")
	if err != nil {
		log.Fatalf("Error retrieving value from SSM: %v", err)
	}

	appClientSecret, err = getParam(ssmPath + "APP_CLIENT_SECRET")
	if err != nil {
		log.Fatalf("Error retrieving value from SSM: %v", err)
	}

	sessionEnryptSecret, err := getParam(ssmPath + "SESSION_ENCRYPTION_SECRET")
	if err != nil {
		log.Fatalf("Error retrieving value from SSM: %v", err)
	}

	dbHost, err := getParam(ssmPath + "DB_HOST")
	if err != nil {
		log.Fatalf("Error retrieving value from SSM: %v", err)
	}

	dbEngine, err := getParam(ssmPath + "DB_ENGINE")
	if err != nil {
		log.Fatalf("Error retrieving value from SSM: %v", err)
	}

	dbName, err := getParam(ssmPath + "DB_NAME")
	if err != nil {
		log.Fatalf("Error retrieving value from SSM: %v", err)
	}

	dbUserName, err := getParam(ssmPath + "DB_USERNAME")
	if err != nil {
		log.Fatalf("Error retrieving value from SSM: %v", err)
	}

	dbPassword, err := getParam(ssmPath + "DB_PASSWORD")
	if err != nil {
		log.Fatalf("Error retrieving value from SSM: %v", err)
	}

	sessionStore = sessions.NewCookieStore([]byte(sessionEnryptSecret))

	templates = template.Must(template.ParseFiles(
		"templates/reset_password.html", "templates/log.html", "templates/index.html", "templates/signup.html", "templates/login.html", "templates/confirm.html", "templates/forgot_password.html",
	))

	// Set up AWS session and Cognito client
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})

	cognitoClient = cognitoidentityprovider.New(sess)

	// Set up database connection
	dataSourceName := fmt.Sprintf("%s://%s:%s@%s/%s?sslmode=disable", dbEngine, dbUserName, dbPassword, dbHost, dbName)
	db, err = sql.Open(dbEngine, dataSourceName)
	if err != nil {
		panic(err)
	}
}
