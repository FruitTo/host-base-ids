package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

const (
	host     = "localhost"
	port     = 3000
	dbname   = "postgres"
	user     = "postgres"
	password = "postgres"
)

type LoginData struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	fmt.Printf("Connecting to database %s on %s:%d as user %s\n", dbname, host, port, user)
	dbinfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)
	fmt.Println("Starting server...")
	router := gin.Default()

	router.POST("/api/login", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Login successful",
		})
	})

	router.Run(":3000")
}
