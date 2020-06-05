package main

import (
	"auth-server-go/routes"
	"log"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()
	router.Use(cors.Default())
	routes.Routes(router)
	log.Fatal(router.Run(":" + os.Getenv("PORT")))
}
