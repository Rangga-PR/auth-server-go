package main

import (
	"log"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()
	router.Use(cors.Default())
	log.Fatal(router.Run(":" + os.Getenv("PORT")))
}
