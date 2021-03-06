package routes

import (
	"auth-server-go/config"
	"auth-server-go/controller"
	"context"
	"log"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
)

var (
	ctx             context.Context
	cancel          context.CancelFunc
	db              *mongo.Database
	userController  controller.Controller
	redisClient     *redis.Client
	tokenCollection *mongo.Collection
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal(err)
	}

	db = config.ConnectDatabase(os.Getenv("MONGO_URI"))

	redisDB, err := strconv.Atoi(os.Getenv("REDIS_DB"))
	if err != nil {
		redisDB = 0
	}

	redisClient, err = config.RedisClient(os.Getenv("REDIS_HOST"), os.Getenv("REDIS_PASSWORD"), redisDB)
	if err != nil {
		log.Fatal("redis error: ", err.Error())
	}

	userController = controller.Controller{
		Collection: db.Collection("user"),
		Redis:      redisClient,
	}

	tokenCollection = db.Collection("access_token")
}

// Routes : define server available routes
func Routes(r *gin.Engine) {
	userV1 := r.Group("api/v1/user")
	{
		userV1.POST("/new", userController.RegisterHandler())
		userV1.GET("/auth", userController.LoginHandler(tokenCollection))
		userV1.PATCH("/refresh", userController.RefreshHandler(tokenCollection))
		userV1.PATCH("/logout", userController.LogoutHandler(tokenCollection))
	}
}
