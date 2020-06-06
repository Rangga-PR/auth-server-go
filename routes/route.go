package routes

import (
	"auth-server-go/config"
	"auth-server-go/controller"
	"context"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
)

var (
	ctx            context.Context
	cancel         context.CancelFunc
	db             *mongo.Database
	userController controller.Controller
	redisClient    *redis.Client
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal(err)
	}

	db = config.ConnectDatabase(os.Getenv("MONGO_URI"))

	redisClient, err = config.RedisClient("0.0.0.0:6379", "test123", 0)
	if err != nil {
		log.Fatal("redis error: ", err.Error())
	}

	userController = controller.Controller{
		Collection: db.Collection("user"),
		Redis:      redisClient,
	}
}

// Routes : define server available routes
func Routes(r *gin.Engine) {
	userV1 := r.Group("api/v1/user")
	{
		userV1.POST("/new", userController.RegisterHandler())
		userV1.POST("/auth", userController.LoginHandler())
		// userV1.GET("refresh",)
		// userV1.GET("/:username",)
	}
}
