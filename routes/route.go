package routes

import (
	"auth-server-go/config"
	"auth-server-go/controller"
	"context"
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
)

var (
	ctx            context.Context
	cancel         context.CancelFunc
	db             *mongo.Database
	userController controller.Controller
)

func init() {
	if err := godotenv.Load(); err != nil {
		log.Fatal(err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db = config.ConnectDatabase(os.Getenv("MONGO_URI"))

	userController = controller.Controller{Collection: db.Collection("user")}
}

// Routes : define server available routes
func Routes(r *gin.Engine) {
	userV1 := r.Group("api/v1/user")
	{
		userV1.POST("/new", userController.RegisterHandler())
		// userV1.POST("/auth",)
		// userV1.GET("refresh",)
		// userV1.GET("/:username",)
	}
}
