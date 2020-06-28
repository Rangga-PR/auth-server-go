package controller

import (
	"auth-server-go/model"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

//Controller : constructor
type Controller struct {
	Collection *mongo.Collection
	Redis      *redis.Client
}

//Claims : custom claims
type Claims struct {
	ID    primitive.ObjectID `json:"id"`
	Email string             `json:"email"`
	jwt.StandardClaims
}

func sendFailedResponse(c *gin.Context, statusCode int, msg string) {
	c.JSON(statusCode, gin.H{
		"success": 0,
		"error":   msg,
	})
}

func sendSuccessResponse(c *gin.Context, statusCode int, data gin.H) {
	c.JSON(statusCode, gin.H{
		"success": 1,
		"result":  data,
	})
}

var secretKey = []byte(os.Getenv("SECRET_KEY"))

//RegisterHandler : handle user registeration logic
func (con *Controller) RegisterHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var u model.User

		if err := c.ShouldBindJSON(&u); err != nil {
			sendFailedResponse(c, http.StatusInternalServerError, "something went wrong")
			log.Println(err.Error())
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), 14)
		if err != nil {
			sendFailedResponse(c, http.StatusInternalServerError, "something went wrong")
			log.Println(err.Error())
			return
		}

		userData := model.User{
			Username:  u.Username,
			Email:     u.Email,
			Password:  string(hashedPassword),
			CreatedAt: primitive.NewDateTimeFromTime(time.Now().UTC()),
			UpdatedAt: primitive.NewDateTimeFromTime(time.Now().UTC()),
		}

		newUser, err := con.Collection.InsertOne(c, userData)
		if err != nil {
			sendFailedResponse(c, http.StatusInternalServerError, "something went wrong")
			log.Println(err.Error())
			return
		}

		sendSuccessResponse(c, http.StatusCreated, gin.H{
			"new_user_id": newUser.InsertedID,
		})
	}
}

//LoginHandler : handle user login logic
func (con *Controller) LoginHandler(tokenCollection *mongo.Collection) gin.HandlerFunc {
	return func(c *gin.Context) {

		email := c.Query("email")
		password := c.Query("password")

		if email == "" || password == "" {
			sendFailedResponse(c, http.StatusBadRequest, "please fill email and password")
			return
		}

		accessToken, err := con.Redis.Get(c, email).Result()
		if err != nil && accessToken != "" {
			sendSuccessResponse(c, http.StatusOK, gin.H{
				"access_token": accessToken,
			})
			return
		}

		var loginUser model.User
		err = con.Collection.FindOne(c, bson.M{"email": email}).Decode(&loginUser)
		if err != nil {
			sendFailedResponse(c, http.StatusNotFound, "user not found")
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(loginUser.Password), []byte(password))
		if err != nil {
			sendFailedResponse(c, http.StatusNotFound, "incorrect password")
			return
		}

		claims := &Claims{
			ID:    loginUser.ID,
			Email: loginUser.Email,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(6 * time.Hour).Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		accessToken, err = token.SignedString(secretKey)
		if err != nil {
			log.Println("jwt-error: ", err.Error())
			sendFailedResponse(c, http.StatusInternalServerError, "something went wrong")
			return
		}

		newToken := model.AccessToken{
			UserID:      loginUser.ID,
			AccessToken: accessToken,
			LoggedOut:   false,
			Revoked:     false,
			ExpiresAt:   primitive.NewDateTimeFromTime(time.Now().Add(6 * time.Hour).UTC()),
			CreatedAt:   primitive.NewDateTimeFromTime(time.Now().UTC()),
			UpdatedAt:   primitive.NewDateTimeFromTime(time.Now().UTC()),
		}

		_, err = tokenCollection.InsertOne(c, newToken)
		if err != nil {
			sendFailedResponse(c, http.StatusInternalServerError, "something went wrong")
			log.Println(err.Error())
			return
		}

		err = con.Redis.Set(c, loginUser.Email, accessToken, 6*time.Hour).Err()
		if err != nil {
			log.Println("redis error: ", err.Error())
		}

		sendSuccessResponse(c, http.StatusOK, gin.H{
			"access_token": accessToken,
		})
	}
}

//RefreshHandler : handle user token refresh logic
func (con *Controller) RefreshHandler(tokenCollection *mongo.Collection) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.Query("access_token")
		if tokenString == "" {
			sendFailedResponse(c, http.StatusBadRequest, "Access token is required")
			return
		}

		objectID, err := primitive.ObjectIDFromHex(c.Query("user"))
		if err != nil {
			log.Println(err.Error())
			sendFailedResponse(c, http.StatusUnprocessableEntity, "invalid user id")
			return
		}

		currentDate := primitive.NewDateTimeFromTime(time.Now().UTC())
		existingToken := tokenCollection.FindOne(c, bson.M{
			"access_token": tokenString,
			"logged_out":   false,
			"expires_at": bson.M{
				"$lte": currentDate,
			},
		})
		if existingToken.Err() != mongo.ErrNoDocuments {
			sendFailedResponse(c, http.StatusUnprocessableEntity, "access token rejected")
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return secretKey, nil
		})

		if err != nil {
			log.Println(err.Error())
			sendFailedResponse(c, http.StatusInternalServerError, "something went wrong")
			return
		}

		if !token.Valid {
			sendFailedResponse(c, http.StatusBadRequest, "invalid token")
			return
		}

		claims.ExpiresAt = time.Now().Add(6 * time.Hour).Unix()
		newToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secretKey)

		if err != nil {
			log.Println(err.Error())
			sendFailedResponse(c, http.StatusInternalServerError, "something went wrong")
			return
		}

		accessToken := model.AccessToken{
			UserID:      objectID,
			AccessToken: newToken,
			LoggedOut:   false,
			Revoked:     false,
			ExpiresAt:   primitive.NewDateTimeFromTime(time.Now().Add(6 * time.Hour).UTC()),
			CreatedAt:   primitive.NewDateTimeFromTime(time.Now().UTC()),
			UpdatedAt:   primitive.NewDateTimeFromTime(time.Now().UTC()),
		}
		_, err = tokenCollection.InsertOne(c, accessToken)
		if err != nil {
			sendFailedResponse(c, http.StatusInternalServerError, "something went wrong")
			log.Println(err.Error())
			return
		}

		err = con.Redis.Set(c, claims.Email, newToken, 6*time.Hour).Err()
		if err != nil {
			log.Println("redis error: ", err.Error())
		}

		sendSuccessResponse(c, http.StatusOK, gin.H{
			"access_token": newToken,
		})
	}
}

//LogoutHandler : handle user logout logic
func (con *Controller) LogoutHandler(tokenCollection *mongo.Collection) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.Query("access_token")
		email := c.Query("email")
		if tokenString == "" || email == "" {
			sendFailedResponse(c, http.StatusBadRequest, "token and email cannot be empty")
			return
		}

		filter := bson.M{"access_token": tokenString}
		update := bson.D{
			primitive.E{
				Key: "set",
				Value: bson.D{
					primitive.E{Key: "logged_out", Value: true},
				},
			},
		}

		existingToken := tokenCollection.FindOneAndUpdate(c, filter, update)
		if existingToken.Err() != mongo.ErrNoDocuments {
			sendFailedResponse(c, http.StatusUnprocessableEntity, "access token rejected")
			return
		}

		err := con.Redis.Del(c, email).Err()
		if err != nil {
			log.Println("redis error: ", err.Error())
		}

		sendSuccessResponse(c, http.StatusOK, gin.H{
			"message": "User has logged out",
		})
	}
}
