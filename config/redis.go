package config

import (
	"context"

	"github.com/go-redis/redis/v8"
)

//RedisClient : new Redis Client
func RedisClient(host, password string, db int) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     host,
		Password: password,
		DB:       db,
	})

	_, err := client.Ping(context.TODO()).Result()

	return client, err
}
