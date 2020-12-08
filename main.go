package main

import (
	"gin_demo/log"
	"github.com/gin-gonic/gin"
)

func SetupRouter() *gin.Engine {
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.String(200, "pong")
	})
	return r
}

func init() {

}

func main() {
	r := SetupRouter()
	r.Use(log.LogFormatter())
	r.Run(":8080")
}