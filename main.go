package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

var ApplicationName = "Enigma"
var JwtSigningMethod = jwt.SigningMethodHS256
var JwtSignatureKey = []byte("Password")
var LOGIN_EXPIRATION_DURATION = time.Duration(10) * time.Minute
var TOKEN_DUMP = []string{}

type MyClaims struct {
	jwt.StandardClaims
	Username string `json:"Username"`
	Email    string `json:"Email"`
}

type UserCredential struct {
	Username string `json:"user_name" binding:"required"`
	Password string `json:"user_password" binding:"required"`
}

type authHeader struct {
	AuthorizationHeader string `header:"authorization" binding:"required"`
}

func main() {
	r := gin.Default()
	r.Use(authMiddle())
	publicRoute := r.Group("/enigma")
	publicRoute.POST("/login", func(c *gin.Context) {
		user := UserCredential{}
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(400, gin.H{
				"Message":    "Invalid input",
				"StatusCode": 400,
			})
			return
		}
		if user.Username == "user" && user.Password == "pass" {
			token, err := GenerateToken(user.Username, "user@user.com")
			if err != nil {
				c.AbortWithStatusJSON(500, gin.H{
					"Message":    "Internal Server Error",
					"ErrMessage": err.Error(),
					"StatusCode": 401,
				})
				return
			}
			TOKEN_DUMP = append(TOKEN_DUMP, "Bearer "+token)
			c.JSON(200, gin.H{
				"Message":    "Success",
				"StatusCode": 200,
				"Data":       token,
			})
			return
		}
		c.AbortWithStatusJSON(401, gin.H{
			"Message":    "Invalid credentials",
			"StatusCode": 401,
		})
	})

	publicRoute.POST("/logout", func(c *gin.Context) {
		var isChanged bool
		authValue := c.GetHeader("Authorization")
		TOKEN_DUMP, isChanged = SearchDelete(TOKEN_DUMP, authValue)
		if isChanged {
			c.JSON(200, gin.H{
				"Message":    "Success Log out",
				"StatusCode": 200,
			})
			return
		}
		c.JSON(500, gin.H{
			"Message":    "Internal Error. No Change Found!",
			"StatusCode": 500,
		})

	})

	publicRoute.GET("/customer", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"Message":    "Success",
			"StatusCode": 200,
			"Data":       c.GetHeader("Authorization"),
		})
	})
	err := r.Run()
	if err != nil {
		log.Fatalln("Failed running", err)
	}
}

func authMiddle() gin.HandlerFunc {
	authFunc := func(c *gin.Context) {
		if c.Request.URL.Path == "/enigma/login" {
			c.Next()
			return
		}
		var h authHeader
		if err := c.ShouldBindHeader(&h); err != nil || h.AuthorizationHeader == "" {
			c.AbortWithStatusJSON(400, gin.H{
				"Message":    "No valid header provided",
				"StatusCode": 400,
			})
		} else if !SearchElement(TOKEN_DUMP, h.AuthorizationHeader) {
			c.AbortWithStatusJSON(401, gin.H{
				"Message":    "Invalid header value",
				"StatusCode": 401,
			})
			return
		}
		tokenString := strings.Fields(h.AuthorizationHeader)
		token, err := parseToken(tokenString[1])
		fmt.Println(token)
		if err != nil {
			c.JSON(500, gin.H{
				"Message":    "Internal Server Error in Token Parsing",
				"StatusCode": 500,
				"ErrMsg":     err.Error(),
			})
			return
		}
		if token["iss"] != ApplicationName {
			c.AbortWithStatusJSON(401,
				gin.H{
					"Message":    "Unauthorized. Unknown Media",
					"StatusCode": 401,
				})
			return
		}
	}
	return authFunc
}

func GenerateToken(username, email string) (string, error) {
	claims := MyClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    ApplicationName,
			ExpiresAt: time.Now().Add(LOGIN_EXPIRATION_DURATION).Unix(),
		},
		Username: username,
		Email:    email,
	}
	token := jwt.NewWithClaims(JwtSigningMethod, claims)
	return token.SignedString(JwtSignatureKey)
}

func SearchElement(arr []string, word string) bool {
	for _, val := range arr {
		if val == word {
			return true
		}
	}
	return false
}

func SearchDelete(arr []string, word string) ([]string, bool) {
	var list []string
	var ischange bool
	for index, val := range arr {
		if val == word {
			list = append(arr[:index], arr[index+1:]...)
			ischange = true
		}
	}
	return list, ischange
}

func parseToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Signing method invalid")
		} else if method != JwtSigningMethod {
			return nil, fmt.Errorf("Signing method invalid")
		}
		return JwtSignatureKey, nil
	})
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, err
	}
	return claims, nil
}
