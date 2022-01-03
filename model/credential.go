package model

type Credentials struct {
	Username string `json:"user_name" binding:"required"`
	Password string `json:"user_password" binding:"required"`
	Email    string `json:"user_email"`
}
