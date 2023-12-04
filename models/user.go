package models

type User struct {
	ID            int    `json:"id"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	Password      string `json:"password"`
	Token         string `json:"token,omitempty"`
	TokenExpireAt int64  `json:"token_expire_at,omitempty"`
}
