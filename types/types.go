package types

import (
	"time"

	"github.com/google/uuid"
)

type UserStore interface {
	GetUserByEmail(email string) (*User, error)
	GetUserByID(id uuid.UUID) (*User, error)
	GetUserByLogin(login string) (*User, error)
	GetRefreshToken(token string) (*RefreshToken, error)
	GetSessionByUser(userID uuid.UUID) ([]Session, error)
	GetSessionByID(id uuid.UUID) (*Session, error)
	GetUserByFriendCode(code string) (*User, error)
	GetFriendRequestByID(requestID uuid.UUID) (*FriendRequest, error)
	CreateUser(User) error
	CreateSession(session Session) error
	CreateFriendRequest(senderID, receiverID uuid.UUID) error
	CreateFriendship(user1, user2 uuid.UUID) error
	GenerateFriendCode() (string, error)
	FriendCodeExists(code string) (bool, error)
	FriendRequestExists(senderID, receiverID uuid.UUID) (bool, error)
	UpdateUser(User) error
	SaveRefreshToken(rt RefreshToken) error
	DeleteUser(id uuid.UUID) error
	DeleteRefreshToken(token string) error
	DeleteSessionByID(userID uuid.UUID, sessionID uuid.UUID) error
	DeleteFriendRequest(requestID uuid.UUID) error
}

type RefreshToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Token     string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type Session struct {
	ID           uuid.UUID `json:"id"`
	UserID       uuid.UUID `json:"userId"`
	DeviceID     string    `json:"deviceId"`
	IpAddress    string    `json:"ipAddress"`
	UserAgent    string    `json:"userAgent"`
	RefreshToken string    `json:"refreshToken"`
	CreatedAt    time.Time `json:"createdAt"`
}

type FriendRequest struct {
	ID         uuid.UUID `json:"id"`
	SenderID   uuid.UUID `json:"senderId"`
	ReceiverID uuid.UUID `json:"receiverId"`
	Status     string    `json:"status"`
}

type User struct {
	ID              uuid.UUID `json:"id"`
	Username        string    `json:"username"`
	FriendCode      string    `json:"friendCode"`
	ProfileImage    string    `json:"profileImage"`
	Bio             string    `json:"bio"`
	Email           string    `json:"email"`
	Password        string    `json:"password"`
	IsVerified      bool      `json:"isVerified"`
	VerificationOTP string    `json:"-"`
	OTPExp          time.Time `json:"-"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

type RegisterUserPayload struct {
	Username string `json:"username" validate:"required,min=1,max=20"`
	Email    string `json:"email" validate:"required"`
	Password string `json:"password" validate:"required,min=6,max=20"`
}

type LoginUserPayload struct {
	Login    string `json:"login" validate:"required"`
	Password string `json:"password" validate:"required,min=6,max=20"`
}

type ResendOTPPayload struct {
	Email string `json:"email" validate:"required,email"`
}

type VerifyOTPPayload struct {
	Email string `json:"email" validate:"required,email"`
	OTP   string `json:"otp" validate:"required"`
}

type OnboardingPayload struct {
	ProfileImage string `json:"profileImage" validate:"required,url"`
	Username     string `json:"username" validate:"required,min=2,max=20"`
	Bio          string `json:"bio" validate:"required,max=225"`
}
