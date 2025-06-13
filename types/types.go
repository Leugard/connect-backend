package types

import (
	"mime/multipart"
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
	GetIncomingFriendRequests(userID uuid.UUID) ([]User, error)
	GetOutgoingFriendRequests(userID uuid.UUID) ([]User, error)
	GetFriends(userID uuid.UUID) ([]User, error)
	GetBlockedUsers(userID uuid.UUID) ([]User, error)
	GetMessagesByConversation(convoID uuid.UUID) ([]Message, error)
	GetUserConversations(userID uuid.UUID) ([]ConversationPreview, error)
	GetOrCreateConversation(user1, user2 uuid.UUID) (uuid.UUID, error)
	GetStories(userID uuid.UUID) ([]Story, error)
	CreateUser(User) error
	CreateSession(session Session) error
	CreateFriendRequest(senderID, receiverID uuid.UUID) error
	CreateFriendship(user1, user2 uuid.UUID) error
	CreateStory(story Story) error
	GetStoryViewers(storyId, ownerID uuid.UUID) ([]StoryViewer, error)
	GetOtherParticipant(convoID, senderID uuid.UUID) (uuid.UUID, error)
	GenerateFriendCode() (string, error)
	FriendCodeExists(code string) (bool, error)
	FriendRequestExists(senderID, receiverID uuid.UUID) (bool, error)
	UpdateUser(User) error
	UpdateMessageStatus(messageID uuid.UUID, status string) error
	SaveRefreshToken(rt RefreshToken) error
	DeleteUser(id uuid.UUID) error
	DeleteRefreshToken(token string) error
	DeleteSessionByID(userID uuid.UUID, sessionID uuid.UUID) error
	DeleteFriendRequest(requestID uuid.UUID) error
	CancelFriendRequest(senderID, receiverID uuid.UUID) error
	BlockUser(blockerID, blockedID uuid.UUID) error
	UnblockUser(blockerID, blockedID uuid.UUID) error
	IsBlocked(userA, userB uuid.UUID) (bool, error)
	SendMessage(conversationID, senderID uuid.UUID, content, imageURL string) (Message, error)
	AreFriends(user1, user2 uuid.UUID) (bool, error)
	IsParticipant(userID, convoID uuid.UUID) (bool, error)
	MarkStoryViewed(storyID, viewerID uuid.UUID) error
	MarkMessagesAsRead(conversationID, readerID uuid.UUID) error
	CleanupExpiredStories() (int64, error)
}

type UploadStore interface {
	UploadImage(file multipart.File, folder, filename string) (string, error)
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
	FriendCode      string    `json:"friendCode"`
	Username        string    `json:"username"`
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

type Story struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"userId"`
	MediaURL  string    `json:"mediaUrl"`
	Caption   string    `json:"caption"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type StoryViewer struct {
	ID         uuid.UUID `json:"id"`
	Username   string    `json:"username"`
	ProfilePic string    `json:"profilePic"`
	ViewedAt   time.Time `json:"viewedAt"`
}

type Message struct {
	ID             uuid.UUID `json:"id"`
	ConversationID uuid.UUID `json:"conversationId"`
	SenderID       uuid.UUID `json:"senderId"`
	Content        string    `json:"content"`
	ImageURL       string    `json:"imageUrl"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"createdAt"`
}

type ConversationPreview struct {
	ConversationID   uuid.UUID `json:"conversationId"`
	FriendID         uuid.UUID `json:"friendId"`
	FriendUsername   string    `json:"friendUsername"`
	FriendProfilePic string    `json:"friendProfilePic"`
	LastContent      string    `json:"lastContent,omitempty"`
	LastImageUrl     string    `json:"lastImageUrl,omitempty"`
	LastMessageAt    time.Time `json:"lastMessageAt"`
}

type RegisterUserPayload struct {
	Username string `json:"username" validate:"required,min=1,max=20"`
	Email    string `json:"email" validate:"email,required"`
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
