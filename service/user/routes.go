package user

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Leugard/connect-backend/middleware"
	"github.com/Leugard/connect-backend/service/auth"
	"github.com/Leugard/connect-backend/service/websocket"
	"github.com/Leugard/connect-backend/types"
	"github.com/Leugard/connect-backend/utils"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	store types.UserStore
}

func NewHandler(store types.UserStore) *Handler {
	return &Handler{store: store}
}

func (h *Handler) RegisterRoutes(router *mux.Router) {
	wsHandler := &websocket.Handler{
		Store:   h.store,
		Manager: websocket.NewManager(),
	}
	router.Handle("/ws", middleware.RequireAuth(middleware.RequireVerified(h.store.GetUserByID)(http.HandlerFunc(wsHandler.HandleWebSocket))))

	router.HandleFunc("/register", h.handleRegister).Methods("POST")
	router.HandleFunc("/login", h.handleLogin).Methods("POST")
	router.HandleFunc("/google", h.handleGoogleLogin).Methods("POST")
	router.Handle("/logout", middleware.RequireAuth(http.HandlerFunc(h.handleLogout))).Methods("POST")

	router.HandleFunc("/refresh-token", h.handleRefreshToken).Methods("POST")
	router.Handle("/verify-otp", middleware.RequireAuth(http.HandlerFunc(h.handleVerifyOTP))).Methods("POST")
	router.Handle("/resend-otp", middleware.RequireAuth(http.HandlerFunc(h.handleResendOTP))).Methods("POST")
	router.Handle("/onboarding", middleware.RequireAuth(http.HandlerFunc(h.handleOnboarding))).Methods("POST")
	router.Handle("/sessions", middleware.RequireAuth(http.HandlerFunc(h.handleListSessions))).Methods("GET")
	router.Handle("/sessions/{id}", middleware.RequireAuth(http.HandlerFunc(h.handleDeleteSession))).Methods("DELETE")

	router.Handle("/me", middleware.RequireAuth(middleware.RequireVerified(h.store.GetUserByID)(http.HandlerFunc(h.handleProfile)))).Methods("GET")
	router.Handle("/friend/request", middleware.RequireAuth(middleware.RequireVerified(h.store.GetUserByID)(http.HandlerFunc(h.handleSendFriendRequest)))).Methods("POST")
	router.Handle("/friend/request", middleware.RequireAuth(middleware.RequireVerified(h.store.GetUserByID)(http.HandlerFunc(h.handleCancelFriendRequest)))).Methods("DELETE")
	router.Handle("/friend/response", middleware.RequireAuth(middleware.RequireVerified(h.store.GetUserByID)(http.HandlerFunc(h.handleRespondToFriendRequest)))).Methods("POST")
	router.Handle("/friends/requests", middleware.RequireAuth(middleware.RequireVerified(h.store.GetUserByID)(http.HandlerFunc(h.handleGetFriendRequests)))).Methods("GET")
	router.Handle("/friends", middleware.RequireAuth(middleware.RequireVerified(h.store.GetUserByID)(http.HandlerFunc(h.handleGetFriends)))).Methods("GET")
	router.Handle("/block", middleware.RequireAuth(middleware.RequireVerified(h.store.GetUserByID)(http.HandlerFunc(h.handleBlockUser)))).Methods("POST")
	router.Handle("/unblock", middleware.RequireAuth(middleware.RequireVerified(h.store.GetUserByID)(http.HandlerFunc(h.handleUnblockUser)))).Methods("POST")
	router.Handle("/blocked", middleware.RequireAuth(middleware.RequireVerified(h.store.GetUserByID)(http.HandlerFunc(h.handleGetBlockedUsers)))).Methods("GET")
	router.Handle("/messages/send", middleware.RequireAuth(middleware.RequireVerified(h.store.GetUserByID)(http.HandlerFunc(h.handleSendMessage)))).Methods("POST")
	router.Handle("/messages/{conversationId}", middleware.RequireAuth(middleware.RequireVerified(h.store.GetUserByID)(http.HandlerFunc(h.handleGetMessages)))).Methods("GET")

}

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	var payload types.RegisterUserPayload
	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
	}

	// validate payload
	if err := utils.Validate.Struct(payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid payload"))
		return
	}

	// check user
	if existing, _ := h.store.GetUserByEmail(payload.Email); existing != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("user with email %s already exists", payload.Email))
		return
	}

	// verify password
	hashedPassword, err := auth.HashedPassword(payload.Password)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	otp, err := utils.GenerateOTP()
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to generate OTP"))
		return
	}

	friendCode, err := h.store.GenerateFriendCode()
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to generate friend code"))
		return
	}

	// create the user
	user := types.User{
		ID:              uuid.New(),
		Username:        payload.Username,
		FriendCode:      friendCode,
		Email:           payload.Email,
		Password:        hashedPassword,
		IsVerified:      false,
		VerificationOTP: otp,
		OTPExp:          utils.SetOTPExpiration(),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	if err := h.store.CreateUser(user); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to create user", err.Error()))
		return
	}

	if err := utils.SendEmailOTP(payload.Email, otp); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to send OTP email"))
		return
	}

	utils.MarkOTPSent(user.Email)

	token, err := auth.GenerateJWT(user.ID.String())
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to generate token"))
		return
	}

	utils.WriteJSON(w, http.StatusCreated, map[string]any{
		"message":    "user created succesfully",
		"token":      token,
		"isVerified": false,
	})
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	var payload types.LoginUserPayload
	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	// validate payload
	if err := utils.Validate.Struct(payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid payload"))
		return
	}

	// get user by email
	u, err := h.store.GetUserByLogin(payload.Login)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("User not found"))
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(payload.Password)); err != nil {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("Invalid email or password"))
		return
	}

	otp, err := utils.GenerateOTP()
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to generate otp"))
		return
	}

	u.VerificationOTP = otp
	u.OTPExp = utils.SetOTPExpiration()
	u.UpdatedAt = time.Now()

	if err := h.store.UpdateUser(*u); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to update ser"))
		return
	}

	accessToken, err := auth.GenerateJWT(u.ID.String())
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to generate access token"))
		return
	}

	refreshToken := uuid.New().String()
	refreshExp := time.Now().Add(7 * 24 * time.Hour)

	err = h.store.SaveRefreshToken(types.RefreshToken{
		ID:        uuid.New(),
		UserID:    u.ID,
		Token:     refreshToken,
		ExpiresAt: refreshExp,
	})

	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to store refresh token", err.Error()))
		return
	}

	if err := utils.SendEmailOTP(u.Email, otp); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to send OTP"))
		return
	}

	utils.MarkOTPSent(u.Email)

	ip := middleware.GetIP(r.RemoteAddr)
	ua := r.UserAgent()
	deviceID := utils.HashDeviceInfo(ip, ua)

	session := types.Session{
		ID:           uuid.New(),
		UserID:       u.ID,
		DeviceID:     deviceID,
		IpAddress:    ip,
		UserAgent:    ua,
		RefreshToken: refreshToken,
		CreatedAt:    time.Now(),
	}

	if err := h.store.CreateSession(session); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to store session", err.Error()))
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]any{
		"message":      "OTP sent to your email",
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
		"isVerified":   u.IsVerified,
	})
}

func (h *Handler) handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		IDToken string `json:"idToken" validate:"required"`
	}

	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	if err := utils.Validate.Struct(payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid input"))
		return
	}

	gPayload, err := auth.VerifyGoogleIDToken(payload.IDToken)
	if err != nil {
		utils.WriteError(w, http.StatusUnauthorized, err)
		return
	}

	email, ok := gPayload.Claims["email"].(string)
	if !ok {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to get email from Google claims", err.Error()))
		return
	}
	name, _ := gPayload.Claims["name"].(string)
	picture, _ := gPayload.Claims["picture"].(string)

	friendCode, err := h.store.GenerateFriendCode()
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to generate friend code"))
		return
	}
	log.Printf(friendCode)

	user, err := h.store.GetUserByEmail(email)
	if err != nil {
		user = &types.User{
			ID:           uuid.New(),
			Email:        email,
			Username:     name,
			FriendCode:   friendCode,
			IsVerified:   false,
			ProfileImage: picture,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}
		if err := h.store.CreateUser(*user); err != nil {
			utils.WriteError(w, 500, fmt.Errorf("failed to create google user"))
			return
		}
	}

	accessToken, err := auth.GenerateJWT(user.ID.String())
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to generate access token"))
		return
	}

	refreshToken := uuid.New().String()
	refreshExp := time.Now().Add(7 * 24 * time.Hour)

	err = h.store.SaveRefreshToken(types.RefreshToken{
		ID:        uuid.New(),
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: refreshExp,
	})
	if err != nil {
		utils.WriteError(w, 500, fmt.Errorf("failed to store refresh token"))
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]any{
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
		"isVerified":   user.IsVerified,
	})
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		RefreshToken string `json:"refreshToken" validate:"required"`
	}
	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf(err.Error()))
		return
	}

	if err := utils.Validate.Struct(payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid input"))
		return
	}

	userID, ok := r.Context().Value(middleware.UserIDKey).(string)
	if !ok {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
		return
	}

	rt, err := h.store.GetRefreshToken(payload.RefreshToken)
	if err != nil || rt.UserID.String() != userID {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("invalid refresh token"))
		return
	}

	if err := h.store.DeleteRefreshToken(payload.RefreshToken); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to revoke token"))
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "logout seccesful",
	})
}

func (h *Handler) handleResendOTP(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(middleware.UserIDKey).(string)
	if !ok || userID == "" {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
		return
	}

	id, _ := uuid.Parse(userID)
	user, err := h.store.GetUserByID(id)
	if err != nil {
		utils.WriteError(w, http.StatusNotFound, fmt.Errorf("user not found"))
		return
	}

	if user.IsVerified {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("account already verified"))
		return
	}

	if !utils.CanSendOTP(user.Email) {
		utils.WriteError(w, http.StatusTooManyRequests, fmt.Errorf("please wait before requesting another OTP"))
		return
	}

	otp, err := utils.GenerateOTP()
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to generate OTP"))
		return
	}

	user.VerificationOTP = otp
	user.OTPExp = utils.SetOTPExpiration()
	user.UpdatedAt = time.Now()

	if err := h.store.UpdateUser(*user); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to update OTP"))
		return
	}

	utils.MarkOTPSent(user.Email)

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "OTP resent successfully",
	})
}

func (h *Handler) handleVerifyOTP(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(middleware.UserIDKey).(string)
	if !ok || userID == "" {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
		return
	}

	var payload types.VerifyOTPPayload
	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	if err := utils.Validate.Struct(payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid payload"))
		return
	}

	user, err := h.store.GetUserByEmail(payload.Email)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("User not found", err.Error()))
		return
	}

	if user.VerificationOTP != payload.OTP {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("Invalid OTP"))
		return
	}

	if time.Now().After(user.OTPExp) {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("OTP Expired"))
		return
	}

	user.VerificationOTP = ""
	user.OTPExp = time.Time{}
	user.UpdatedAt = time.Now()

	if err := h.store.UpdateUser(*user); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("Failed to verify user"))
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]any{
		"message":    "Account verified successfully",
		"isVerified": user.IsVerified,
		"needsSetup": !user.IsVerified,
	})
}

func (h *Handler) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		RefreshToken string `json:"refreshToken" validate:"required"`
	}

	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	if err := utils.Validate.Struct(payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid input"))
		return
	}

	oldRT, err := h.store.GetRefreshToken(payload.RefreshToken)
	if err != nil {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("invalid refresh token", err.Error()))
		return
	}

	if time.Now().After(oldRT.ExpiresAt) {
		_ = h.store.DeleteRefreshToken(payload.RefreshToken)
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("refresh token expired"))
		return
	}

	_ = h.store.DeleteRefreshToken(payload.RefreshToken)

	accessToken, err := auth.GenerateJWT(oldRT.UserID.String())
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to generate access token"))
		return
	}

	newRTValue := uuid.New().String()
	newRT := types.RefreshToken{
		ID:        uuid.New(),
		UserID:    oldRT.UserID,
		Token:     newRTValue,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}

	if err := h.store.SaveRefreshToken(newRT); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to store new refresh token"))
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"accessToken":  accessToken,
		"refreshToken": newRT.Token,
		"expiresIn":    "900",
	})
}

func (h *Handler) handleOnboarding(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(middleware.UserIDKey).(string)
	if !ok || userID == "" {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
		return
	}

	var payload types.OnboardingPayload
	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	if err := utils.Validate.Struct(payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid input"))
		return
	}

	id, _ := uuid.Parse(userID)
	user, err := h.store.GetUserByID(id)
	if err != nil {
		utils.WriteError(w, http.StatusNotFound, fmt.Errorf("user not found", err.Error()))
		return
	}

	if user.IsVerified {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("onboarding already completed"))
		return
	}

	user.ProfileImage = payload.ProfileImage
	user.Bio = payload.Bio
	user.Username = payload.Username
	user.IsVerified = true
	user.UpdatedAt = time.Now()

	if err := h.store.UpdateUser(*user); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to complete onboarding"))
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "onboarding completed successfully",
	})
}

func (h *Handler) handleListSessions(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(middleware.UserIDKey).(string)
	if !ok || userID == "" {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
		return
	}

	id, _ := uuid.Parse(userID)
	sessions, err := h.store.GetSessionByUser(id)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	var result []map[string]any
	for _, s := range sessions {
		result = append(result, map[string]any{
			"id":        s.ID,
			"deviceId":  s.DeviceID,
			"userAgent": s.UserAgent,
			"ipAddress": s.IpAddress,
			"createdAt": s.CreatedAt,
		})
	}

	utils.WriteJSON(w, http.StatusOK, result)
}

func (h *Handler) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["id"]

	id, err := uuid.Parse(sessionID)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid session ID"))
		return
	}

	userID, ok := r.Context().Value(middleware.UserIDKey).(string)
	if !ok || userID == "" {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
		return
	}
	user, _ := uuid.Parse(userID)

	session, err := h.store.GetSessionByID(id)
	if err == nil && session.UserID == user {
		_ = h.store.DeleteRefreshToken(session.RefreshToken)
	}

	if err := h.store.DeleteSessionByID(user, id); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to delete session"))
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "session logged out successfully",
	})

}

func (h *Handler) handleProfile(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(middleware.UserIDKey).(string)
	if !ok || userID == "" {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("user not authenticated"))
		return
	}

	id, err := uuid.Parse(userID)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid user ID"))
		return
	}

	user, err := h.store.GetUserByID(id)
	if err != nil {
		utils.WriteError(w, http.StatusNotFound, fmt.Errorf("user not found"))
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]any{
		"id":           user.ID,
		"username":     user.Username,
		"email":        user.Email,
		"profileImage": user.ProfileImage,
		"bio":          user.Bio,
		"createdAt":    user.CreatedAt,
	})

}

func (h *Handler) handleSendFriendRequest(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		FriendCode string `json:"friendCode" validate:"required"`
	}

	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf(err.Error()))
	}

	if err := utils.Validate.Struct(payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid input", err.Error()))
		return
	}

	sender, _ := r.Context().Value(middleware.UserIDKey).(string)
	senderID, _ := uuid.Parse(sender)

	receiver, err := h.store.GetUserByFriendCode(payload.FriendCode)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("user not found", err.Error()))
		return
	}

	if receiver.ID == senderID {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("cannot sent friend request to yourself"))
		return
	}

	if !receiver.IsVerified {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("cannot sent request to unverified user"))
		return
	}

	exists, err := h.store.FriendRequestExists(senderID, receiver.ID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	if exists {
		utils.WriteError(w, 409, fmt.Errorf("friend request already sent"))
		return
	}

	err = h.store.CreateFriendRequest(senderID, receiver.ID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	isBlocked, err := h.store.IsBlocked(senderID, receiver.ID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to check block status"))
		return
	}

	if isBlocked {
		utils.WriteError(w, 403, fmt.Errorf("cannot send request - one of you has blocked the other"))
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "friend request sent",
	})
}

func (h *Handler) handleRespondToFriendRequest(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		RequestID string `json:"requestId" validate:"required"`
		Accept    bool   `json:"accept"`
	}

	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf(err.Error()))
		return
	}

	if err := utils.Validate.Struct(payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid input", err.Error()))
		return
	}

	requestID, err := uuid.Parse(payload.RequestID)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid request ID"))
		return
	}

	userID := r.Context().Value(middleware.UserIDKey).(string)
	user, _ := uuid.Parse(userID)

	fr, err := h.store.GetFriendRequestByID(requestID)
	if err != nil {
		utils.WriteError(w, 404, fmt.Errorf("friend request not found"))
		return
	}

	if fr.ReceiverID != user {
		utils.WriteError(w, 403, fmt.Errorf("you are not authorized to respond to this request"))
		return
	}

	status := "rejected"
	if payload.Accept {
		if err := h.store.CreateFriendship(fr.SenderID, fr.ReceiverID); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to create friendship", err.Error()))
			return
		}
		status = "accepted"
	}

	err = h.store.DeleteFriendRequest(requestID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to delete friend request"))
		return
	}

	utils.WriteJSON(w, 200, map[string]string{
		"message": fmt.Sprintf("friend request %s", status),
	})
}

func (h *Handler) handleGetFriendRequests(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(middleware.UserIDKey).(string)
	user, _ := uuid.Parse(userID)

	queryType := r.URL.Query().Get("type")

	var users []types.User
	var err error

	if queryType == "outgoing" {
		users, err = h.store.GetOutgoingFriendRequests(user)
	} else {
		users, err = h.store.GetIncomingFriendRequests(user)
	}

	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to get friend requests"))
		return
	}

	result := make([]map[string]any, 0)
	for _, u := range users {
		result = append(result, map[string]any{
			"id":           u.ID,
			"username":     u.Username,
			"email":        u.Email,
			"profileImage": u.ProfileImage,
			"friendCode":   u.FriendCode,
		})
	}

	utils.WriteJSON(w, http.StatusOK, result)
}

func (h *Handler) handleGetFriends(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(middleware.UserIDKey).(string)
	user, _ := uuid.Parse(userID)

	friends, err := h.store.GetFriends(user)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to fetch friends"))
		return
	}

	result := make([]map[string]any, 0)
	for _, f := range friends {
		result = append(result, map[string]any{
			"id":           f.ID,
			"username":     f.Username,
			"email":        f.Email,
			"profileImage": f.ProfileImage,
			"friendCode":   f.FriendCode,
		})
	}

	utils.WriteJSON(w, http.StatusOK, result)
}

func (h *Handler) handleCancelFriendRequest(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		ReceiverID string `json:"receiverID" validate:"required"`
	}

	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	senderID := r.Context().Value(middleware.UserIDKey).(string)
	id, _ := uuid.Parse(senderID)
	receiverID, err := uuid.Parse(payload.ReceiverID)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid receiver ID"))
		return
	}

	err = h.store.CancelFriendRequest(id, receiverID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "Friend request canceled",
	})
}

func (h *Handler) handleBlockUser(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		UserID string `json:"userId" validate:"required"`
	}

	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	blockerID := r.Context().Value(middleware.UserIDKey).(string)
	blocker, _ := uuid.Parse(blockerID)
	blocked, err := uuid.Parse(payload.UserID)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid user ID"))
		return
	}

	if blocked == blocker {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("cannot block yourself"))
		return
	}

	err = h.store.BlockUser(blocker, blocked)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	_ = h.store.CancelFriendRequest(blocked, blocker)
	_ = h.store.CancelFriendRequest(blocker, blocked)

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "user blocked",
	})
}

func (h *Handler) handleUnblockUser(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		UserID string `json:"userId" validate:"required"`
	}

	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	blockerID := r.Context().Value(middleware.UserIDKey).(string)
	blocker, _ := uuid.Parse(blockerID)
	blocked, err := uuid.Parse(payload.UserID)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid user ID"))
		return
	}

	if blocked == blocker {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("cannot block yourself"))
		return
	}

	err = h.store.UnblockUser(blocker, blocked)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "user unblocked",
	})
}

func (h *Handler) handleGetBlockedUsers(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(middleware.UserIDKey).(string)
	user, _ := uuid.Parse(userID)

	users, err := h.store.GetBlockedUsers(user)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to get blocked users", err.Error()))
		return
	}

	var result []map[string]any
	for _, u := range users {
		result = append(result, map[string]any{
			"id":         u.ID,
			"username":   u.Username,
			"email":      u.Email,
			"profilePic": u.ProfileImage,
			"friendCode": u.FriendCode,
		})
	}

	utils.WriteJSON(w, http.StatusOK, result)
}

func (h *Handler) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		ReceiverID string `json:"receiverId" validate:"required"`
		Content    string `json:"content"`
		ImageURL   string `json:"imageUrl"`
	}

	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	if err := utils.Validate.Struct(payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid input"))
		return
	}

	if payload.Content == "" && payload.ImageURL == "" {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("message must have content or image"))
		return
	}

	senderID, _ := r.Context().Value(middleware.UserIDKey).(string)
	sender, _ := uuid.Parse(senderID)
	receiverID, err := uuid.Parse(payload.ReceiverID)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid receiver ID"))
		return
	}

	isFriend, err := h.store.AreFriends(sender, receiverID)
	if err != nil || !isFriend {
		utils.WriteError(w, 403, fmt.Errorf("you can only message friends"))
		return
	}

	convoID, err := h.store.GetOrCreateConversation(sender, receiverID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to get/create conversations", err.Error()))
		return
	}

	err = h.store.SendMessage(convoID, sender, payload.Content, payload.ImageURL)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to send message"))
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "message sent",
	})
}

func (h *Handler) handleGetMessages(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	convoID := vars["conversationId"]
	convo, err := uuid.Parse(convoID)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid conversation ID"))
		return
	}

	userID := r.Context().Value(middleware.UserIDKey).(string)
	user, _ := uuid.Parse(userID)

	isParticipant, err := h.store.IsParticipant(user, convo)
	if err != nil || !isParticipant {
		utils.WriteError(w, 403, fmt.Errorf("not part of this conversation"))
		return
	}

	messages, err := h.store.GetMessagesByConversation(convo)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to fetch messages", err.Error()))
		return
	}

	utils.WriteJSON(w, http.StatusOK, messages)
}
