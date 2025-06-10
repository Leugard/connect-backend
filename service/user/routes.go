package user

import (
	"fmt"
	"net/http"
	"time"

	"github.com/Leugard/connect-backend/middleware"
	"github.com/Leugard/connect-backend/service/auth"
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

	// create the user
	user := types.User{
		ID:              uuid.New(),
		Username:        payload.Username,
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

	user, err := h.store.GetUserByEmail(email)
	if err != nil {
		user = &types.User{
			ID:           uuid.New(),
			Email:        email,
			Username:     name,
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
		utils.WriteError(w, http.StatusNotFound, fmt.Errorf("user not found"))
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
