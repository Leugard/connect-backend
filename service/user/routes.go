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

	router.Handle("/verify-otp", middleware.RequireAuth(http.HandlerFunc(h.handleVerifyOTP))).Methods("POST")
	router.Handle("/resend-otp", middleware.RequireAuth(http.HandlerFunc(h.handleResendOTP))).Methods("POST")
	router.Handle("/onboarding", middleware.RequireAuth(http.HandlerFunc(h.handleOnboarding))).Methods("POST")
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

	utils.WriteJSON(w, http.StatusOK, map[string]any{
		"message":      "OTP sent to your email",
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
		"isVerified":   u.IsVerified,
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
