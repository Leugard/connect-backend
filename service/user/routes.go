package user

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Leugard/connect-backend/middleware"
	"github.com/Leugard/connect-backend/service/auth"
	"github.com/Leugard/connect-backend/types"
	"github.com/Leugard/connect-backend/utils"
	"github.com/go-playground/validator"
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
	router.HandleFunc("/login", h.handleLogin).Methods("POST")
	router.HandleFunc("/register", h.handleRegister).Methods("POST")
	router.HandleFunc("/forgot-password", h.handleForgotPassword).Methods("POST")
	router.HandleFunc("/reset-password", h.handleResetPassword).Methods("POST")
	router.HandleFunc("/resend-otp", h.handleResendOTP).Methods("POST")
	router.HandleFunc("/verify-otp", h.handleVerifyOTP).Methods("POST")

	router.Handle("/me", middleware.RequireAuth(http.HandlerFunc(h.handleProfile))).Methods("GET")
	router.Handle("/me", middleware.RequireAuth(http.HandlerFunc(h.handleEditProfile))).Methods("PATCH")
	router.Handle("/me", middleware.RequireAuth(http.HandlerFunc(h.handleDeleteAccount))).Methods("DELETE")
	router.Handle("/sessions", middleware.RequireAuth(http.HandlerFunc(h.handleListSessions))).Methods("GET")
	router.Handle("/status", middleware.RequireAuth(http.HandlerFunc(h.handleStatus))).Methods("GET")
	router.Handle("/change-password", middleware.RequireAuth(http.HandlerFunc(h.handleChangePassword))).Methods("POST")
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	var payload types.LoginUserPayload
	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	// validate payload
	if err := utils.Validate.Struct(payload); err != nil {
		errors := err.(validator.ValidationErrors)
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid payload %v", errors))
		return
	}

	// get user by email
	u, err := h.store.GetUserByLogin(payload.Login)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("User not found"))
		return
	}

	// check if user is verified
	if !u.IsVerified {
		utils.WriteError(w, http.StatusForbidden, fmt.Errorf("account not verified"))
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(payload.Password))
	if err != nil {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("Invalid email or password"))
		return
	}

	// generate token
	token, err := auth.GenerateJWT(u.ID.String())
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	ip := middleware.GetIP(r.RemoteAddr)
	if !middleware.AllowRequest(ip) {
		utils.WriteError(w, 429, fmt.Errorf("Too many requests. Please wait and try again."))
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "succesfully logged in",
		"token":   token,
	})

	session := types.Session{
		ID:        uuid.New(),
		UserID:    u.ID,
		IP:        r.RemoteAddr,
		UserAgent: r.UserAgent(),
		CreatedAt: time.Now(),
	}

	_ = h.store.CreateSession(session)
}

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	var payload types.RegisterUserPayload
	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
	}

	// validate payload
	if err := utils.Validate.Struct(payload); err != nil {
		errors := err.(validator.ValidationErrors)
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid payload %v", errors))
		return
	}

	// get user by email
	_, err := h.store.GetUserByEmail(payload.Email)
	if err == nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("user with email %s already exists", payload.Email))
		log.Fatal("")
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
	utils.MarkOTPSent(payload.Email)

	// create the user
	err = h.store.CreateUser(types.User{
		ID:              uuid.New(),
		Username:        payload.Username,
		Email:           payload.Email,
		Password:        hashedPassword,
		IsVerified:      false,
		VerificationOTP: otp,
		OTPExp:          utils.SetOTPExpiration(),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	})

	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("Kontol"))
		return
	}

	if err := utils.SendEmailOTP(payload.Email, otp); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to send OTP email"))
		return
	}

	utils.WriteJSON(w, http.StatusCreated, map[string]string{
		"message": "user created succesfully",
	})
}

func (h *Handler) handleListSessions(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(middleware.UserIDKey).(string)
	if !ok || userID == "" {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
		return
	}

	id, _ := uuid.Parse(userID)

	sessions, err := h.store.GetSessionByUserID(id)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]any{
		"sessions": sessions,
	})
}

func (h *Handler) handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	var payload types.ForgotPasswordPayload
	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	if err := utils.Validate.Struct(payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("Invalid email"))
		return
	}

	if !utils.CanSendOTP(payload.Email) {
		utils.WriteError(w, http.StatusTooManyRequests, fmt.Errorf("Please wait 30 seconds before requesting another OTP"))
		return
	}

	user, err := h.store.GetUserByEmail(payload.Email)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("email not found"))
		return
	}

	otp, err := utils.GenerateOTP()
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("Couln't generate OTP"))
		return
	}

	user.VerificationOTP = otp
	user.OTPExp = utils.SetOTPExpiration()
	user.UpdatedAt = time.Now()

	if err := h.store.UpdateUser(*user); err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("couldn't send OTP"))
		return
	}

	if err := utils.SendEmailOTP(payload.Email, otp); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("Couln't send OTP email"))
		return
	}
	utils.MarkOTPSent(payload.Email)

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "OTP sent to your email",
	})

}

func (h *Handler) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	var payload types.ResetForgotPasswordPayload
	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	user, err := h.store.GetUserByEmail(payload.Email)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("user not found"))
		return
	}

	if user.VerificationOTP != payload.OTP {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("invalid OTP"))
		return
	}

	if time.Now().After(user.OTPExp) {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("OTP expired"))
		return
	}

	hashed, _ := auth.HashedPassword(payload.NewPassword)
	user.Password = hashed
	user.VerificationOTP = ""
	user.OTPExp = time.Time{}
	user.UpdatedAt = time.Now()

	if err := h.store.UpdateUser(*user); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to reset password"))
		return
	}

	ip := middleware.GetIP(r.RemoteAddr)
	if !middleware.AllowRequest(ip) {
		utils.WriteError(w, 429, fmt.Errorf("Too many requests. Please wait and try again"))
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "password reset successfully",
	})
}

func (h *Handler) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(middleware.UserIDKey).(string)
	if !ok || userID == "" {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
		return
	}

	var payload types.ResetPasswordPayload
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

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(payload.CurrentPassword)); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("incorrect current password"))
	}

	newHash, err := auth.HashedPassword(payload.NewPassword)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to hash new password"))
	}

	user.Password = newHash
	user.UpdatedAt = time.Now()
	if err := h.store.UpdateUser(*user); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to update password"))
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "password updated successfully",
	})
}

func (h *Handler) handleResendOTP(w http.ResponseWriter, r *http.Request) {
	var payload types.ResendOTPPayload
	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	if err := utils.Validate.Struct(payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("Invalid email"))
		return
	}

	if !utils.CanSendOTP(payload.Email) {
		utils.WriteError(w, http.StatusTooManyRequests, fmt.Errorf("Please wait 30 seconds before requesting another OTP"))
		return
	}

	user, err := h.store.GetUserByEmail(payload.Email)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("User not found"))
		return
	}

	otp, err := utils.GenerateOTP()
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("Couln't generate OTP"))
		return
	}

	user.VerificationOTP = otp
	user.OTPExp = utils.SetOTPExpiration()

	if err := h.store.UpdateUser(*user); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("Couln't update OTP"))
		return
	}

	if err := utils.SendEmailOTP(payload.Email, otp); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("Couln't send OTP email"))
		return
	}
	utils.MarkOTPSent(payload.Email)

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "OTP resent succesfully",
	})
}

func (h *Handler) handleVerifyOTP(w http.ResponseWriter, r *http.Request) {
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
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("User not found"))
		return
	}

	if user.IsVerified {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("Account already verified"))
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

	user.IsVerified = true
	user.VerificationOTP = ""
	user.OTPExp = time.Time{}

	if err := h.store.UpdateUser(*user); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("Failed to verify user"))
		return
	}

	token, err := auth.GenerateJWT(user.ID.String())
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("Failed to generate token"))
		return
	}

	ip := middleware.GetIP(r.RemoteAddr)
	if !middleware.AllowRequest(ip) {
		utils.WriteError(w, 429, fmt.Errorf("Too many requests. Please wait and try again"))
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "Account verified successfully",
		"token":   token,
	})
}

func (h *Handler) handleProfile(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(middleware.UserIDKey).(string)
	if !ok || userID == "" {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("user not authenticated"))
		return
	}

	id, _ := uuid.Parse(userID)

	user, err := h.store.GetUserByID(id)
	if err != nil {
		utils.WriteError(w, http.StatusNotFound, fmt.Errorf("user not found"))
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"data": map[string]any{
			"id":        user.ID,
			"username":  user.Username,
			"email":     user.Email,
			"verified":  user.IsVerified,
			"createdAt": user.CreatedAt,
		},
	})
}

func (h *Handler) handleEditProfile(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(middleware.UserIDKey).(string)
	if !ok || userID == "" {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("user not authenticated"))
		return
	}

	var payload types.UpdateProfilePayload
	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	if err := utils.Validate.Struct(payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid input"))
		return
	}

	id, err := uuid.Parse(userID)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid user id"))
		return
	}

	user, err := h.store.GetUserByID(id)
	if err != nil {
		utils.WriteError(w, http.StatusNotFound, fmt.Errorf("user not found"))
		return
	}

	if payload.Username != "" {
		user.Username = payload.Username
	}

	user.UpdatedAt = time.Now()

	if err := h.store.UpdateUser(*user); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to update profile"))
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]any{
		"message": "Profile updated successfully",
	})
}

func (h *Handler) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(middleware.UserIDKey).(string)
	if !ok || userID == "" {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
		return
	}

	id, err := uuid.Parse(userID)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid user ID"))
		return
	}

	err = h.store.DeleteUser(id)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to delete account"))
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "account deleted successfully",
	})
}

func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
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

	utils.WriteJSON(w, http.StatusOK, map[string]any{
		"email":      user.Email,
		"isVerified": user.IsVerified,
	})
}
