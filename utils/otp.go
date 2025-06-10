package utils

import (
	"crypto/rand"
	"math/big"
	"sync"
	"time"
)

var (
	otpCooldowns = make(map[string]time.Time)
	cooldownMux  = &sync.Mutex{}
)

func GenerateOTP() (string, error) {
	const length = 5
	const charset = "0123456789"
	otp := make([]byte, length)

	for i := range otp {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}

		otp[i] = charset[num.Int64()]
	}

	return string(otp), nil
}

func SendEmailOTP(toEmail, otp string) error {
	// smtpHost := os.Getenv("SMTP_HOST")
	// smtpPort := 587
	// smtpUser := os.Getenv("SMTP_USERNAME")
	// smtpPass := os.Getenv("SMTP_PASSWORD")
	// fromEmail := os.Getenv("FROM_EMAIL")

	// subject := "🔐 Connect - OTP Code"

	// htmlBody := fmt.Sprintf(`
	// 	<!DOCTYPE html>
	// 	<html>
	// 	<head>
	// 	  <meta charset="UTF-8">
	// 	  <title>Verify Your Email</title>
	// 	  <style>
	// 	    @media only screen and (max-width: 600px) {
	// 	      .container {
	// 	        padding: 20px !important;
	// 	      }
	// 	    }
	// 	  </style>
	// 	</head>
	// 	<body style="margin:0; padding:0; font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color:#f5f7fa;">
	// 	  <div style="max-width:600px; margin:40px auto; background:white; border-radius:12px; box-shadow:0 5px 20px rgba(0,0,0,0.1); overflow:hidden;">
	// 	    <div style="background-color:#1E88E5; padding:20px; color:white; text-align:center;">
	// 	      <h2 style="margin:0;">🔐 Email Verification</h2>
	// 	    </div>
	// 	    <div class="container" style="padding:40px;">
	// 	      <p style="font-size:16px; color:#333;">Hello 👋,</p>
	// 	      <p style="font-size:16px; color:#555;">Thank you for signing up. Please use the following One-Time Password (OTP) to verify your email address. This code is valid for <strong>5 minutes</strong>.</p>

	// 	      <div style="text-align:center; margin:30px 0;">
	// 	        <span style="font-size:36px; font-weight:bold; letter-spacing:6px; color:#1E88E5; padding:15px 30px; border:2px dashed #2c3e50; border-radius:8px; display:inline-block;">
	// 	          %s
	// 	        </span>
	// 	      </div>

	// 	      <p style="font-size:14px; color:#888; text-align:center;">
	// 	        If you didn't request this, you can safely ignore this email.
	// 	      </p>
	// 	    </div>
	// 	    <div style="background-color:#f0f0f0; padding:15px; text-align:center; font-size:12px; color:#888;">
	// 	      &copy; %d Connect. All rights reserved.
	// 	    </div>
	// 	  </div>
	// 	</body>
	// 	</html>`, otp, time.Now().Year())

	// msg := gomail.NewMessage()
	// msg.SetHeader("From", fromEmail)
	// msg.SetHeader("To", toEmail)
	// msg.SetHeader("Subject", subject)
	// msg.SetBody("text/html", htmlBody)

	// d := gomail.NewDialer(smtpHost, smtpPort, smtpUser, smtpPass)

	// if err := d.DialAndSend(msg); err != nil {
	// 	log.Printf("Failed to send email: %v", err.Error())
	// 	return err
	// }

	// log.Printf("Sent OTP to %s", toEmail)
	return nil
}

func CanSendOTP(email string) bool {
	cooldownMux.Lock()
	defer cooldownMux.Unlock()

	lastSent, exists := otpCooldowns[email]
	if !exists {
		return true
	}

	return time.Since(lastSent) >= 30*time.Second
}

func MarkOTPSent(email string) {
	cooldownMux.Lock()
	defer cooldownMux.Unlock()
	otpCooldowns[email] = time.Now()
}

func SetOTPExpiration() time.Time {
	return time.Now().Add(5 * time.Minute)
}
