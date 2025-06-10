package main

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"gopkg.in/gomail.v2"
)

func generateOTP(length int) string {
	rand.Seed(time.Now().UnixNano())
	digits := "0123456789"
	otp := ""
	for i := 0; i < length; i++ {
		otp += string(digits[rand.Intn(len(digits))])
	}

	return otp
}

func sendEmailOTP(to, from, smtpUser, smtpPass, smtpHost string, smtpPort int, otp string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", "Your otp code")

	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
		<html>
		<head>
			<meta charset="UTF-8">
			<title>Your OTP Code</title>
		</head>
		<body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
			<div style="max-width: 500px; margin: auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); padding: 30px;">
				<h2 style="text-align: center; color: #333333;">Your One-Time Password</h2>
				<p style="font-size: 16px; color: #555555;">Use the following OTP to proceed with your authentication:</p>
				<div style="text-align: center; margin: 20px 0;">
					<span style="display: inline-block; font-size: 32px; font-weight: bold; color: #2c3e50; background-color: #eaf1fb; padding: 12px 24px; border-radius: 6px; letter-spacing: 6px;">
						%s
					</span>
				</div>
				<p style="font-size: 14px; color: #999999; text-align: center;">This code is valid for the next 5 minutes.</p>
			</div>
		</body>
		</html>`, otp)

	m.SetBody("text/html", htmlBody)

	d := gomail.NewDialer(smtpHost, smtpPort, smtpUser, smtpPass)

	if err := d.DialAndSend(m); err != nil {
		return err
	}

	return d.DialAndSend(m)
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal()
	}

	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort, _ := strconv.Atoi(os.Getenv("SMTP_PORT"))
	smtpUser := os.Getenv("SMTP_USERNAME")
	smtpPass := os.Getenv("SMTP_PASSWORD")
	fromEmail := os.Getenv("FROM_EMAIL")
	toEmail := os.Getenv("TO_EMAIL")

	otp := generateOTP(6)
	fmt.Println("generated OTP:", otp)

	err := sendEmailOTP(toEmail, fromEmail, smtpUser, smtpPass, smtpHost, smtpPort, otp)
	if err != nil {
		log.Fatalf("Failed to send OTP: %v", err)
	}

	fmt.Println("OTP email sent successfully!")
}
