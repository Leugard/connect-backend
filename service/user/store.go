package user

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/Leugard/connect-backend/types"
	"github.com/google/uuid"
)

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) GetUserByEmail(email string) (*types.User, error) {
	rows, err := s.db.Query("SELECT * FROM users WHERE email = ?", email)
	if err != nil {
		return nil, err
	}

	u := new(types.User)
	for rows.Next() {
		u, err = scanRowIntoUser(rows)
		if err != nil {
			return nil, err
		}
	}

	if u.ID == uuid.Nil {
		return nil, fmt.Errorf("user not found")
	}

	return u, nil
}

func (s *Store) GetUserByID(id uuid.UUID) (*types.User, error) {
	rows, err := s.db.Query("SELECT * FROM users WHERE id = ?", id)
	if err != nil {
		return nil, err
	}

	u := new(types.User)
	for rows.Next() {
		u, err = scanRowIntoUser(rows)
		if err != nil {
			return nil, err
		}
	}

	if u.ID == uuid.Nil {
		return nil, fmt.Errorf("user not found")
	}

	return u, nil
}

func (s *Store) GetUserByLogin(login string) (*types.User, error) {
	rows, err := s.db.Query(`SELECT * FROM users WHERE email = ? OR username = ? LIMIT 1`, login, login)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	if !rows.Next() {
		return nil, fmt.Errorf("User not found")
	}

	return scanRowIntoUser(rows)
}

func (s *Store) GetRefreshToken(token string) (*types.RefreshToken, error) {
	row := s.db.QueryRow(`SELECT * FROM refresh_tokens WHERE token = ?`, token)

	var rt types.RefreshToken
	var uid string
	err := row.Scan(&rt.ID, &uid, &rt.Token, &rt.ExpiresAt, &rt.CreatedAt)
	if err != nil {
		return nil, err
	}

	rt.UserID, _ = uuid.Parse(uid)
	return &rt, nil
}

func (s *Store) GetSessionByUser(userID uuid.UUID) ([]types.Session, error) {
	rows, err := s.db.Query(`SELECT id, user_id, device_id, ip_address, user_agent, refresh_token, created_at FROM sessions WHERE user_id = ?`,
		userID.String())

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []types.Session
	for rows.Next() {
		var ses types.Session
		var uid string
		if err := rows.Scan(&ses.ID, &uid, &ses.DeviceID, &ses.IpAddress, &ses.UserAgent, &ses.RefreshToken, &ses.CreatedAt); err != nil {
			return nil, err
		}
		ses.UserID, _ = uuid.Parse(uid)
		sessions = append(sessions, ses)
	}

	return sessions, nil
}

func (s *Store) CreateUser(user types.User) error {
	_, err := s.db.Exec("INSERT INTO users (id, username, email, password, is_verified, verification_otp, otp_exp, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", user.ID, user.Username, user.Email, user.Password, user.IsVerified, user.VerificationOTP, user.OTPExp, user.CreatedAt, user.UpdatedAt)
	if err != nil {
		return err
	}

	return nil
}

func (s *Store) CreateSession(session types.Session) error {
	_, err := s.db.Exec(`INSERT INTO sessions (id, user_id, device_id, ip_address, user_agent, refresh_token, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		session.ID.String(), session.UserID.String(), session.DeviceID, session.IpAddress, session.UserAgent, session.RefreshToken, session.CreatedAt)

	return err
}

func (s *Store) UpdateUser(user types.User) error {
	_, err := s.db.Exec(`UPDATE users SET 
			username = ?,
			profile_pic = ?,
			bio = ?, 
			email = ?, 
			password = ?, 
			is_verified = ?, 
			verification_otp = ?, 
			otp_exp = ?, 
			updated_at = ?
		WHERE id = ?`, user.Username, user.ProfileImage, user.Bio, user.Email, user.Password, user.IsVerified, user.VerificationOTP, user.OTPExp, time.Now(), user.ID)
	if err != nil {
		return err
	}

	return nil
}

func (s *Store) SaveRefreshToken(rt types.RefreshToken) error {
	_, err := s.db.Exec(`INSERT INTO refresh_tokens (id,user_id,token,expires_at) VALUES (?,?,?,?)`, rt.ID, rt.UserID, rt.Token, rt.ExpiresAt)

	return err
}

func (s *Store) DeleteUser(id uuid.UUID) error {
	_, err := s.db.Exec("DELETE FROM users WHERE ID = ?", id.String())

	return err
}

func (s *Store) DeleteRefreshToken(token string) error {
	_, err := s.db.Exec(`DELETE FROM refresh_tokens WHERE token = ?`, token)

	return err
}

func scanRowIntoUser(rows *sql.Rows) (*types.User, error) {
	var user types.User
	var profilePic, bio sql.NullString

	err := rows.Scan(
		&user.ID,
		&user.Username,
		&profilePic,
		&bio,
		&user.Email,
		&user.Password,
		&user.IsVerified,
		&user.VerificationOTP,
		&user.OTPExp,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if profilePic.Valid {
		user.ProfileImage = profilePic.String
	}

	if bio.Valid {
		user.Bio = bio.String
	}

	return &user, nil
}
