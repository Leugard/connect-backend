package user

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/Leugard/connect-backend/types"
	"github.com/Leugard/connect-backend/utils"
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

func (s *Store) GetSessionByID(id uuid.UUID) (*types.Session, error) {
	row := s.db.QueryRow(`SELECT id, user_id, device_id, ip_address, user_agent, refresh_token, created_at FROM sessions WHERE id = ?`, id.String())

	var ses types.Session
	var uid string
	if err := row.Scan(
		&ses.ID, &uid, &ses.DeviceID, &ses.IpAddress, &ses.UserAgent, &ses.RefreshToken, &ses.CreatedAt,
	); err != nil {
		return nil, err
	}
	ses.UserID, _ = uuid.Parse(uid)

	return &ses, nil
}

func (s *Store) GetUserByFriendCode(code string) (*types.User, error) {
	row := s.db.QueryRow(`SELECT id, friend_code, email, username, is_verified FROM users WHERE friend_code = ?`, code)

	var u types.User
	err := row.Scan(&u.ID, &u.FriendCode, &u.Email, &u.Username, &u.IsVerified)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) GetFriendRequestByID(requestID uuid.UUID) (*types.FriendRequest, error) {
	row := s.db.QueryRow(`SELECT id, sender_id, receiver_id, status FROM friend_requests WHERE id = ?`, requestID.String())

	var fr types.FriendRequest
	var senderID, receiverID string

	err := row.Scan(&fr.ID, &senderID, &receiverID, &fr.Status)
	if err != nil {
		return nil, err
	}

	fr.SenderID, _ = uuid.Parse(senderID)
	fr.ReceiverID, _ = uuid.Parse(receiverID)
	return &fr, err
}

func (s *Store) GetIncomingFriendRequests(userID uuid.UUID) ([]types.User, error) {
	rows, err := s.db.Query(`SELECT u.id, u.username, u.email, u.profile_pic, u.friend_code FROM friend_requests fr JOIN users u ON fr.sender_id = u.id WHERE fr.receiver_id = ? AND fr.status = 'pending'`,
		userID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []types.User
	for rows.Next() {
		var u types.User

		err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.ProfileImage, &u.FriendCode)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

func (s *Store) GetOutgoingFriendRequests(userID uuid.UUID) ([]types.User, error) {
	rows, err := s.db.Query(`SELECT u.id, u.username, u.email, u.profile_pic, u.friend_code FROM friend_requests fr JOIN users u ON fr.receiver_id = u.id WHERE fr.sender_id = ? AND fr.status = 'pending'`,
		userID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []types.User
	for rows.Next() {
		var u types.User

		err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.ProfileImage, &u.FriendCode)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

func (s *Store) GetFriends(userID uuid.UUID) ([]types.User, error) {
	rows, err := s.db.Query(`SELECT u.id, u.username, u.email, u.profile_pic, u.friend_code FROM friends f JOIN users u ON f.friend_id = u.id WHERE f.user_id = ?`,
		userID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var friends []types.User
	for rows.Next() {
		var u types.User

		err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.ProfileImage, &u.FriendCode)
		if err != nil {
			return nil, err
		}
		friends = append(friends, u)
	}

	return friends, nil
}

func (s *Store) CreateUser(user types.User) error {
	_, err := s.db.Exec("INSERT INTO users (id, username, friend_code, email, password, is_verified, verification_otp, otp_exp, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", user.ID, user.Username, user.FriendCode, user.Email, user.Password, user.IsVerified, user.VerificationOTP, user.OTPExp, user.CreatedAt, user.UpdatedAt)
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

func (s *Store) CreateFriendRequest(senderID, receiverID uuid.UUID) error {
	_, err := s.db.Exec(`INSERT INTO friend_requests (id, sender_id, receiver_id, status) VALUES (?, ?, ?, 'pending')`,
		uuid.New().String(), senderID.String(), receiverID.String())

	return err
}

func (s *Store) GenerateFriendCode() (string, error) {
	for i := 0; i < 10; i++ {
		code := utils.GenerateFriendCode(5)
		exists, err := s.FriendCodeExists(code)
		if err != nil {
			return "", err
		}

		if !exists {
			return code, nil
		}

		log.Printf("code: ", code)
	}

	return "", fmt.Errorf("failed to generate friend code after 10 tries")
}

func (s *Store) CreateFriendship(user1, user2 uuid.UUID) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}

	_, err = tx.Exec(`INSERT INTO friends (user_id, friend_id) VALUES (?, ?)`, user1.String(), user2.String())
	if err != nil {
		tx.Rollback()
		return err
	}

	_, err = tx.Exec(`INSERT INTO friends (user_id, friend_id) VALUES (?, ?)`, user2.String(), user1.String())
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

func (s *Store) FriendCodeExists(code string) (bool, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE friend_code = ?`, code).Scan(&count)

	return count > 0, err
}

func (s *Store) FriendRequestExists(senderID, receiverID uuid.UUID) (bool, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM friend_requests WHERE sender_id = ? AND receiver_id = ?`, senderID.String(), receiverID.String()).Scan(&count)

	return count > 0, err
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

func (s *Store) DeleteSessionByID(userID uuid.UUID, sessionID uuid.UUID) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id = ? AND user_id = ?`, sessionID.String(), userID.String())

	return err
}

func (s *Store) DeleteFriendRequest(requestID uuid.UUID) error {
	_, err := s.db.Exec(`DELETE FROM friend_requests WHERE id = ?`, requestID.String())

	return err
}

func (s *Store) CancelFriendRequest(senderID, receiverID uuid.UUID) error {
	_, err := s.db.Exec(`DELETE FROM friend_requests WHERE sender_id = ? AND receiver_id = ? AND status = 'pending'`,
		senderID.String(), receiverID.String())

	return err
}

func (s *Store) BlockUser(blockerID, blockedID uuid.UUID) error {
	_, err := s.db.Exec(`INSERT IGNORE INTO blocked_users (blocker_id, blocked_id) VALUES (?, ?)`,
		blockerID.String(), blockedID.String())

	return err
}

func (s *Store) UnblockUser(blockerID, blockedID uuid.UUID) error {
	_, err := s.db.Exec(`DELETE FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?`,
		blockerID.String(), blockedID.String())

	return err
}

func (s *Store) IsBlocked(userA, userB uuid.UUID) (bool, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM blocked_users
	WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)`,
		userA.String(), userB.String(), userB.String(), userA.String()).Scan(&count)

	return count > 0, err
}

func scanRowIntoUser(rows *sql.Rows) (*types.User, error) {
	var user types.User
	var profilePic, bio sql.NullString

	err := rows.Scan(
		&user.ID,
		&user.Username,
		&user.FriendCode,
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
