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

func (s *Store) GetBlockedUsers(userID uuid.UUID) ([]types.User, error) {
	rows, err := s.db.Query(`SELECT u.id, u.username, u.email, u.profile_pic, u.friend_code
	FROM blocked_users b JOIN users u ON b.blocked_id = u.id WHERE b.blocker_id = ?`, userID.String())
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

func (s *Store) GetMessagesByConversation(convoID uuid.UUID) ([]types.Message, error) {
	rows, err := s.db.Query(`SELECT id, sender_id, content, image_url, created_at
	FROM messages WHERE conversation_id = ? ORDER by created_at ASC`, convoID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []types.Message
	for rows.Next() {
		var m types.Message

		err := rows.Scan(&m.ID, &m.SenderID, &m.Content, &m.ImageURL, &m.CreatedAt)
		if err != nil {
			return nil, err
		}
		m.ConversationID = convoID
		messages = append(messages, m)
	}

	return messages, nil
}

func (s *Store) GetUserConversations(userID uuid.UUID) ([]types.ConversationPreview, error) {
	rows, err := s.db.Query(`SELECT 
	c.id,
	u.id,
	u.username,
	u.profile_pic,
	m.content,
	m.image_url,
	m.created_at FROM conversations c JOIN conversation_participants cp1 ON c.id = cp1.conversation_id
	JOIN conversation_participants cp2 ON c.id = cp2.conversation_id AND cp2.user_id != ?
	JOIN users u ON cp2.user_id = u.id LEFT JOIN messages m ON c.id = m.conversation_id
	WHERE cp1.user_id = ? AND m.created_at = (SELECT MAX(created_at) FROM messages WHERE conversation_id = c.id)
	ORDER BY m.created_at DESC`, userID.String(), userID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var previews []types.ConversationPreview
	for rows.Next() {
		var p types.ConversationPreview

		err := rows.Scan(
			&p.ConversationID,
			&p.FriendID,
			&p.FriendUsername,
			&p.FriendProfilePic,
			&p.LastContent,
			&p.LastImageUrl,
			&p.LastMessageAt,
		)
		if err != nil {
			return nil, err
		}
		previews = append(previews, p)
	}

	return previews, nil
}

func (s *Store) GetOrCreateConversation(user1, user2 uuid.UUID) (uuid.UUID, error) {
	row := s.db.QueryRow(`SELECT cp1.conversation_id
	FROM conversation_participants cp1
	JOIN conversation_participants cp2
	ON cp1.conversation_id = cp2.conversation_id
	WHERE cp1.user_id = ? AND cp2.user_id = ?`, user1.String(), user2.String())

	var convoID string
	err := row.Scan(&convoID)
	if err == sql.ErrNoRows {
		newID := uuid.New().String()
		_, err = s.db.Exec(`INSERT INTO conversations (id) VALUES (?)`, newID)
		if err != nil {
			return uuid.Nil, err
		}

		_, err := s.db.Exec(`INSERT INTO conversation_participants (conversation_id, user_id) VALUES (?, ?), (?, ?)`,
			newID, user1.String(), newID, user2.String())
		if err != nil {
			return uuid.Nil, err
		}
		return uuid.MustParse(newID), nil
	} else if err != nil {
		return uuid.Nil, err
	}

	return uuid.MustParse(convoID), nil
}

func (s *Store) GetStories(userID uuid.UUID) ([]types.Story, error) {
	rows, err := s.db.Query(`SELECT s.id, s.user_id, s.media_url, s.caption, s.created_at, s.expires_at
	FROM stories s JOIN friends f ON f.friend_id = s.user_id WHERE f.user_id = ? AND s.expires_at > NOW()
	ORDER BY s.created_at DESC`, userID.String())
	if err != nil {
		return nil, err

	}

	var stories []types.Story
	for rows.Next() {
		var s types.Story
		var uid string
		log.Printf("here")

		err := rows.Scan(&s.ID, &uid, &s.MediaURL, &s.Caption, &s.CreatedAt, &s.ExpiresAt)
		if err != nil {
			return nil, err
		}
		s.UserID, _ = uuid.Parse(uid)
		stories = append(stories, s)
	}

	return stories, nil
}

func (s *Store) GetStoryViewers(storyId, ownerID uuid.UUID) ([]types.StoryViewer, error) {
	var exists int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM stories WHERE id = ? AND user_id = ?`, storyId.String(), ownerID.String()).Scan(&exists)
	if err != nil {
		return nil, err
	}

	if exists == 0 {
		return nil, fmt.Errorf("not authorized to view story viewers")
	}

	rows, err := s.db.Query(`SELECT u.id, u.username, u.profile_pic, sv.viewed_at
	FROM story_views sv JOIN users u ON sv.viewer_id = u.id WHERE sv.story_id = ?
	ORDER BY sv.viewed_at DESC`, storyId.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var viewers []types.StoryViewer
	for rows.Next() {
		var v types.StoryViewer
		var uid string

		err := rows.Scan(&uid, &v.Username, &v.ProfilePic, &v.ViewedAt)
		if err != nil {
			return nil, err
		}

		v.ID, _ = uuid.Parse(uid)
		viewers = append(viewers, v)
	}

	return viewers, nil
}

func (s *Store) GetOtherParticipant(convoID, senderID uuid.UUID) (uuid.UUID, error) {
	var otherID string
	err := s.db.QueryRow(`SELECT user_id FROM conversation_participants 
	WHERE conversation_id = ? AND user_id != ?`, convoID.String(), senderID.String()).Scan(&otherID)
	if err != nil {
		return uuid.Nil, err
	}

	return uuid.Parse(otherID)
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

func (s *Store) CreateStory(story types.Story) error {
	_, err := s.db.Exec(`INSERT INTO stories (id, user_id, media_url, caption, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		story.ID.String(), story.UserID.String(), story.MediaURL, story.Caption, story.CreatedAt, story.ExpiresAt)

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

func (s *Store) UpdateMessageStatus(messageID uuid.UUID, status string) error {
	_, err := s.db.Exec(`UPDATE messages SET status = ? WHERE id = ?`, status, messageID.String())

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

func (s *Store) SaveRefreshToken(rt types.RefreshToken) error {
	_, err := s.db.Exec(`INSERT INTO refresh_tokens (id,user_id,token,expires_at) VALUES (?,?,?,?)`, rt.ID, rt.UserID, rt.Token, rt.ExpiresAt)

	return err
}

func (s *Store) SendMessage(convoID, senderID uuid.UUID, content, imageURL string) (types.Message, error) {
	id := uuid.New()
	createdAt := time.Now()

	message := types.Message{
		ID:             id,
		ConversationID: convoID,
		SenderID:       senderID,
		Content:        content,
		ImageURL:       imageURL,
		Status:         "unread",
		CreatedAt:      createdAt,
	}

	_, err := s.db.Exec(`INSERT INTO messages (id, conversation_id, sender_id, content, image_url, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		message.ID.String(), message.ConversationID.String(), message.SenderID.String(),
		message.Content, message.ImageURL, message.Status, message.CreatedAt)

	return message, err
}

func (s *Store) AreFriends(user1, user2 uuid.UUID) (bool, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM friends WHERE user_id = ? AND friend_id = ?`, user1.String(), user2.String()).Scan(&count)

	return count > 0, err
}

func (s *Store) IsParticipant(userID, convoID uuid.UUID) (bool, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM conversation_participants
	WHERE conversation_id = ? AND user_id = ?`, convoID.String(), userID.String()).Scan(&count)

	return count > 0, err
}

func (s *Store) MarkStoryViewed(storyID, viewerID uuid.UUID) error {
	_, err := s.db.Exec(`INSERT IGNORE INTO story_views (story_id, viewer_id) VALUES (?, ?)`, storyID.String(), viewerID.String())

	return err
}

func (s *Store) MarkMessagesAsRead(conversationID, readerID uuid.UUID) error {
	_, err := s.db.Exec(`UPDATE messages SET status = 'read' 
	WHERE conversation_id = ? AND sender_id != ? AND status != 'read'`, conversationID.String(), readerID.String())

	return err
}

func (s *Store) CleanupExpiredStories() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM stories WHERE expires_at < NOW()`)
	if err != nil {
		return 0, err
	}

	return res.RowsAffected()
}

func scanRowIntoUser(rows *sql.Rows) (*types.User, error) {
	var user types.User
	var profilePic, bio sql.NullString

	err := rows.Scan(
		&user.ID,
		&user.FriendCode,
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
