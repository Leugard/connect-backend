package websocket

import (
	"log"
	"net/http"

	"github.com/Leugard/connect-backend/middleware"
	"github.com/Leugard/connect-backend/types"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

type Handler struct {
	Store   types.UserStore
	Manager *Manager
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func (h *Handler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("websocket upgrade error:", err.Error())
		return
	}

	userID := r.Context().Value(middleware.UserIDKey).(string)
	user, _ := uuid.Parse(userID)
	h.Manager.Add(user, conn)

	defer func() {
		log.Printf("[WS][%s] Disconnected\n", userID)
		h.Manager.Remove(user, conn)
		conn.Close()
	}()

	for {
		var msg struct {
			Type           string `json:"type"`
			ReceiverID     string `json:"receiverId"`
			Content        string `json:"content"`
			ImageURL       string `json:"imageUrl"`
			ConversationID string `json:"conversationId"`
			IsTyping       bool   `json:"isTyping"`
		}

		if err := conn.ReadJSON(&msg); err != nil {
			log.Printf("[WS][%s] Read error: %v\n", userID, err)
			break
		}

		log.Printf("[WS][%s] Received: %+v\n", userID, msg)

		switch msg.Type {
		case "message":
			h.handleSendMessage(user, struct {
				ReceiverID string
				Content    string
				ImageURL   string
			}{
				ReceiverID: msg.ReceiverID,
				Content:    msg.Content,
				ImageURL:   msg.ImageURL,
			})
		case "read":
			h.handleMarkRead(user, msg.ConversationID)
		case "typing":
			h.handleTyping(user, msg.ReceiverID, msg.IsTyping)
		}
	}
}

func (h *Handler) handleSendMessage(sender uuid.UUID, msg struct {
	ReceiverID string
	Content    string
	ImageURL   string
}) {
	receiverID, err := uuid.Parse(msg.ReceiverID)
	if err != nil {
		log.Println("[WS] Invalid receiver ID:", msg.ReceiverID)
		return
	}

	isFriend, err := h.Store.AreFriends(sender, receiverID)
	if err != nil || !isFriend {
		log.Println("[WS] Not friends or failed:", err)
		return
	}

	convoID, err := h.Store.GetOrCreateConversation(sender, receiverID)
	if err != nil {
		log.Println("[WS] GetOrCreateConversation failed:", err)
		return
	}

	message, err := h.Store.SendMessage(convoID, sender, msg.Content, msg.ImageURL)
	if err != nil {
		log.Println("[WS] SendMessage failed:", err)
		return
	}

	if h.Manager.IsOnline(receiverID) {
		h.Store.UpdateMessageStatus(message.ID, "delivered")
		message.Status = "delivered"
	} else {
		message.Status = "unread"
	}

	response := map[string]any{
		"type":           "message",
		"message":        message,
		"conversationId": convoID.String(),
	}

	h.Manager.Send(sender, response)
	h.Manager.Send(receiverID, response)

}

func (h *Handler) handleTyping(sender uuid.UUID, receiverID string, isTyping bool) {
	receiver, err := uuid.Parse(receiverID)
	if err != nil {
		return
	}

	if h.Manager.IsOnline(receiver) {
		h.Manager.Send(receiver, map[string]any{
			"type":     "typing",
			"userId":   sender.String(),
			"isTyping": isTyping,
		})
	}
}

func (h *Handler) handleMarkRead(userID uuid.UUID, convoID string) {
	convo, err := uuid.Parse(convoID)
	if err != nil {
		log.Println("[WS] invalid convo for read:", convoID)
		return
	}

	err = h.Store.MarkMessagesAsRead(convo, userID)
	if err != nil {
		log.Println("[WS] markmessageasread failed:", err)
	}
}
