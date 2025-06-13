package main

import (
	"database/sql"
	"log"
	"time"

	"github.com/Leugard/connect-backend/api"
	"github.com/Leugard/connect-backend/config"
	"github.com/Leugard/connect-backend/db"
	"github.com/Leugard/connect-backend/service/user"
	"github.com/Leugard/connect-backend/types"
	"github.com/go-sql-driver/mysql"
)

func cleanup(store types.UserStore) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			count, err := store.CleanupExpiredStories()
			if err != nil {
				log.Println("[cleanup] failed to delete expired status", err)
			} else if count > 0 {
				log.Printf("[cleanup] deleted %d expired stories\n", count)
			}
		}
	}
}

func main() {

	dbConn, err := db.NewMySQLStorage(mysql.Config{
		User:                 config.Envs.DBUser,
		Passwd:               config.Envs.DBPassword,
		Addr:                 config.Envs.DBAddress,
		DBName:               config.Envs.DBName,
		Net:                  "tcp",
		AllowNativePasswords: true,
		ParseTime:            true,
	})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	s := user.NewStore(dbConn)

	go cleanup(s)

	initStorage(dbConn)

	server := api.NewAPIServer(":8080", dbConn)
	if err := server.Run(); err != nil {
		log.Fatal(err)
	}

}

func initStorage(db *sql.DB) {
	err := db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("DB: Succesfully Conntected!")
}
