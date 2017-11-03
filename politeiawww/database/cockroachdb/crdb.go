package cockroachdb

import (
	"github.com/badoux/checkmail"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

// cockroachdb implements the database interface.
type DB struct {
	*gorm.DB
}

// New creates a new cockroachdb instance
func New(addr string) (*DB, error) {
	db, err := gorm.Open("postgres", addr)
	if err != nil {
		return nil, err
	}
	crdb := &DB{db}

	db.AutoMigrate(&database.User{})

	return crdb, nil
}

// UserGet returns a user record if found in the database.
func (crdb *DB) UserGet(email string) (*database.User, error) {
	var user database.User
	var query *gorm.DB
	if query = crdb.Find(&user, user.Email); query.Error != nil {
		return nil, query.Error
	}

	var count int
	if err := query.Count(&count).Error; err != nil {
		return nil, err
	} else if count == 0 {
		return nil, database.ErrUserNotFound
	}

	return &user, nil
}

// UserUpdate updates a user record
func (crdb *DB) UserUpdate(user *database.User) error {
	var query *gorm.DB
	if query = crdb.Model(user).Where("email = ?", user.Email); query.Error != nil {
		return query.Error
	}

	var count int
	if err := query.Count(&count).Error; err != nil {
		return err
	} else if count == 0 {
		return database.ErrUserNotFound
	}

	return query.Update(*user).Error
}

// UserNew stores a new user record
func (crdb *DB) UserNew(user *database.User) error {
	if err := checkmail.ValidateFormat(user.Email); err != nil {
		return database.ErrInvalidEmail
	}

	var query *gorm.DB
	if query = crdb.Find(&user, user.Email); query.Error != nil {
		return query.Error
	}

	var count int
	if err := query.Count(&count).Error; err != nil {
		return err
	} else if count > 0 {
		return database.ErrUserExists
	}

	return crdb.Create(user).Error
}

// Close shuts down the database
func (crdb *DB) Close() error {
	return crdb.DB.Close()
}
