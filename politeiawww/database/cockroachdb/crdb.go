package cockroachdb

import (
	"sync"

	"github.com/badoux/checkmail"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

// DB implements the database interface
type DB struct {
	sync.RWMutex
	*gorm.DB
	Shutdown bool // backend is shutdown
}

// New creates a new cockroachdb instance
func New(host string) (*DB, error) {
	log.Tracef("cockroachdb New: %v", host)

	db, err := gorm.Open("postgres", host)
	if err != nil {
		return nil, err
	}
	crdb := &DB{DB: db}

	db.AutoMigrate(&database.User{})

	return crdb, nil
}

// UserGet returns a user record if found in the database.
func (crdb *DB) UserGet(email string) (*database.User, error) {
	crdb.RLock()
	defer crdb.RUnlock()
	if crdb.Shutdown {
		return nil, database.ErrShutdown
	}

	var user database.User
	if err := crdb.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, errToDatabaseError(err)
	}
	return &user, nil
}

// UserUpdate updates a user record
func (crdb *DB) UserUpdate(user *database.User) error {
	crdb.RLock()
	defer crdb.RUnlock()
	if crdb.Shutdown {
		return database.ErrShutdown
	}

	if err := crdb.Model(user).Where("id = ?", user.ID).First(user).Update(*user).Error; err != nil {
		return errToDatabaseError(err)
	}
	return nil
}

// UserNew stores a new user record
func (crdb *DB) UserNew(user *database.User) error {
	crdb.RLock()
	defer crdb.RUnlock()
	if crdb.Shutdown {
		return database.ErrShutdown
	}

	if err := checkmail.ValidateFormat(user.Email); err != nil {
		return database.ErrInvalidEmail
	}

	var count int
	if err := crdb.Model(user).Where("email = ?", user.Email).Count(&count).Error; err != nil {
		return err
	}

	if count > 0 {
		return database.ErrUserExists
	}

	if err := crdb.Create(user).Error; err != nil {
		return errToDatabaseError(err)
	}
	return nil
}

// Close shuts down the database
func (crdb *DB) Close() error {
	crdb.Lock()
	defer crdb.Unlock()
	crdb.Shutdown = true

	return crdb.DB.Close()
}

// errToDecredError (helper function) converts a gorm error to a decred error
func errToDatabaseError(err error) error {
	switch err {
	case gorm.ErrRecordNotFound:
		return database.ErrUserNotFound
	default:
		return err
	}
}
