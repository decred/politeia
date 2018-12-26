package cockroachdb

type Version struct {
	Version uint32 `gorm:"primary_key"` // Cache version
	Time    int64  `gorm:"not null"`    // Time of record creation
}

type File struct {
	Key       uint   `gorm:"primary_key"`      // Primary key
	RecordKey string `gorm:"not null"`         // Record foreign key
	Name      string `gorm:"not null"`         // Basename of the file
	MIME      string `gorm:"not null"`         // MIME type
	Digest    string `gorm:"size:64;not null"` // SHA256 of decoded Payload
	Payload   string `gorm:"not null"`         // base64 encoded file
}

type MetadataStream struct {
	Key       uint   `gorm:"primary_key"` // Primary key
	RecordKey string `gorm:"not null"`    // Record foreign key
	ID        uint64 `gorm:"not null"`    // Stream identity
	Payload   string `gorm:"not null"`    // String encoded metadata
}

type CensorshipRecord struct {
	Key       uint   `gorm:"primary_key"`       // Primary key
	Token     string `gorm:"size:64;not null"`  // Censorship token
	Merkle    string `gorm:"size:64;not null"`  // Merkle root of all files in record
	Signature string `gorm:"size:128;not null"` // Server signature of merkle+token
}

type Record struct {
	Key                 string `gorm:"primary_key"` // Primary key (token+version)
	CensorshipRecordKey uint   `gorm:"not null"`    // Censorship record foreign key
	Version             string `gorm:"not null"`    // Version of files
	Status              int    `gorm:"not null"`    // Current status
	Timestamp           int64  `gorm:"not null"`    // Last updated

	CensorshipRecord CensorshipRecord `gorm:"foreignkey:CensorshipRecordKey"` // Censorship record
	Metadata         []MetadataStream `gorm:"foreignkey:RecordKey"`           // User provided metadata
	Files            []File           `gorm:"foreignkey:RecordKey"`           // User provided files
}
