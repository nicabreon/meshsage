package protocol

// MessageEnvelope adalah struktur dasar untuk semua data yang mengalir antar node.
// Kita menggunakan tag JSON satu huruf agar ukuran paket tetap sangat kecil.
type MessageEnvelope struct {
	ID        string `json:"i"`          // Unique Message ID
	Type      string `json:"t"`          // "text", "status", "file", "group"
	Content   string `json:"c,omitempty"` // Isi pesan atau payload
	Timestamp int64  `json:"n"`          // Unix timestamp (nanoseconds)
	Status    string `json:"s,omitempty"` // "delivered", "read"
	RefID     string `json:"r,omitempty"` // Merujuk ke Message ID lain (untuk ACK/Reply)
	Sender    string `json:"u,omitempty"` // Alias pengirim (opsional)
	Signature string `json:"g,omitempty"` // Digital Signature (Ed25519)
}

const (
	MsgTypeText   = "text"
	MsgTypeStatus = "status"
	MsgTypeFile   = "file"
	MsgTypeGroup  = "group"

	StatusDelivered = "delivered"
	StatusRead      = "read"
)
