package crypto

import (
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/libp2p/go-libp2p/core/crypto"
)

// RingSignature represents a linkable ring signature (LSAG)
type RingSignature struct {
	C0        []byte   // c_0
	R         [][]byte // r_0, r_1, ..., r_{d-1}
	KeyImageX []byte
	KeyImageY []byte
}

// PubKeyPoint represents a public key point on the P-256 curve
type PubKeyPoint struct {
	X *big.Int
	Y *big.Int
}

// DeriveZKPKeypair derives a deterministic P-256 private key and public key point from a libp2p private key.
func DeriveZKPKeypair(priv crypto.PrivKey) (k *big.Int, x *big.Int, y *big.Int, err error) {
	raw, err := priv.Raw()
	if err != nil {
		return nil, nil, nil, err
	}

	h := sha256.Sum256(raw)
	curve := elliptic.P256()
	n := curve.Params().N

	k = new(big.Int).SetBytes(h[:])
	k.Mod(k, n)
	if k.Sign() == 0 {
		k.SetInt64(1)
	}

	x, y = curve.ScalarBaseMult(k.Bytes())
	return k, x, y, nil
}

// HashToPoint hashes arbitrary data to a valid point on the P-256 curve using the hash-and-try method.
func HashToPoint(curve elliptic.Curve, data []byte) (x, y *big.Int) {
	p := curve.Params().P
	b := curve.Params().B
	three := big.NewInt(3)

	h := sha256.Sum256(data)
	counter := 0
	for {
		hBuf := append(h[:], []byte(fmt.Sprintf("-%d", counter))...)
		xBytes := sha256.Sum256(hBuf)
		xVal := new(big.Int).SetBytes(xBytes[:])
		xVal.Mod(xVal, p)

		// Compute x^3 - 3x + b (mod p)
		x3 := new(big.Int).Mul(xVal, xVal)
		x3.Mul(x3, xVal)

		threeX := new(big.Int).Mul(three, xVal)

		y2 := new(big.Int).Sub(x3, threeX)
		y2.Add(y2, b)
		y2.Mod(y2, p)

		// Find sqrt(y2) mod p
		yVal := new(big.Int).ModSqrt(y2, p)
		if yVal != nil {
			if curve.IsOnCurve(xVal, yVal) {
				return xVal, yVal
			}
		}
		counter++
	}
}

// hashVal hashes the ring parameters, message, and ephemeral points to a scalar modulo n.
func hashVal(curve elliptic.Curve, ring []PubKeyPoint, imageX, imageY []byte, msg []byte, Lx, Ly, Rx, Ry *big.Int) *big.Int {
	h := sha256.New()
	for _, pub := range ring {
		h.Write(pub.X.Bytes())
		h.Write(pub.Y.Bytes())
	}
	h.Write(imageX)
	h.Write(imageY)
	h.Write(msg)
	if Lx != nil {
		h.Write(Lx.Bytes())
	}
	if Ly != nil {
		h.Write(Ly.Bytes())
	}
	if Rx != nil {
		h.Write(Rx.Bytes())
	}
	if Ry != nil {
		h.Write(Ry.Bytes())
	}

	sum := h.Sum(nil)
	n := curve.Params().N
	val := new(big.Int).SetBytes(sum)
	return val.Mod(val, n)
}

// GenerateRingSignature signs a message using a linkable ring signature (LSAG).
// s is the index of the signer's public key in the ring.
func GenerateRingSignature(msg []byte, ring []PubKeyPoint, s int, privKey *big.Int) (*RingSignature, error) {
	if s < 0 || s >= len(ring) {
		return nil, fmt.Errorf("invalid signer index")
	}

	curve := elliptic.P256()
	n := curve.Params().N

	// 1. Compute Hash-to-point of the signer's public key
	pubKey := ring[s]
	pubBytes := append(pubKey.X.Bytes(), pubKey.Y.Bytes()...)
	Hx, Hy := HashToPoint(curve, pubBytes)

	// 2. Key Image I = x * H(Y_s)
	Ix, Iy := curve.ScalarMult(Hx, Hy, privKey.Bytes())

	// 3. Choose random u
	uBytes := sha256.Sum256(append(privKey.Bytes(), msg...)) // deterministic random u for testing/robustness
	u := new(big.Int).SetBytes(uBytes[:])
	u.Mod(u, n)
	if u.Sign() == 0 {
		u.SetInt64(1)
	}

	// 4. Compute L_s = u * G, R_s = u * H(Y_s)
	Lx_s, Ly_s := curve.ScalarBaseMult(u.Bytes())
	Rx_s, Ry_s := curve.ScalarMult(Hx, Hy, u.Bytes())

	// Initialize c and r slices
	d := len(ring)
	for i := 0; i < d; i++ {
		if !curve.IsOnCurve(ring[i].X, ring[i].Y) {
			return nil, fmt.Errorf("ring contains invalid public key point at index %d", i)
		}
	}
	c := make([]*big.Int, d)
	r := make([]*big.Int, d)

	// Compute c_{s+1}
	cNext := hashVal(curve, ring, Ix.Bytes(), Iy.Bytes(), msg, Lx_s, Ly_s, Rx_s, Ry_s)

	// 5. Loop for i = s+1, ..., d-1, 0, ..., s-1
	for j := 1; j < d; j++ {
		i := (s + j) % d
		c[i] = cNext

		// Choose random r_i
		rBytes := sha256.Sum256(append(c[i].Bytes(), byte(i)))
		rVal := new(big.Int).SetBytes(rBytes[:])
		rVal.Mod(rVal, n)
		r[i] = rVal

		// Compute L_i = r_i * G + c_i * Y_i
		Lx1, Ly1 := curve.ScalarBaseMult(r[i].Bytes())
		Lx2, Ly2 := curve.ScalarMult(ring[i].X, ring[i].Y, c[i].Bytes())
		Lx, Ly := curve.Add(Lx1, Ly1, Lx2, Ly2)

		// Compute R_i = r_i * H(Y_i) + c_i * I
		YBytes := append(ring[i].X.Bytes(), ring[i].Y.Bytes()...)
		H_x, H_y := HashToPoint(curve, YBytes)
		Rx1, Ry1 := curve.ScalarMult(H_x, H_y, r[i].Bytes())
		Rx2, Ry2 := curve.ScalarMult(Ix, Iy, c[i].Bytes())
		Rx, Ry := curve.Add(Rx1, Ry1, Rx2, Ry2)

		cNext = hashVal(curve, ring, Ix.Bytes(), Iy.Bytes(), msg, Lx, Ly, Rx, Ry)
	}

	// 6. Close the ring: compute r_s = (u - c_s * x) mod n
	c[s] = cNext
	cx := new(big.Int).Mul(c[s], privKey)
	cx.Mod(cx, n)

	r_s := new(big.Int).Sub(u, cx)
	r_s.Mod(r_s, n)
	if r_s.Sign() < 0 {
		r_s.Add(r_s, n)
	}
	r[s] = r_s

	// Prepare signature bytes
	rBytes := make([][]byte, d)
	for i := 0; i < d; i++ {
		rBytes[i] = r[i].Bytes()
	}

	return &RingSignature{
		C0:        c[0].Bytes(),
		R:         rBytes,
		KeyImageX: Ix.Bytes(),
		KeyImageY: Iy.Bytes(),
	}, nil
}

// VerifyRingSignature verifies a linkable ring signature (LSAG).
func VerifyRingSignature(msg []byte, ring []PubKeyPoint, sig *RingSignature) bool {
	if sig == nil || len(ring) == 0 || len(sig.R) != len(ring) {
		return false
	}

	curve := elliptic.P256()
	n := curve.Params().N

	Ix := new(big.Int).SetBytes(sig.KeyImageX)
	Iy := new(big.Int).SetBytes(sig.KeyImageY)

	if !curve.IsOnCurve(Ix, Iy) {
		return false
	}

	d := len(ring)
	c := new(big.Int).SetBytes(sig.C0)
	c.Mod(c, n)

	for i := 0; i < d; i++ {
		if !curve.IsOnCurve(ring[i].X, ring[i].Y) {
			return false
		}
		r_i := new(big.Int).SetBytes(sig.R[i])
		r_i.Mod(r_i, n)

		// L_i = r_i * G + c_i * Y_i
		Lx1, Ly1 := curve.ScalarBaseMult(r_i.Bytes())
		Lx2, Ly2 := curve.ScalarMult(ring[i].X, ring[i].Y, c.Bytes())
		Lx, Ly := curve.Add(Lx1, Ly1, Lx2, Ly2)

		// R_i = r_i * H(Y_i) + c_i * I
		YBytes := append(ring[i].X.Bytes(), ring[i].Y.Bytes()...)
		H_x, H_y := HashToPoint(curve, YBytes)
		Rx1, Ry1 := curve.ScalarMult(H_x, H_y, r_i.Bytes())
		Rx2, Ry2 := curve.ScalarMult(Ix, Iy, c.Bytes())
		Rx, Ry := curve.Add(Rx1, Ry1, Rx2, Ry2)

		c = hashVal(curve, ring, sig.KeyImageX, sig.KeyImageY, msg, Lx, Ly, Rx, Ry)
	}

	c0 := new(big.Int).SetBytes(sig.C0)
	c0.Mod(c0, n)
	return c.Cmp(c0) == 0
}
