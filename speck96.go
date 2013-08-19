package simonspeck

const (
	roundsSpeck96_96  = 28
	roundsSpeck96_144 = 29
)

// Use NewSpeck96 below to expand a Speck96 key. Speck96Cipher
// implements the cipher.Block interface.
type Speck96Cipher struct {
	k      []uint64
	rounds int
}

// NewSpeck96 creates and returns a new Speck96Cipher. It accepts a
// 96-bit key (for Speck96/96) or a 144-bit key (for Speck96/144). See
// the documentation on Simon32 or the test suite for our endianness
// convention.
func NewSpeck96(key []byte) *Speck96Cipher {
	cipher := new(Speck96Cipher)
	var keyWords int
	var auxKey []uint64

	switch len(key) {
	case 12:
		keyWords = 2
		cipher.rounds = roundsSpeck96_96
	case 18:
		keyWords = 3
		cipher.rounds = roundsSpeck96_144
	default:
		panic("NewSpeck96() requires a 96- or 144-bit key")
	}
	cipher.k = make([]uint64, cipher.rounds)
	auxKey = make([]uint64, keyWords+cipher.rounds-2)
	cipher.k[0] = littleEndianBytesToUInt48(key[0:6])
	for i := 0; i < keyWords-1; i++ {
		auxKey[i] = littleEndianBytesToUInt48(key[6*i+6 : 6*i+12])
	}
	for i := 0; i < cipher.rounds-1; i++ {
		auxKey[i+keyWords-1] = ((cipher.k[i] + rightRotate48(auxKey[i], 8)) ^ uint64(i)) & bitMask48
		cipher.k[i+1] = leftRotate48(cipher.k[i], 3) ^ auxKey[i+keyWords-1]
	}
	return cipher
}

// Speck96 has a 96-bit block length.
func (cipher *Speck96Cipher) BlockSize() int {
	return 12
}

// Encrypt encrypts the first block in src into dst.
// Dst and src may point at the same memory. See crypto/cipher.
func (cipher *Speck96Cipher) Encrypt(dst, src []byte) {
	y := littleEndianBytesToUInt48(src[0:6])
	x := littleEndianBytesToUInt48(src[6:12])
	for i := 0; i < cipher.rounds; i++ {
		x = ((rightRotate48(x, 8) + y) ^ cipher.k[i]) & bitMask48
		y = leftRotate48(y, 3) ^ x

	}
	storeLittleEndianUInt48(dst[0:6], y)
	storeLittleEndianUInt48(dst[6:12], x)
}

// Decrypt decrypts the first block in src into dst.
// Dst and src may point at the same memory. See crypto/cipher.
func (cipher *Speck96Cipher) Decrypt(dst, src []byte) {
	y := littleEndianBytesToUInt48(src[0:6])
	x := littleEndianBytesToUInt48(src[6:12])
	for i := cipher.rounds - 1; i >= 0; i-- {
		y = rightRotate48(y^x, 3)
		x = leftRotate48(((x^cipher.k[i])-y)&bitMask48, 8)

	}
	storeLittleEndianUInt48(dst[0:6], y)
	storeLittleEndianUInt48(dst[6:12], x)
}
