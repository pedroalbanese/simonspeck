package simonspeck

const (
	roundsSpeck48_72 = 22
	roundsSpeck48_96 = 23
)

// Use NewSpeck48 below to expand a Speck48 key. Speck48Cipher
// implements the cipher.Block interface.
type Speck48Cipher struct {
	k      []uint32
	rounds int
}

// NewSpeck48 creates and returns a new Speck48Cipher. It accepts
// either a 72-bit key (for Speck48/72) or a 96-bit key (for
// Speck48/96). See the documentation on Simon32 or the test suite
// for our endianness convention.
func NewSpeck48(key []byte) *Speck48Cipher {
	cipher := new(Speck48Cipher)
	var keyWords int
	var auxKey []uint32

	switch len(key) {
	case 9:
		keyWords = 3
		cipher.rounds = roundsSpeck48_72
	case 12:
		keyWords = 4
		cipher.rounds = roundsSpeck48_96
	default:
		panic("NewSpeck48() requires either a 72- or 96-bit key")
	}
	cipher.k = make([]uint32, cipher.rounds)
	auxKey = make([]uint32, keyWords+cipher.rounds-2)
	cipher.k[0] = littleEndianBytesToUInt24(key[0:3])
	for i := 0; i < keyWords-1; i++ {
		auxKey[i] = littleEndianBytesToUInt24(key[3*i+3 : 3*i+6])
	}
	for i := 0; i < cipher.rounds-1; i++ {
		auxKey[i+keyWords-1] = ((cipher.k[i] + rightRotate24(auxKey[i], 8)) ^ uint32(i)) & bitMask24
		cipher.k[i+1] = leftRotate24(cipher.k[i], 3) ^ auxKey[i+keyWords-1]
	}
	return cipher
}

// Speck48 has a 48-bit block length.
func (cipher *Speck48Cipher) BlockSize() int {
	return 6
}

// Encrypt encrypts the first block in src into dst.
// Dst and src may point at the same memory. See crypto/cipher.
func (cipher *Speck48Cipher) Encrypt(dst, src []byte) {
	y := littleEndianBytesToUInt24(src[0:3])
	x := littleEndianBytesToUInt24(src[3:6])
	for i := 0; i < cipher.rounds; i++ {
		x = ((rightRotate24(x, 8) + y) ^ cipher.k[i]) & bitMask24
		y = leftRotate24(y, 3) ^ x

	}
	storeLittleEndianUInt24(dst[0:3], y)
	storeLittleEndianUInt24(dst[3:6], x)
}

// Decrypt decrypts the first block in src into dst.
// Dst and src may point at the same memory. See crypto/cipher.
func (cipher *Speck48Cipher) Decrypt(dst, src []byte) {
	y := littleEndianBytesToUInt24(src[0:3])
	x := littleEndianBytesToUInt24(src[3:6])
	for i := cipher.rounds - 1; i >= 0; i-- {
		y = rightRotate24(y^x, 3)
		x = leftRotate24(((x^cipher.k[i])-y)&bitMask24, 8)

	}
	storeLittleEndianUInt24(dst[0:3], y)
	storeLittleEndianUInt24(dst[3:6], x)
}
