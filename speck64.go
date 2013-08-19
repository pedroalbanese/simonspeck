package simonspeck

const (
	roundsSpeck64_96  = 26
	roundsSpeck64_128 = 27
)

// Use NewSpeck64 below to expand a Simon64 key. Speck64Cipher
// implements the cipher.Block interface.
type Speck64Cipher struct {
	k      []uint32
	rounds int
}

// NewSpeck64 creates and returns a new Speck64Cipher. It accepts
// either a 96-bit key (for Speck64/96) or a 128-bit key (for
// Speck64/128). See the documentation on Simon32 or the test suite
// for our endianness convention.
func NewSpeck64(key []byte) *Speck64Cipher {
	cipher := new(Speck64Cipher)
	var keyWords int
	var auxKey []uint32

	switch len(key) {
	case 12:
		keyWords = 3
		cipher.rounds = roundsSpeck64_96
	case 16:
		keyWords = 4
		cipher.rounds = roundsSpeck64_128
	default:
		panic("NewSpeck64() requires either a 96- or 128-bit key")
	}
	cipher.k = make([]uint32, cipher.rounds)
	auxKey = make([]uint32, keyWords+cipher.rounds-2)
	cipher.k[0] = littleEndianBytesToUInt32(key[0:4])
	for i := 0; i < keyWords-1; i++ {
		auxKey[i] = littleEndianBytesToUInt32(key[4*i+4 : 4*i+8])
	}
	for i := 0; i < cipher.rounds-1; i++ {
		auxKey[i+keyWords-1] = (cipher.k[i] + rightRotate32(auxKey[i], 8)) ^ uint32(i)
		cipher.k[i+1] = leftRotate32(cipher.k[i], 3) ^ auxKey[i+keyWords-1]
	}
	return cipher
}

// Speck64 has a 64-bit block length.
func (cipher *Speck64Cipher) BlockSize() int {
	return 8
}

// Encrypt encrypts the first block in src into dst.
// Dst and src may point at the same memory. See crypto/cipher.
func (cipher *Speck64Cipher) Encrypt(dst, src []byte) {
	y := littleEndianBytesToUInt32(src[0:4])
	x := littleEndianBytesToUInt32(src[4:8])
	for i := 0; i < cipher.rounds; i++ {
		x = (rightRotate32(x, 8) + y) ^ cipher.k[i]
		y = leftRotate32(y, 3) ^ x

	}
	storeLittleEndianUInt32(dst[0:4], y)
	storeLittleEndianUInt32(dst[4:8], x)
}

// Decrypt decrypts the first block in src into dst.
// Dst and src may point at the same memory. See crypto/cipher.
func (cipher *Speck64Cipher) Decrypt(dst, src []byte) {
	y := littleEndianBytesToUInt32(src[0:4])
	x := littleEndianBytesToUInt32(src[4:8])
	for i := cipher.rounds - 1; i >= 0; i-- {
		y = rightRotate32(y^x, 3)
		x = leftRotate32((x^cipher.k[i])-y, 8)

	}
	storeLittleEndianUInt32(dst[0:4], y)
	storeLittleEndianUInt32(dst[4:8], x)
}
