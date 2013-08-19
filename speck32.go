package simonspeck

const (
	roundsSpeck32_64 = 22
)

// Use NewSpeck32 below to expand a Speck32 key. Speck32Cipher
// implements the cipher.Block interface.
type Speck32Cipher struct {
	k      []uint16
	rounds int
}

// NewSpeck32 creates and returns a new Speck32Cipher. It accepts
// either a 96-bit key (for Speck32/96) or a 128-bit key (for
// Speck32/128). See the documentation on Simon32 or the test suite
// for our endianness convention.
func NewSpeck32(key []byte) *Speck32Cipher {
	cipher := new(Speck32Cipher)
	var keyWords int
	var auxKey []uint16

	if len(key) != 8 {
		panic("NewSpeck32() requires a 64-bit key")
	}
	keyWords = 4
	cipher.rounds = roundsSpeck32_64
	cipher.k = make([]uint16, cipher.rounds)
	auxKey = make([]uint16, keyWords+cipher.rounds-2)
	cipher.k[0] = littleEndianBytesToUInt16(key[0:2])
	for i := 0; i < keyWords-1; i++ {
		auxKey[i] = littleEndianBytesToUInt16(key[2*i+2 : 2*i+4])
	}
	for i := 0; i < cipher.rounds-1; i++ {
		auxKey[i+keyWords-1] = (cipher.k[i] + rightRotate16(auxKey[i], 7)) ^ uint16(i)
		cipher.k[i+1] = leftRotate16(cipher.k[i], 2) ^ auxKey[i+keyWords-1]
	}
	return cipher
}

// Speck32 has a 32-bit block length.
func (cipher *Speck32Cipher) BlockSize() int {
	return 4
}

// Encrypt encrypts the first block in src into dst.
// Dst and src may point at the same memory. See crypto/cipher.
func (cipher *Speck32Cipher) Encrypt(dst, src []byte) {
	y := littleEndianBytesToUInt16(src[0:2])
	x := littleEndianBytesToUInt16(src[2:4])
	for i := 0; i < cipher.rounds; i++ {
		x = (rightRotate16(x, 7) + y) ^ cipher.k[i]
		y = leftRotate16(y, 2) ^ x

	}
	storeLittleEndianUInt16(dst[0:2], y)
	storeLittleEndianUInt16(dst[2:4], x)
}

// Decrypt decrypts the first block in src into dst.
// Dst and src may point at the same memory. See crypto/cipher.
func (cipher *Speck32Cipher) Decrypt(dst, src []byte) {
	y := littleEndianBytesToUInt16(src[0:2])
	x := littleEndianBytesToUInt16(src[2:4])
	for i := cipher.rounds - 1; i >= 0; i-- {
		y = rightRotate16(y^x, 2)
		x = leftRotate16((x^cipher.k[i])-y, 7)

	}
	storeLittleEndianUInt16(dst[0:2], y)
	storeLittleEndianUInt16(dst[2:4], x)
}
