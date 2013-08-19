package simon

const (
	roundsSimon128_128 = 68
	roundsSimon128_192 = 69
	roundsSimon128_256 = 72
)

func leftRotate64(n uint64, shift uint) uint64 {
	return (n << shift) | (n >> (64 - shift))
}

// Use NewSimon128 below to expand a Simon128 key. Simon128Cipher
// implements the cipher.Block interface.
type Simon128Cipher struct {
	k      []uint64
	rounds int
}

func littleEndianBytesToUInt64(b []byte) uint64 {
	r := uint64(0)
	for i := uint(0); i < 8; i++ {
		r |= uint64(b[i]) << (8 * i)
	}
	return r
}

func storeLittleEndianUInt64(dst []byte, n uint64) {
	for i := uint(0); i < 8; i++ {
		dst[i] = byte(n >> (8 * i))
	}
}

// NewSimon64 creates and returns a new Simon64Cipher. It accepts
// either a 96-bit key (for Simon64/96) or a 128-bit key (for
// Simon64/128). See the documentation on Simon32 or the test suite
// for our endianness convention.
func NewSimon128(key []byte) *Simon128Cipher {
	cipher := new(Simon128Cipher)
	var keyWords int
	var z uint64

	switch len(key) {
	case 16:
		keyWords = 2
		z = zSeq2
		cipher.rounds = roundsSimon128_128
	case 24:
		keyWords = 3
		z = zSeq3
		cipher.rounds = roundsSimon128_192
	case 32:
		keyWords = 4
		z = zSeq4
		cipher.rounds = roundsSimon128_256
	default:
		panic("NewSimon128() requires a 128-,  192- or 256-bit key")
	}
	cipher.k = make([]uint64, cipher.rounds)
	for i := 0; i < keyWords; i++ {
		cipher.k[keyWords-i-1] = littleEndianBytesToUInt64(key[8*i : 8*i+8])
	}
	for i := keyWords; i < cipher.rounds; i++ {
		tmp := leftRotate64(cipher.k[i-1], 61)
		if keyWords == 4 {
			tmp ^= cipher.k[i-3]
		}
		tmp ^= leftRotate64(tmp, 63)
		lfsrBit := (z >> uint((i-keyWords)%62)) & 1
		cipher.k[i] = ^cipher.k[i-keyWords] ^ tmp ^ uint64(lfsrBit) ^ 3
	}
	return cipher
}

// Simon128 has a 128-bit block length.
func (cipher *Simon128Cipher) BlockSize() int {
	return 16
}

func simonScramble64(x uint64) uint64 {
	return (leftRotate64(x, 1) & leftRotate64(x, 8)) ^ leftRotate64(x, 2)
}

// Encrypt encrypts the first block in src into dst.
// Dst and src may point at the same memory. See crypto/cipher.
func (cipher *Simon128Cipher) Encrypt(dst, src []byte) {
	x := littleEndianBytesToUInt64(src[0:8])
	y := littleEndianBytesToUInt64(src[8:16])
	for i := 0; i < cipher.rounds; i++ {
		x, y = y^simonScramble64(x)^cipher.k[i], x
	}
	storeLittleEndianUInt64(dst[0:8], x)
	storeLittleEndianUInt64(dst[8:16], y)
}

// Decrypt decrypts the first block in src into dst.
// Dst and src may point at the same memory. See crypto/cipher.
func (cipher *Simon128Cipher) Decrypt(dst, src []byte) {
	x := littleEndianBytesToUInt64(src[0:8])
	y := littleEndianBytesToUInt64(src[8:16])
	for i := cipher.rounds - 1; i >= 0; i-- {
		x, y = y, x^simonScramble64(y)^cipher.k[i]
	}
	storeLittleEndianUInt64(dst[0:8], x)
	storeLittleEndianUInt64(dst[8:16], y)
}
