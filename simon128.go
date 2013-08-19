package simonspeck

const (
	roundsSimon128_128 = 68
	roundsSimon128_192 = 69
	roundsSimon128_256 = 72
)

// Use NewSimon128 below to expand a Simon128 key. Simon128Cipher
// implements the cipher.Block interface.
type Simon128Cipher struct {
	k      []uint64
	rounds int
}

// NewSimon128 creates and returns a new Simon128Cipher. It accepts a
// 128-bit key (for Simon128/128), a 196-bit key (for Simon128/196),
// or a 256-bit key (for Simon128/256). See the documentation on
// Simon32 or the test suite for our endianness convention.
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
		cipher.k[i] = littleEndianBytesToUInt64(key[8*i : 8*i+8])
	}
	for i := keyWords; i < cipher.rounds; i++ {
		tmp := rightRotate64(cipher.k[i-1], 3)
		if keyWords == 4 {
			tmp ^= cipher.k[i-3]
		}
		tmp ^= rightRotate64(tmp, 1)
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
	y := littleEndianBytesToUInt64(src[0:8])
	x := littleEndianBytesToUInt64(src[8:16])
	for i := 0; i < cipher.rounds; i++ {
		x, y = y^simonScramble64(x)^cipher.k[i], x
	}
	storeLittleEndianUInt64(dst[0:8], y)
	storeLittleEndianUInt64(dst[8:16], x)
}

// Decrypt decrypts the first block in src into dst.
// Dst and src may point at the same memory. See crypto/cipher.
func (cipher *Simon128Cipher) Decrypt(dst, src []byte) {
	y := littleEndianBytesToUInt64(src[0:8])
	x := littleEndianBytesToUInt64(src[8:16])
	for i := cipher.rounds - 1; i >= 0; i-- {
		x, y = y, x^simonScramble64(y)^cipher.k[i]
	}
	storeLittleEndianUInt64(dst[0:8], y)
	storeLittleEndianUInt64(dst[8:16], x)
}
