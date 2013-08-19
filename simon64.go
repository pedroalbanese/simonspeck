package simon

const (
	roundsSimon64_96  = 42
	roundsSimon64_128 = 44
)

func leftRotate32(n uint32, shift uint) uint32 {
	return (n << shift) | (n >> (32 - shift))
}

func rightRotate32(n uint32, shift uint) uint32 {
	return leftRotate32(n, 32-shift)
}

// Use NewSimon64 below to expand a Simon64 key. Simon64Cipher
// implements the cipher.Block interface.
type Simon64Cipher struct {
	k      []uint32
	rounds int // 42 for 96-bit key, 44 for 128-bit
}

func littleEndianBytesToUInt32(b []byte) uint32 {
	return uint32(b[0]) | (uint32(b[1]) << 8) | (uint32(b[2]) << 16) | (uint32(b[3]) << 24)
}

func storeLittleEndianUInt32(dst []byte, n uint32) {
	dst[0] = byte(n)
	dst[1] = byte(n >> 8)
	dst[2] = byte(n >> 16)
	dst[3] = byte(n >> 24)
}

// NewSimon64 creates and returns a new Simon64Cipher. It accepts
// either a 96-bit key (for Simon64/96) or a 128-bit key (for
// Simon64/128). See the documentation on Simon32 or the test suite
// for our endianness convention.
func NewSimon64(key []byte) *Simon64Cipher {
	cipher := new(Simon64Cipher)
	var keyWords int
	var z uint64

	switch len(key) {
	case 12:
		keyWords = 3
		z = zSeq2
		cipher.rounds = roundsSimon64_96
	case 16:
		keyWords = 4
		z = zSeq3
		cipher.rounds = roundsSimon64_128
	default:
		panic("NewSimon64() requires either a 96- or 128-bit key")
	}
	cipher.k = make([]uint32, cipher.rounds)
	for i := 0; i < keyWords; i++ {
		cipher.k[i] = littleEndianBytesToUInt32(key[4*i : 4*i+4])
	}
	for i := keyWords; i < cipher.rounds; i++ {
		tmp := rightRotate32(cipher.k[i-1], 3)
		if keyWords == 4 {
			tmp ^= cipher.k[i-3]
		}
		tmp ^= rightRotate32(tmp, 1)
		lfsrBit := (z >> uint((i-keyWords)%62)) & 1
		cipher.k[i] = ^cipher.k[i-keyWords] ^ tmp ^ uint32(lfsrBit) ^ 3
	}
	return cipher
}

// Simon64 has a 64-bit block length.
func (cipher *Simon64Cipher) BlockSize() int {
	return 8
}

func simonScramble32(x uint32) uint32 {
	return (leftRotate32(x, 1) & leftRotate32(x, 8)) ^ leftRotate32(x, 2)
}

// Encrypt encrypts the first block in src into dst.
// Dst and src may point at the same memory. See crypto/cipher.
func (cipher *Simon64Cipher) Encrypt(dst, src []byte) {
	y := littleEndianBytesToUInt32(src[0:4])
	x := littleEndianBytesToUInt32(src[4:8])
	for i := 0; i < cipher.rounds; i += 2 {
		y ^= simonScramble32(x) ^ cipher.k[i]
		x ^= simonScramble32(y) ^ cipher.k[i+1]
	}
	storeLittleEndianUInt32(dst[0:4], y)
	storeLittleEndianUInt32(dst[4:8], x)
}

// Decrypt decrypts the first block in src into dst.
// Dst and src may point at the same memory. See crypto/cipher.
func (cipher *Simon64Cipher) Decrypt(dst, src []byte) {
	y := littleEndianBytesToUInt32(src[0:4])
	x := littleEndianBytesToUInt32(src[4:8])
	for i := cipher.rounds - 1; i > 0; i -= 2 {
		x ^= simonScramble32(y) ^ cipher.k[i]
		y ^= simonScramble32(x) ^ cipher.k[i-1]
	}
	storeLittleEndianUInt32(dst[0:4], y)
	storeLittleEndianUInt32(dst[4:8], x)
}
