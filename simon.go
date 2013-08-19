// Package simon implements the Simon family of NSA block ciphers.
// It is a straightforward translation of the pseudocode in the paper [1] into golang.
// This implementation is not cryptographically secure.
//
// [1]: http://eprint.iacr.org/2013/404
package simon

const (
	roundsSimon32_64   = 32
	roundsSimon48_72   = 36
	roundsSimon48_96   = 36
	roundsSimon64_96   = 42
	roundsSimon64_128  = 44
	roundsSimon96_96   = 52
	roundsSimon96_144  = 54
	roundsSimon128_128 = 68
	roundsSimon128_192 = 69
	roundsSimon128_256 = 72
)

func leftRotate16(n uint16, shift uint) uint16 {
	return (n << shift) | (n >> (16 - shift))
}

func leftRotate32(n uint32, shift uint) uint32 {
	return (n << shift) | (n >> (32 - shift))
}

// Simon relies on five bit sequences generated by LFSRs. For fun
// I've implemented each as a shift register rather than bit constants.
// ShiftU corresponds to the matrix
// [0 1 0 0 0; 0 0 1 0 0; 1 0 0 1 0; 0 0 0 0 1; 1 0 0 0 1].
func ShiftU(reg uint) uint {
	s := reg << 1
	if s&32 != 0 {
		s ^= 37
	}
	s ^= reg & 1
	return s
}

// ShiftV corresponds to the matrix
// [0 1 1 0 0; 0 0 1 0 0; 1 0 0 1 0; 0 0 0 0 1; 1 0 0 0 0].
func ShiftV(reg uint) uint {
	s := reg << 1
	if s&32 != 0 {
		s ^= 37
	}
	s ^= (reg & 4) << 2
	return s
}

// ShiftW corresponds to the matrix
// [0 1 0 0 0; 0 0 1 0 0; 1 0 0 1 0; 0 0 0 0 1; 1 0 0 0 0].
func ShiftW(reg uint) uint {
	s := reg << 1
	if s&32 != 0 {
		s ^= 37
	}
	return s
}

// Use NewSimon32 below to expand a Simon32 key. Simon32Cipher
// implements the cipher.Block interface.
type Simon32Cipher struct {
	k [32]uint16
}

// NewSimon32 creates and returns a new Simon32Cipher. To compare with
// the test vectors in the NSA paper, give the key words in the same
// order as they appear in the paper, but as little-endian words. For
// example, the cipher with key "1918 1110 0908 0100" is generated by
// NewSimon32([]byte{0x18, 0x19, 0x10, 0x11, 0x08, 0x09, 0x00, 0x01}).
func NewSimon32(key []byte) *Simon32Cipher {
	cipher := new(Simon32Cipher)

	if len(key) != 8 {
		panic("NewSimon32 requires an 8-byte key")
	}
	for i := 0; i < 4; i++ {
		cipher.k[3-i] = uint16(key[2*i]) | (uint16(key[2*i+1]) << 8)
	}
	for i, reg := 4, uint(1); i < roundsSimon32_64; i++ {
		tmp := leftRotate16(cipher.k[i-1], 13)
		tmp ^= cipher.k[i-3]
		tmp ^= leftRotate16(tmp, 15)
		cipher.k[i] = ^cipher.k[i-4] ^ tmp ^ uint16(reg&1) ^ 3
		reg = ShiftU(reg)
	}
	return cipher
}

// Simon32 has a 32-bit block length. Note that this is in bytes, not words.
func (cipher *Simon32Cipher) BlockSize() int {
	return 4
}

// simonScramble16 is the only non-affine component of the Simon block cipher.
func simonScramble16(x uint16) uint16 {
	return (leftRotate16(x, 1) & leftRotate16(x, 8)) ^ leftRotate16(x, 2)
}

// Encrypt encrypts the first block in src into dst.
// Dst and src may point at the same memory. See crypto/cipher.
func (cipher *Simon32Cipher) Encrypt(dst, src []byte) {
	if len(src) < 4 || len(dst) < 4 {
		panic("Simon32Cipher.Encrypt() requires at least one block to encipher.")
	}
	x := uint16(src[0]) | (uint16(src[1]) << 8)
	y := uint16(src[2]) | (uint16(src[3]) << 8)
	for i := 0; i < roundsSimon32_64; i += 2 {
		y ^= simonScramble16(x) ^ cipher.k[i]
		x ^= simonScramble16(y) ^ cipher.k[i+1]
	}
	dst[0] = byte(x)
	dst[1] = byte(x >> 8)
	dst[2] = byte(y)
	dst[3] = byte(y >> 8)
}

// Decrypt decrypts the first block in src into dst.
// Dst and src may point at the same memory. See crypto/cipher.
func (cipher *Simon32Cipher) Decrypt(dst, src []byte) {
	if len(src) < 4 || len(dst) < 4 {
		panic("Simon32Cipher.Encrypt() requires at least one block to decipher.")
	}
	x := uint16(src[0]) | (uint16(src[1]) << 8)
	y := uint16(src[2]) | (uint16(src[3]) << 8)
	for i := roundsSimon32_64 - 1; i >= 0; i -= 2 {
		x ^= simonScramble16(y) ^ cipher.k[i]
		y ^= simonScramble16(x) ^ cipher.k[i-1]
	}
	dst[0] = byte(x)
	dst[1] = byte(x >> 8)
	dst[2] = byte(y)
	dst[3] = byte(y >> 8)
}

// Use NewSimon64 below to expand a Simon64 key. Simon64Cipher
// implements the cipher.Block interface.
type Simon64Cipher struct {
	k        []uint32
	rounds   int // 42 for 96-bit key, 44 for 128-bit
	keyWords int // m in the original paper
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
	var lfsr func(uint) uint

	switch len(key) {
	case 12:
		cipher.keyWords = 3
		cipher.rounds = roundsSimon64_96
		cipher.k = make([]uint32, cipher.rounds)
		for i := 0; i < cipher.keyWords; i++ {
			cipher.k[cipher.keyWords-i-1] = littleEndianBytesToUInt32(key[4*i : 4*i+4])
		}
		lfsr = ShiftU
	case 16:
		cipher.keyWords = 4
		cipher.rounds = roundsSimon64_128
		cipher.k = make([]uint32, cipher.rounds)
		for i := 0; i < cipher.keyWords; i++ {
			cipher.k[cipher.keyWords-i-1] = littleEndianBytesToUInt32(key[4*i : 4*i+4])
		}
		lfsr = ShiftV
	default:
		panic("NewSimon64() requires either a 96- or 128-bit key")
	}
	for i, reg, bit := cipher.keyWords, uint(1), uint32(0); i < cipher.rounds; i++ {
		tmp := leftRotate32(cipher.k[i-1], 29)
		if cipher.keyWords == 4 {
			tmp ^= cipher.k[i-3]
		}
		tmp ^= leftRotate32(tmp, 31)
		cipher.k[i] = ^cipher.k[i-cipher.keyWords] ^ tmp ^ uint32(reg&1) ^ bit ^ 3
		reg = lfsr(reg)
		bit ^= 1
	}
	return cipher
}

// Simon64 has a 64-bit block length. Note that this is in bytes, not words.
func (cipher *Simon64Cipher) BlockSize() int {
	return 8
}

func simonScramble32(x uint32) uint32 {
	return (leftRotate32(x, 1) & leftRotate32(x, 8)) ^ leftRotate32(x, 2)
}

// Encrypt encrypts the first block in src into dst.
// Dst and src may point at the same memory. See crypto/cipher.
func (cipher *Simon64Cipher) Encrypt(dst, src []byte) {
	x := littleEndianBytesToUInt32(src[0:4])
	y := littleEndianBytesToUInt32(src[4:8])
	for i := 0; i < cipher.rounds; i += 2 {
		y ^= simonScramble32(x) ^ cipher.k[i]
		x ^= simonScramble32(y) ^ cipher.k[i+1]
	}
	storeLittleEndianUInt32(dst[0:4], x)
	storeLittleEndianUInt32(dst[4:8], y)
}

// Decrypt decrypts the first block in src into dst.
// Dst and src may point at the same memory. See crypto/cipher.
func (cipher *Simon64Cipher) Decrypt(dst, src []byte) {
	x := littleEndianBytesToUInt32(src[0:4])
	y := littleEndianBytesToUInt32(src[4:8])
	for i := cipher.rounds - 1; i >= 0; i -= 2 {
		x ^= simonScramble32(y) ^ cipher.k[i]
		y ^= simonScramble32(x) ^ cipher.k[i-1]
	}
	storeLittleEndianUInt32(dst[0:4], x)
	storeLittleEndianUInt32(dst[4:8], y)
}
