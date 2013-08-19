// Copyright 2013 Samuel Isaacson. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package simonspeck

const (
	roundsSpeck128_128 = 32
	roundsSpeck128_192 = 33
	roundsSpeck128_256 = 34
)

// Use NewSpeck128 below to expand a Speck128 key. Speck128Cipher
// implements the cipher.Block interface.
type Speck128Cipher struct {
	k      []uint64
	rounds int
}

// NewSpeck128 creates and returns a new Speck128Cipher. It accepts a
// 128-bit key (for Speck128/128), a 196-bit key (for Speck128/196),
// or a 256-bit key (for Speck128/256). See the documentation on
// Simon32 or the test suite for our endianness convention.
func NewSpeck128(key []byte) *Speck128Cipher {
	cipher := new(Speck128Cipher)
	var keyWords int
	var auxKey []uint64

	switch len(key) {
	case 16:
		keyWords = 2
		cipher.rounds = roundsSpeck128_128
	case 24:
		keyWords = 3
		cipher.rounds = roundsSpeck128_192
	case 32:
		keyWords = 4
		cipher.rounds = roundsSpeck128_256
	default:
		panic("NewSpeck128() requires a 128-, 192-, or 256-bit key")
	}
	cipher.k = make([]uint64, cipher.rounds)
	auxKey = make([]uint64, keyWords+cipher.rounds-2)
	cipher.k[0] = littleEndianBytesToUInt64(key[0:8])
	for i := 0; i < keyWords-1; i++ {
		auxKey[i] = littleEndianBytesToUInt64(key[8*i+8 : 8*i+16])
	}
	for i := 0; i < cipher.rounds-1; i++ {
		auxKey[i+keyWords-1] = (cipher.k[i] + rightRotate64(auxKey[i], 8)) ^ uint64(i)
		cipher.k[i+1] = leftRotate64(cipher.k[i], 3) ^ auxKey[i+keyWords-1]
	}
	return cipher
}

// Speck128 has a 128-bit block length.
func (cipher *Speck128Cipher) BlockSize() int {
	return 16
}

// Encrypt encrypts the first block in src into dst.
// Dst and src may point at the same memory. See crypto/cipher.
func (cipher *Speck128Cipher) Encrypt(dst, src []byte) {
	y := littleEndianBytesToUInt64(src[0:8])
	x := littleEndianBytesToUInt64(src[8:16])
	for i := 0; i < cipher.rounds; i++ {
		x = (rightRotate64(x, 8) + y) ^ cipher.k[i]
		y = leftRotate64(y, 3) ^ x

	}
	storeLittleEndianUInt64(dst[0:8], y)
	storeLittleEndianUInt64(dst[8:16], x)
}

// Decrypt decrypts the first block in src into dst.
// Dst and src may point at the same memory. See crypto/cipher.
func (cipher *Speck128Cipher) Decrypt(dst, src []byte) {
	y := littleEndianBytesToUInt64(src[0:8])
	x := littleEndianBytesToUInt64(src[8:16])
	for i := cipher.rounds - 1; i >= 0; i-- {
		y = rightRotate64(y^x, 3)
		x = leftRotate64((x^cipher.k[i])-y, 8)

	}
	storeLittleEndianUInt64(dst[0:8], y)
	storeLittleEndianUInt64(dst[8:16], x)
}
