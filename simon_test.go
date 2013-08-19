package simon

import (
	"crypto/cipher"
	"math/rand"
	"testing"
)

func TestRotate(t *testing.T) {
	if leftRotate16(0x0003, 15) != 0x8001 {
		t.Errorf("Bad rotation")
	}
}

func TestShiftU(t *testing.T) {
	const uOutput = "11111010001001010110000111001101111101000100101011000011100110"
	var reg uint = 1

	for i, bit := range uOutput {
		if (bit == '1' && reg&1 == 0) || (bit == '0' && reg&1 == 1) {
			t.Errorf("Bad output at step %d of U LFSR", i)
		}
		reg = ShiftU(reg)
	}
}

func TestShiftV(t *testing.T) {
	const vOutput = "10001110111110010011000010110101000111011111001001100001011010"
	var reg uint = 1

	for i, bit := range vOutput {
		if (bit == '1' && reg&1 == 0) || (bit == '0' && reg&1 == 1) {
			t.Errorf("Bad output at step %d of V LFSR", i)
		}
		reg = ShiftV(reg)
	}
}

func TestShiftW(t *testing.T) {
	const wOutput = "10000100101100111110001101110101000010010110011111000110111010"
	var reg uint = 1

	for i, bit := range wOutput {
		if (bit == '1' && reg&1 == 0) || (bit == '0' && reg&1 == 1) {
			t.Errorf("Bad output at step %d of W LFSR", i)
		}
		reg = ShiftW(reg)
	}
}

func TestEncrypt32(t *testing.T) {
	// Note that these are given as little-endian words in the reference paper.
	var key = []byte{0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19}
	var plaintext = []byte{0x65, 0x65, 0x77, 0x68}
	var ciphertext = []byte{0x9b, 0xc6, 0xbb, 0xe9}

	var cipher = NewSimon32(key)
	cipher.Encrypt(plaintext, plaintext)
	for i := 0; i < len(plaintext); i++ {
		if ciphertext[i] != plaintext[i] {
			t.Errorf("Bad encryption; expecting 0x%02x, got 0x%02x", ciphertext[i], plaintext[i])
		}
	}
}

func TestEncDec32(t *testing.T) {
	key := make([]byte, 8)
	for i, _ := range key {
		key[i] = byte(rand.Int() & 0xff)
	}
	simon32 := NewSimon32(key)
	iv := make([]byte, 4)
	for i, _ := range iv {
		iv[i] = byte(rand.Int() & 0xff)
	}
	// We make sure to use CBC as it uses both encryption and decryption.
	enc := cipher.NewCBCEncrypter(simon32, iv)
	dec := cipher.NewCBCDecrypter(simon32, iv)
	plaintext := make([]byte, 16384*simon32.BlockSize())
	ciphertext := make([]byte, 16384*simon32.BlockSize())
	for i, _ := range plaintext {
		plaintext[i] = byte(rand.Int() & 0xff)
	}
	enc.CryptBlocks(ciphertext, plaintext)
	dec.CryptBlocks(ciphertext, ciphertext)
	for i, p := range plaintext {
		if p != ciphertext[i] {
			t.Errorf("Encryption followed by decryption failed.")
			break
		}
	}
}
