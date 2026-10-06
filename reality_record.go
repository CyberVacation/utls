package tls

import (
	"encoding/binary"
	"errors"
	"io"
)

// writeRealityPostHandshakeRecords follows Xray's record-size matching: empty
// application records padded to the observed lengths, under application keys.
// These records carry no application bytes or usable session tickets.
func (c *Conn) writeRealityPostHandshakeRecords(lengths []int) error {
	if len(lengths) == 0 {
		return nil
	}
	c.out.Lock()
	defer c.out.Unlock()
	cipher, ok := c.out.cipher.(aead)
	if !ok || c.out.version != VersionTLS13 {
		return errors.New("REALITY: post-handshake records require TLS 1.3 application keys")
	}
	// Bound empty records to the TLS reader's tolerance and validate the entire
	// batch before writing any of it.
	if len(lengths) > maxUselessRecords {
		return errors.New("REALITY: too many post-handshake records")
	}
	for _, length := range lengths {
		if length < recordHeaderLen+cipher.Overhead()+1 || length > recordHeaderLen+maxPlaintext+1+cipher.Overhead() {
			return errors.New("REALITY: invalid post-handshake record length")
		}
	}
	for _, length := range lengths {
		record := make([]byte, length-cipher.Overhead())
		record[0], record[1], record[2] = byte(recordTypeApplicationData), 3, 3
		binary.BigEndian.PutUint16(record[3:5], uint16(length-recordHeaderLen))
		// TLSInnerPlaintext: empty content, application_data type, then padding.
		record[5] = byte(recordTypeApplicationData)
		record = cipher.Seal(record[:recordHeaderLen], c.out.seq[:], record[recordHeaderLen:], record[:recordHeaderLen])
		c.out.incSeq()
		n, err := c.write(record)
		if err == nil && n != len(record) {
			err = io.ErrShortWrite
		}
		if err != nil {
			return c.out.setErrorLocked(err)
		}
	}
	return nil
}
