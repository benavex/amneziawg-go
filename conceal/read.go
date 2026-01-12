package conceal

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode"
)

var (
	errInvalidData = errors.New("invalid data")
)

type readContext struct {
	*flexBuffer
	*BufferPool
	nextDataSize int
}

func ReadUntil(r io.Reader, b []byte, delim byte) (n int, err error) {
	for n < len(b) {
		if _, err = r.Read(b[n : n+1]); err != nil {
			return n, err
		}
		if b[n] == delim {
			return n, nil
		}
		n++
	}
	return n, io.ErrShortBuffer
}

func (o *bytesObf) Read(r io.Reader, ctx *readContext) error {
	tmp := ctx.GetBuffer()
	defer ctx.Put(tmp)

	buf := tmp[:len(o.data)]
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}

	if !bytes.Equal(buf, o.data) {
		return errInvalidData
	}

	return nil
}

func (o *dataObf) Read(r io.Reader, ctx *readContext) error {
	buf := ctx.PushTail(ctx.nextDataSize)
	if buf == nil {
		return io.ErrShortBuffer
	}

	_, err := io.ReadFull(r, buf)
	return err
}

func (o *dataSizeObf) Read(r io.Reader, ctx *readContext) error {
	tmp := ctx.GetBuffer()
	defer ctx.Put(tmp)

	switch o.format {
	case NumFormatBE:
		buf := tmp[:o.length]
		if _, err := io.ReadFull(r, buf); err != nil {
			return err
		}
		var size int
		for i := range buf {
			size <<= 8
			size |= int(buf[i])
		}
		ctx.nextDataSize = size

	case NumFormatLE:
		buf := tmp[:o.length]
		if _, err := io.ReadFull(r, buf); err != nil {
			return err
		}
		var size int
		for i := len(buf) - 1; i >= 0; i-- {
			size <<= 8
			size |= int(buf[i])
		}
		ctx.nextDataSize = size

	case NumFormatAscii:
		n, err := ReadUntil(r, tmp, o.end)
		if err != nil {
			return err
		}

		size64, err := strconv.ParseInt(string(tmp[:n]), 10, 32)
		if err != nil {
			return err
		}
		ctx.nextDataSize = int(size64)

	case NumFormatHex:
		n, err := ReadUntil(r, tmp, o.end)
		if err != nil {
			return err
		}

		size64, err := strconv.ParseInt(string(tmp[:n]), 16, 32)
		if err != nil {
			return err
		}
		ctx.nextDataSize = int(size64)
	}

	return nil
}

func (o *dataStringObf) Read(r io.Reader, ctx *readContext) error {
	tmp := ctx.GetBuffer()
	defer ctx.Put(tmp)

	base64len := base64.RawStdEncoding.EncodedLen(ctx.nextDataSize)
	buf := tmp[:base64len]
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}

	data := ctx.PushTail(ctx.nextDataSize)
	if data == nil {
		return io.ErrShortBuffer
	}

	if _, err := base64.RawStdEncoding.Decode(data, buf); err != nil {
		// return buf in case of error
		ctx.PullTail(len(data))
		return fmt.Errorf("failed to decode base64: %w", err)
	}

	return nil
}

func (o *randObf) Read(r io.Reader, ctx *readContext) error {
	tmp := ctx.GetBuffer()
	defer ctx.Put(tmp)

	buf := tmp[:o.length]
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}

	// I guess, there is no way to validate randomness
	// so just return nil here like everything is fine
	return nil
}

func (o *randCharObf) Read(r io.Reader, ctx *readContext) error {
	tmp := ctx.GetBuffer()
	defer ctx.Put(tmp)

	buf := tmp[:o.length]
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}

	for _, b := range buf {
		if !unicode.IsLetter(rune(b)) {
			return errInvalidData
		}
	}

	return nil
}

func (o *randDigitObf) Read(r io.Reader, ctx *readContext) error {
	tmp := ctx.GetBuffer()
	defer ctx.Put(tmp)

	buf := tmp[:o.length]
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}

	for _, b := range buf {
		if !unicode.IsDigit(rune(b)) {
			return errInvalidData
		}
	}

	return nil
}

func (o *timestampObf) Read(r io.Reader, ctx *readContext) error {
	var timestamp uint32
	if err := binary.Read(r, binary.BigEndian, &timestamp); err != nil {
		return err
	}

	// TODO: check timestamp?

	return nil
}
