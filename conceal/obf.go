package conceal

import (
	"io"
)

type Obf interface {
	Spec() string
	Read(r io.Reader, ctx *readContext) error
	Write(w io.Writer, ctx *writeContext) error
}

type Obfs []Obf

type timestampObf struct{}

type randDigitObf struct {
	length int
}

type randCharObf struct {
	length int
}

type randObf struct {
	length int
}

type dataSizeObf struct {
	format NumFormat
	length int
	end    byte
}

type dataObf struct {
}

type bytesObf struct {
	data []byte
}

type dataStringObf struct {
}
