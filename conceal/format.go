package conceal

import (
	"errors"
	"strings"
)

type NumFormat int

const (
	NumFormatBE NumFormat = iota
	NumFormatLE
	NumFormatAscii
)

func NumFormatFromString(str string) (NumFormat, error) {
	str = strings.ToLower(str)

	switch str {
	case "be":
		return NumFormatBE, nil
	case "le":
		return NumFormatLE, nil
	case "ascii":
		return NumFormatAscii, nil
	}
	return NumFormatBE, errors.New("wrong format")
}

func (f NumFormat) ToString() string {
	switch f {
	case NumFormatBE:
		return "be"
	case NumFormatLE:
		return "le"
	case NumFormatAscii:
		return "ascii"
	}
	return ""
}
