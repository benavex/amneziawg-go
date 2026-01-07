//go:build windows

package conn

func NewDefaultBind() Bind {
	return NewMultibind(NewWinRingBind(), NewBindStream())
}
