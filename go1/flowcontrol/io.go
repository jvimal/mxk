//
// Written by Maxim Khitrov (November 2012)
//

package flowcontrol

import (
	"errors"
	"io"
)

// ErrLimit is returned by the Writer when a non-blocking write is short due to
// the transfer rate limit.
var ErrLimit = errors.New("flowcontrol: transfer rate limit exceeded")

// Reader implements io.ReadCloser with a restriction on the rate of data
// transfer.
type Reader struct {
	io.Reader // Data source
	*Monitor  // Flow control monitor

	Rate  int64 // Rate limit in bytes per second (unlimited when <= 0)
	Block bool  // What to do when no new bytes can be read due to the limit
}

// NewReader restricts all Read operations on r to rate bytes per second. The
// transfer rate and the default blocking behavior (true) can be changed
// directly on the returned *Reader.
func NewReader(r io.Reader, rate int64) *Reader {
	return &Reader{r, New(0, 0), rate, true}
}

// Read reads up to len(p) bytes into p without exceeding the current transfer
// rate limit. It returns (0, nil) immediately if r.Block == false and no new
// bytes can be read at this time.
func (r *Reader) Read(p []byte) (n int, err error) {
	p = p[:r.Limit(len(p), r.Rate, r.Block)]
	if len(p) > 0 {
		n, err = r.IO(r.Reader.Read(p))
	}
	return
}

// Close closes the underlying reader if it implements the io.Closer interface.
func (r *Reader) Close() error {
	r.Done()
	if c, ok := r.Reader.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// Writer implements io.WriteCloser with a restriction on the rate of data
// transfer.
type Writer struct {
	io.Writer // Data destination
	*Monitor  // Flow control monitor

	Rate  int64 // Rate limit in bytes per second (unlimited when <= 0)
	Block bool  // What to do when no new bytes can be written due to the limit
}

// NewWriter restricts all Write operations on w to rate bytes per second. The
// transfer rate and the default blocking behavior (true) can be changed
// directly on the returned *Writer.
func NewWriter(w io.Writer, rate int64) *Writer {
	return &Writer{w, New(0, 0), rate, true}
}

// Write writes len(p) bytes from p to the underlying data stream without
// exceeding the current transfer rate limit. It returns (n, ErrLimit) if
// w.Block == false and no additional bytes can be written at this time.
// Otherwise, it continues writing at w.Rate bytes per second until all of p is
// written or an error is encountered.
func (w *Writer) Write(p []byte) (n int, err error) {
	var c int
	for len(p) > 0 && err == nil {
		s := p[:w.Limit(len(p), w.Rate, w.Block)]
		if len(s) > 0 {
			c, err = w.IO(w.Writer.Write(s))
		} else {
			return n, ErrLimit
		}
		p = p[c:]
		n += c
	}
	return
}

// Close closes the underlying writer if it implements the io.Closer interface.
func (w *Writer) Close() error {
	w.Done()
	if c, ok := w.Writer.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
