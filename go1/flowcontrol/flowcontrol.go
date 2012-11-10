//
// Written by Maxim Khitrov (November 2012)
//

// Package flowcontrol provides the tools for monitoring and limiting the
// transfer rate of an arbitrary data stream.
package flowcontrol

import (
	"math"
	"sync"
	"time"
)

// clockRate is the resolution and precision of clock().
const clockRate = 20 * time.Millisecond

// czero is the process start time rounded down to the nearest clockRate
// increment.
var czero = time.Duration(time.Now().UnixNano()) / clockRate * clockRate

// clock returns a low resolution timestamp relative to the process start time.
func clock() time.Duration {
	return time.Duration(time.Now().UnixNano())/clockRate*clockRate - czero
}

// clockToTime converts a clock() timestamp to an absolute time.Time value.
func clockToTime(c time.Duration) time.Time {
	return time.Unix(0, int64(czero+c))
}

// clockRound returns d rounded to the nearest clockRate increment.
func clockRound(d time.Duration) time.Duration {
	return (d + clockRate>>1) / clockRate * clockRate
}

// round returns x rounded to the nearest int64 (non-negative values only).
func round(x float64) int64 {
	if _, frac := math.Modf(x); frac >= 0.5 {
		return int64(math.Ceil(x))
	}
	return int64(math.Floor(x))
}

// Monitor monitors and limits the transfer rate of a data stream.
type Monitor struct {
	active  bool          // Flag indicating an active transfer
	start   time.Duration // Transfer start time (clock() value)
	bytes   int64         // Total number of bytes transferred
	samples int64         // Total number of samples taken

	rSample float64 // Most recent transfer rate sample (bytes per second)
	rEMA    float64 // Exponential moving average of rSample
	rPeak   float64 // Peak transfer rate (max of all rSamples)
	rWindow float64 // rEMA window (seconds)

	sBytes int64         // Number of bytes transferred since sLast
	sLast  time.Duration // Most recent sample time (stop time when inactive)
	sRate  time.Duration // Sampling rate

	mu sync.Mutex // Mutex guarding access to all internal fields
}

// New creates a new flow control monitor. Instantaneous transfer rate is
// measured and updated for each sampleRate interval. windowSize determines the
// weight of each sample in the exponential moving average (EMA) calculation.
// The exact formulas are:
//
// 	sampleTime = currentTime - prevSampleTime
// 	sampleRate = byteCount / sampleTime
// 	weight     = 1 - exp(-sampleTime/windowSize)
// 	newRate    = weight*sampleRate + (1-weight)*oldRate
//
// The default values for sampleRate and windowSize (if <= 0) are 100ms and 1s,
// respectively.
func New(sampleRate, windowSize time.Duration) *Monitor {
	if sampleRate = clockRound(sampleRate); sampleRate <= 0 {
		sampleRate = 5 * clockRate
	}
	if windowSize <= 0 {
		windowSize = 1 * time.Second
	}
	now := clock()
	return &Monitor{
		active:  true,
		start:   now,
		rWindow: windowSize.Seconds(),
		sLast:   now,
		sRate:   sampleRate,
	}
}

// Update records the transfer of n bytes and returns n. It should be called
// after each Read/Write operation, even if n is 0.
func (m *Monitor) Update(n int) int {
	m.mu.Lock()
	m.update(n)
	m.mu.Unlock()
	return n
}

// IO is a convenience method intended to wrap io.Reader and io.Writer method
// execution. It calls m.Update(n) and then returns (n, err) unmodified.
func (m *Monitor) IO(n int, err error) (int, error) {
	return m.Update(n), err
}

// Done marks the transfer as finished and prevents any further updates or
// limiting. Instantaneous and current transfer rates drop to 0. Update, IO, and
// Limit methods become NOOPs. It returns the total number of bytes transferred.
func (m *Monitor) Done() int64 {
	m.mu.Lock()
	if now := m.update(0); m.sBytes > 0 {
		m.reset(now)
	}
	m.active = false
	n := m.bytes
	m.mu.Unlock()
	return n
}

// Status represents the current Monitor status. All transfer rates are in bytes
// per second rounded to the nearest byte.
type Status struct {
	Active   bool          // Flag indicating an active transfer
	Start    time.Time     // Transfer start time
	Duration time.Duration // Time period covered by the statistics
	Bytes    int64         // Total number of bytes transferred
	Samples  int64         // Total number of samples taken
	InstRate int64         // Instantaneous transfer rate
	CurRate  int64         // Current transfer rate (EMA of InstRate)
	AvgRate  int64         // Average transfer rate (Bytes / Duration)
	PeakRate int64         // Maximum instantaneous transfer rate
}

// Status returns current transfer status information. The returned value
// remains fixed after a call to Done.
func (m *Monitor) Status() Status {
	m.mu.Lock()
	m.update(0)
	s := Status{
		Active:   m.active,
		Start:    clockToTime(m.start),
		Duration: m.sLast - m.start,
		Bytes:    m.bytes,
		Samples:  m.samples,
		PeakRate: round(m.rPeak),
	}
	if s.Active {
		s.InstRate = round(m.rSample)
		s.CurRate = round(m.rEMA)
	}
	m.mu.Unlock()
	if s.Duration > 0 {
		s.AvgRate = round(float64(s.Bytes) / s.Duration.Seconds())
	}
	return s
}

// Limit restricts the instantaneous (per-sample) data flow to rate bytes per
// second. It returns the maximum number of bytes (0 <= n <= want) that may be
// transferred immediately without exceeding the limit. If block == true, the
// call blocks until n > 0. want is returned unmodified if want < 1, rate < 1,
// or the transfer is inactive (after a call to Done).
//
// At least one byte is always allowed to be transferred in any given sampling
// period. Thus, if the sampling rate is 100ms, the lowest achievable flow rate
// is 10 bytes per second.
//
// For usage examples, see the implementation of Reader and Writer in io.go.
func (m *Monitor) Limit(want int, rate int64, block bool) (n int) {
	if want < 1 || rate < 1 {
		return want
	}
	m.mu.Lock()

	// Determine the maximum number of bytes that can be sent in one sample
	limit := round(float64(rate) * m.sRate.Seconds())
	if limit <= 0 {
		limit = 1
	}

	// If block == true, wait until m.sBytes < limit
	if now := m.update(0); block {
		for m.sBytes >= limit && m.active {
			now = m.waitNextSample(now)
		}
	}

	// Make limit <= want (unlimited if the transfer is no longer active)
	if limit -= m.sBytes; limit > int64(want) || !m.active {
		limit = int64(want)
	}
	m.mu.Unlock()

	if limit < 0 {
		limit = 0
	}
	return int(limit)
}

// update accumulates the transferred byte count for the current sample until
// clock() - m.sLast >= m.sRate. The monitor status is updated once the current
// sample is done.
func (m *Monitor) update(n int) (now time.Duration) {
	if !m.active {
		return // m is frozen, time is irrelevant
	}
	now = clock()
	m.sBytes += int64(n)
	if sTime := now - m.sLast; sTime >= m.sRate {
		t := sTime.Seconds()
		if m.rSample = float64(m.sBytes) / t; m.rSample > m.rPeak {
			m.rPeak = m.rSample
		}

		// Exponential moving average using a method similar to *nix load
		// average calculation. Longer sampling periods carry greater weight.
		if m.samples > 0 {
			w := math.Exp(-t / m.rWindow)
			m.rEMA = m.rSample + w*(m.rEMA-m.rSample)
		} else {
			m.rEMA = m.rSample
		}
		m.reset(now)
	}
	return
}

// reset clears the current sample state in preparation for the next sample.
func (m *Monitor) reset(sampleTime time.Duration) {
	m.bytes += m.sBytes
	m.samples++
	m.sBytes = 0
	m.sLast = sampleTime
}

// waitNextSample sleeps for the remainder of the current sample. The lock is
// released and reacquired during the actual sleep period, so it's possible for
// the transfer to be inactive when this method returns.
func (m *Monitor) waitNextSample(now time.Duration) time.Duration {
	const minWait = 5 * time.Millisecond
	current := m.sLast

	// sleep until the last sample time changes (ideally, just one iteration)
	for m.sLast == current && m.active {
		d := current + m.sRate - now
		m.mu.Unlock()
		if d < minWait {
			d = minWait
		}
		time.Sleep(d)
		m.mu.Lock()
		now = m.update(0)
	}
	return now
}