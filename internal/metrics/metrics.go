package metrics

import (
	"sync/atomic"
)

type Snapshot struct {
	TotalRequests    uint64 `json:"total_requests"`
	ActiveStreams    int64  `json:"active_streams"`
	FailedStreams    uint64 `json:"failed_streams"`
	BytesTransferred uint64 `json:"bytes_transferred"`
}

type Store struct {
	totalRequests    atomic.Uint64
	activeStreams    atomic.Int64
	failedStreams    atomic.Uint64
	bytesTransferred atomic.Uint64
}

func New() *Store {
	return &Store{}
}

func (m *Store) IncRequests() {
	m.totalRequests.Add(1)
}

func (m *Store) IncActiveStreams() {
	m.activeStreams.Add(1)
}

func (m *Store) DecActiveStreams() {
	m.activeStreams.Add(-1)
}

func (m *Store) IncFailedStreams() {
	m.failedStreams.Add(1)
}

func (m *Store) AddBytes(n int64) {
	if n <= 0 {
		return
	}
	m.bytesTransferred.Add(uint64(n))
}

func (m *Store) Snapshot() Snapshot {
	return Snapshot{
		TotalRequests:    m.totalRequests.Load(),
		ActiveStreams:    m.activeStreams.Load(),
		FailedStreams:    m.failedStreams.Load(),
		BytesTransferred: m.bytesTransferred.Load(),
	}
}
