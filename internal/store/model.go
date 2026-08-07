package store

import "time"

type Header map[string][]string

type Request struct {
	ID, DeliveryID, Method, Path, RemoteAddr, BodySHA256 string
	ReceivedAt                                           time.Time
	Headers                                              Header
	Body                                                 []byte
	SignatureVerified                                    bool
}

type RequestSummary struct {
	ID, DeliveryID, Method, Path, BodySHA256 string
	ReceivedAt                               time.Time
	BodyBytes                                int
}

type Attempt struct {
	ID, JobID, RequestID, URL, Error string
	Number, Status                   int
	StartedAt, FinishedAt            time.Time
	ResponseHeaders                  Header
	ResponseBody                     []byte
}

type Job struct {
	ID, RequestID, URL, State, Error, LeaseOwner string
	CreatedAt, UpdatedAt, AvailableAt            time.Time
	LeaseExpiresAt, FinishedAt                   time.Time
}

type Event struct {
	Seq               uint64    `json:"seq"`
	Kind              string    `json:"kind"`
	At                time.Time `json:"at"`
	Snapshot          bool      `json:"snapshot,omitempty"`
	Request           *Request  `json:"request,omitempty"`
	Attempt           *Attempt  `json:"attempt,omitempty"`
	Job               *Job      `json:"job,omitempty"`
	EvictedRequestIDs []string  `json:"evicted_request_ids,omitempty"`
	EvictedJobIDs     []string  `json:"evicted_job_ids,omitempty"`
}

type CaptureResult int

const (
	Captured CaptureResult = iota
	Duplicate
	Conflict
)
