// Package ironeye is the official Go client for the IronEye document
// intelligence and collection API.
//
//	client, err := ironeye.New()  // IRONEYE_API_KEY from the environment
//	if err != nil { return err }
//	envelope, err := client.Secrets(ctx, ironeye.AnalyzeRequest{
//		Input: ironeye.Source{Text: configuration},
//	})
//
// Every method takes a context, and cancelling it cancels the HTTP request and
// any pending retry with it.
package ironeye

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Version is what the client reports in its User-Agent.
const Version = "1.0.0"

const defaultBaseURL = "https://ironeye.org"

var retryableStatus = map[int]bool{408: true, 425: true, 429: true, 500: true, 502: true, 503: true, 504: true}

// Option configures a Client. Zero options is a working client as long as
// IRONEYE_API_KEY is set.
type Option func(*Client)

func WithAPIKey(key string) Option      { return func(c *Client) { c.apiKey = key } }
func WithBaseURL(raw string) Option     { return func(c *Client) { c.baseURL = strings.TrimRight(raw, "/") } }
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }
func WithMaxRetries(n int) Option       { return func(c *Client) { c.maxRetries = n } }
func WithLogger(l *slog.Logger) Option  { return func(c *Client) { c.log = l } }

// WithHeader adds a header to every request. A per-call header of the same name
// still wins.
func WithHeader(name, value string) Option {
	return func(c *Client) { c.headers[name] = value }
}

// Client is safe for concurrent use.
type Client struct {
	apiKey     string
	baseURL    string
	http       *http.Client
	maxRetries int
	log        *slog.Logger
	headers    map[string]string
}

// New builds a client. The key comes from WithAPIKey, or from IRONEYE_API_KEY;
// the base URL from WithBaseURL, IRONEYE_BASE_URL, or the public host.
func New(options ...Option) (*Client, error) {
	c := &Client{
		apiKey:     os.Getenv("IRONEYE_API_KEY"),
		baseURL:    defaultBaseURL,
		http:       &http.Client{Timeout: 60 * time.Second},
		maxRetries: 2,
		log:        slog.New(discardHandler{}),
		headers:    map[string]string{},
	}
	if base := os.Getenv("IRONEYE_BASE_URL"); base != "" {
		c.baseURL = strings.TrimRight(base, "/")
	}
	for _, option := range options {
		option(c)
	}
	if c.apiKey == "" {
		return nil, errors.New("ironeye: an API key is required: use WithAPIKey or set IRONEYE_API_KEY")
	}
	return c, nil
}

// ---------------------------------------------------------------------------
// analysis
// ---------------------------------------------------------------------------

func (c *Client) Analyze(ctx context.Context, r AnalyzeRequest, opts ...CallOption) (*Envelope, error) {
	return c.analysis(ctx, "/v1/analyze", r, opts)
}
func (c *Client) Extract(ctx context.Context, r AnalyzeRequest, opts ...CallOption) (*Envelope, error) {
	return c.analysis(ctx, "/v1/extract", r, opts)
}
func (c *Client) Classify(ctx context.Context, r AnalyzeRequest, opts ...CallOption) (*Envelope, error) {
	return c.analysis(ctx, "/v1/classify", r, opts)
}
func (c *Client) PII(ctx context.Context, r AnalyzeRequest, opts ...CallOption) (*Envelope, error) {
	return c.analysis(ctx, "/v1/pii/analyze", r, opts)
}
func (c *Client) Moderation(ctx context.Context, r AnalyzeRequest, opts ...CallOption) (*Envelope, error) {
	return c.analysis(ctx, "/v1/moderation/analyze", r, opts)
}
func (c *Client) Malware(ctx context.Context, r AnalyzeRequest, opts ...CallOption) (*Envelope, error) {
	return c.analysis(ctx, "/v1/malware/scan", r, opts)
}
func (c *Client) Secrets(ctx context.Context, r AnalyzeRequest, opts ...CallOption) (*Envelope, error) {
	return c.analysis(ctx, "/v1/secrets/scan", r, opts)
}
func (c *Client) Validate(ctx context.Context, r AnalyzeRequest, opts ...CallOption) (*Envelope, error) {
	return c.analysis(ctx, "/v1/validate", r, opts)
}
func (c *Client) Deduplicate(ctx context.Context, r AnalyzeRequest, opts ...CallOption) (*Envelope, error) {
	return c.analysis(ctx, "/v1/deduplicate", r, opts)
}
func (c *Client) Invoices(ctx context.Context, r AnalyzeRequest, opts ...CallOption) (*Envelope, error) {
	return c.analysis(ctx, "/v1/invoices/parse", r, opts)
}

// CallOption tunes one request.
type CallOption func(*call)

// WithIdempotencyKey makes a repeat of the same request return the first
// answer instead of running the engine again.
func WithIdempotencyKey(key string) CallOption {
	return func(c *call) { c.headers["Idempotency-Key"] = key }
}

type call struct {
	headers map[string]string
	query   url.Values
	body    io.Reader
	ctype   string
}

func (c *Client) analysis(ctx context.Context, path string, r AnalyzeRequest, opts []CallOption) (*Envelope, error) {
	var envelope Envelope
	if err := c.do(ctx, http.MethodPost, path, jsonCall(r, opts), &envelope); err != nil {
		return nil, err
	}
	return &envelope, nil
}

// Upload sends the bytes as multipart, for a file already in memory rather than
// base64 inside a JSON body.
type Upload struct {
	Filename         string
	ContentType      string
	Features         []string
	Preset           string
	Options          map[string]any
	OutputMode       string
	RetentionSeconds *int
}

func (c *Client) AnalyzeUpload(ctx context.Context, file []byte, u Upload, opts ...CallOption) (*Envelope, error) {
	buffer := &bytes.Buffer{}
	writer := multipart.NewWriter(buffer)
	name := u.Filename
	if name == "" {
		name = "document"
	}
	part, err := writer.CreateFormFile("file", name)
	if err != nil {
		return nil, fmt.Errorf("ironeye: building the upload: %w", err)
	}
	if _, err := part.Write(file); err != nil {
		return nil, fmt.Errorf("ironeye: building the upload: %w", err)
	}
	fields := map[string]string{"preset": u.Preset, "output_mode": u.OutputMode}
	if len(u.Features) > 0 {
		fields["features"] = strings.Join(u.Features, ",")
	}
	if u.Options != nil {
		encoded, err := json.Marshal(u.Options)
		if err != nil {
			return nil, fmt.Errorf("ironeye: encoding options: %w", err)
		}
		fields["options"] = string(encoded)
	}
	if u.RetentionSeconds != nil {
		fields["retention_seconds"] = strconv.Itoa(*u.RetentionSeconds)
	}
	for key, value := range fields {
		if value != "" {
			_ = writer.WriteField(key, value)
		}
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("ironeye: closing the upload: %w", err)
	}

	request := newCall(opts)
	request.body = buffer
	request.ctype = writer.FormDataContentType()
	var envelope Envelope
	if err := c.do(ctx, http.MethodPost, "/v1/analyze/upload", request, &envelope); err != nil {
		return nil, err
	}
	return &envelope, nil
}

// ---------------------------------------------------------------------------
// jobs
// ---------------------------------------------------------------------------

func (c *Client) CreateJob(ctx context.Context, r AnalyzeRequest) (*Job, error) {
	var job Job
	return &job, c.do(ctx, http.MethodPost, "/v1/jobs", jsonCall(r, nil), &job)
}

func (c *Client) Job(ctx context.Context, id string) (*Job, error) {
	var job Job
	return &job, c.do(ctx, http.MethodGet, "/v1/jobs/"+url.PathEscape(id), newCall(nil), &job)
}

func (c *Client) DeleteJob(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/jobs/"+url.PathEscape(id), newCall(nil), nil)
}

// AwaitJob polls until the job settles or ctx is done. Nothing in the service
// dispatches to a callback URL, so polling is the whole asynchronous contract.
func (c *Client) AwaitJob(ctx context.Context, id string, interval time.Duration) (*Job, error) {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		job, err := c.Job(ctx, id)
		if err != nil {
			return nil, err
		}
		if job.Done() {
			return job, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

// ---------------------------------------------------------------------------
// collection
// ---------------------------------------------------------------------------

func (c *Client) Catalogue(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	return out, c.do(ctx, http.MethodGet, "/v1/harvest/catalogue", newCall(nil), &out)
}

func (c *Client) Operations(ctx context.Context, platform string) (map[string]any, error) {
	request := newCall(nil)
	if platform != "" {
		request.query.Set("platform", platform)
	}
	var out map[string]any
	return out, c.do(ctx, http.MethodGet, "/v1/harvest/operations", request, &out)
}

func (c *Client) Operation(ctx context.Context, opID string) (map[string]any, error) {
	var out map[string]any
	return out, c.do(ctx, http.MethodGet, "/v1/harvest/operations/"+url.PathEscape(opID), newCall(nil), &out)
}

// Collect runs one operation, addressed by its own route as the catalogue gives
// it: "/v1/harvest/reddit/subreddit", say.
func (c *Client) Collect(ctx context.Context, path string, params map[string]string, d Declaration) (*Collection, error) {
	request := newCall(nil)
	for key, value := range params {
		request.query.Set(key, value)
	}
	for name, value := range d.headers() {
		request.headers[name] = value
	}
	var out Collection
	return &out, c.do(ctx, http.MethodGet, path, request, &out)
}

// CollectPost is Collect for the handful of operations the registry declares as
// POST. The parameters are identical; only where they travel changes.
func (c *Client) CollectPost(ctx context.Context, path string, params map[string]string, d Declaration) (*Collection, error) {
	request := jsonCall(params, nil)
	for name, value := range d.headers() {
		request.headers[name] = value
	}
	var out Collection
	return &out, c.do(ctx, http.MethodPost, path, request, &out)
}

// ---------------------------------------------------------------------------
// data subject rights
// ---------------------------------------------------------------------------

func (c *Client) GDPRNotice(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	return out, c.do(ctx, http.MethodGet, "/v1/gdpr/notice", newCall(nil), &out)
}

func (c *Client) Erasure(ctx context.Context, s Subject) (map[string]any, error) {
	var out map[string]any
	return out, c.do(ctx, http.MethodPost, "/v1/gdpr/erasure", jsonCall(s, nil), &out)
}

func (c *Client) Objection(ctx context.Context, s Subject) (map[string]any, error) {
	var out map[string]any
	return out, c.do(ctx, http.MethodPost, "/v1/gdpr/objections", jsonCall(s, nil), &out)
}

func (c *Client) AccessRequest(ctx context.Context, s Subject) (map[string]any, error) {
	var out map[string]any
	return out, c.do(ctx, http.MethodPost, "/v1/gdpr/access", jsonCall(s, nil), &out)
}

func (c *Client) Suppression(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	return out, c.do(ctx, http.MethodGet, "/v1/gdpr/suppression", newCall(nil), &out)
}

func (c *Client) Unsuppress(ctx context.Context, subjectKey string) error {
	return c.do(ctx, http.MethodDelete, "/v1/gdpr/suppression/"+url.PathEscape(subjectKey), newCall(nil), nil)
}

// ---------------------------------------------------------------------------
// service
// ---------------------------------------------------------------------------

func (c *Client) Health(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	return out, c.do(ctx, http.MethodGet, "/healthz", newCall(nil), &out)
}

func (c *Client) Ready(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	return out, c.do(ctx, http.MethodGet, "/readyz", newCall(nil), &out)
}

func (c *Client) Features(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	return out, c.do(ctx, http.MethodGet, "/v1/features", newCall(nil), &out)
}

func (c *Client) Status(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	return out, c.do(ctx, http.MethodGet, "/v1/status", newCall(nil), &out)
}

func (c *Client) AuditHead(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	return out, c.do(ctx, http.MethodGet, "/v1/audit/head", newCall(nil), &out)
}

// ---------------------------------------------------------------------------
// transport
// ---------------------------------------------------------------------------

func newCall(opts []CallOption) *call {
	c := &call{headers: map[string]string{}, query: url.Values{}}
	for _, option := range opts {
		option(c)
	}
	return c
}

func jsonCall(payload any, opts []CallOption) *call {
	c := newCall(opts)
	encoded, err := json.Marshal(payload)
	if err != nil {
		// Marshalling our own request types cannot fail; a caller's Options map
		// containing a channel can, and it surfaces on the first attempt.
		c.body = failingReader{err}
		return c
	}
	c.body = bytes.NewReader(encoded)
	c.ctype = "application/json"
	return c
}

func (c *Client) do(ctx context.Context, method, path string, request *call, out any) error {
	target := c.baseURL + path
	if encoded := request.query.Encode(); encoded != "" {
		target += "?" + encoded
	}

	// The body is read once per attempt, so it is buffered here rather than
	// streamed: a retry with a drained reader would send an empty document.
	var body []byte
	if request.body != nil {
		read, err := io.ReadAll(request.body)
		if err != nil {
			return fmt.Errorf("ironeye: reading the request body: %w", err)
		}
		body = read
	}

	var last error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		started := time.Now()
		response, err := c.send(ctx, method, target, request, body)
		if err != nil {
			last = fmt.Errorf("ironeye: %s %s: %w", method, path, err)
			if attempt >= c.maxRetries || ctx.Err() != nil {
				return last
			}
			if waitErr := c.backoff(ctx, attempt, "", "CONNECTION", path); waitErr != nil {
				return waitErr
			}
			continue
		}

		payload, apiErr := c.interpret(response, method, path, time.Since(started))
		if apiErr == nil {
			if out == nil || len(payload) == 0 {
				return nil
			}
			if err := json.Unmarshal(payload, out); err != nil {
				return fmt.Errorf("ironeye: decoding the response: %w", err)
			}
			return nil
		}
		if attempt >= c.maxRetries || !apiErr.Retryable || !retryableStatus[apiErr.Status] {
			return apiErr
		}
		last = apiErr
		if waitErr := c.backoff(ctx, attempt, response.Header.Get("Retry-After"), apiErr.Code, path); waitErr != nil {
			return waitErr
		}
	}
	return last
}

func (c *Client) send(ctx context.Context, method, target string, request *call, body []byte) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpRequest.Header.Set("User-Agent", "ironeye-go/"+Version)
	if request.ctype != "" {
		httpRequest.Header.Set("Content-Type", request.ctype)
	}
	for name, value := range c.headers {
		httpRequest.Header.Set(name, value)
	}
	for name, value := range request.headers {
		httpRequest.Header.Set(name, value)
	}
	return c.http.Do(httpRequest)
}

func (c *Client) interpret(response *http.Response, method, path string, elapsed time.Duration) ([]byte, *Error) {
	defer response.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(response.Body, 64<<20))
	c.log.Debug("ironeye request",
		"method", method,
		"path", path,
		"status", response.StatusCode,
		"duration_ms", elapsed.Milliseconds(),
		"request_id", response.Header.Get("X-Request-Id"),
	)
	if response.StatusCode < 400 {
		return payload, nil
	}
	var envelope struct {
		Error *Error `json:"error"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil || envelope.Error == nil {
		return nil, &Error{
			Status:          response.StatusCode,
			Code:            "INTERNAL",
			Message:         fmt.Sprintf("the server returned %d with no error body", response.StatusCode),
			Retryable:       response.StatusCode >= 500,
			SuggestedAction: "Retry, and quote the status if it persists.",
		}
	}
	envelope.Error.Status = response.StatusCode
	return nil, envelope.Error
}

// backoff honours Retry-After when the server sent one, because that number is
// the server's own and beats any curve guessed at from here.
func (c *Client) backoff(ctx context.Context, attempt int, retryAfter, code, path string) error {
	wait := time.Duration(250*(1<<attempt))*time.Millisecond + time.Duration(rand.Intn(250))*time.Millisecond
	if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds > 0 {
		wait = time.Duration(seconds) * time.Second
	}
	c.log.Warn("ironeye retrying", "path", path, "code", code, "wait_ms", wait.Milliseconds())
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Client) String() string {
	key := "..."
	if len(c.apiKey) > 12 {
		key = c.apiKey[:9] + "..."
	}
	return fmt.Sprintf("ironeye.Client{base: %s, key: %s}", c.baseURL, key)
}

func (c *Client) GoString() string {
	return c.String() + " // no globals, no init(), no surprises — forged at Direct Softworks"
}

type failingReader struct{ err error }

func (f failingReader) Read([]byte) (int, error) { return 0, f.err }

// discardHandler is the default logger: a client that logs before being asked
// to is a client that writes into somebody else's log format.
type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (h discardHandler) WithAttrs([]slog.Attr) slog.Handler      { return h }
func (h discardHandler) WithGroup(string) slog.Handler           { return h }
