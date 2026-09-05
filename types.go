package ironeye

import "encoding/json"

// Source carries the document. Exactly one of Text, Base64 or URL: two is
// refused, and so is none.
type Source struct {
	Text        string `json:"text,omitempty"`
	Base64      string `json:"base64,omitempty"`
	URL         string `json:"url,omitempty"`
	Filename    string `json:"filename,omitempty"`
	ContentType string `json:"content_type,omitempty"`
}

type Output struct {
	Mode            string `json:"mode,omitempty"`
	IncludeFindings *bool  `json:"include_findings,omitempty"`
}

// AnalyzeRequest is the one body every analysis route and the job route share.
type AnalyzeRequest struct {
	Input   Source         `json:"input"`
	Feature []string       `json:"features,omitempty"`
	Preset  string         `json:"preset,omitempty"`
	Options map[string]any `json:"options,omitempty"`
	Output  *Output        `json:"output,omitempty"`
	// Zero keeps nothing. Above the deployment's ceiling it is refused rather
	// than clamped, so a caller cannot believe they asked for less than they did.
	RetentionSeconds *int   `json:"retention_seconds,omitempty"`
	CallbackURL      string `json:"callback_url,omitempty"`
}

type Evidence struct {
	TextSpan      *[2]int     `json:"text_span,omitempty"`
	Page          *int        `json:"page,omitempty"`
	BBox          *[4]float32 `json:"bbox,omitempty"`
	TimeRange     *[2]float32 `json:"time_range,omitempty"`
	ContainerPath string      `json:"container_path,omitempty"`
}

type Method struct {
	Type     string `json:"type"`
	Version  string `json:"version"`
	Model    string `json:"model,omitempty"`
	Provider string `json:"provider,omitempty"`
}

type Finding struct {
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	Category   string          `json:"category"`
	Epistemic  string          `json:"epistemic"`
	Value      *string         `json:"value,omitempty"`
	Normalized json.RawMessage `json:"normalized,omitempty"`
	Confidence float64         `json:"confidence"`
	Severity   *string         `json:"severity,omitempty"`
	Status     string          `json:"status"`
	Sensitive  bool            `json:"sensitive"`
	Redacted   bool            `json:"redacted,omitempty"`
	Evidence   Evidence        `json:"evidence"`
	Attributes map[string]any  `json:"attributes,omitempty"`
	Method     Method          `json:"method"`
	CreatedAt  string          `json:"created_at"`
}

// ModuleResult keeps the module's own body in Data: every module returns a
// different shape, and unmarshalling it into a fixed struct would drop whatever
// the engine learned to report since this file was written.
type ModuleResult struct {
	Status   string          `json:"status"`
	Cached   bool            `json:"cached"`
	Findings []Finding       `json:"findings,omitempty"`
	Data     json.RawMessage `json:"-"`
}

type Section map[string]ModuleResult

type Input struct {
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	MimeType  string `json:"mime_type,omitempty"`
	Channel   string `json:"channel"`
	Filename  string `json:"filename,omitempty"`
}

// Audit is the position in the append-only chain that the request was
// written to, not a single value: chain_id names the chain, head is the
// digest after this entry, seq is how many entries precede it. It was
// declared a string, and Go decodes strictly, so every successful response
// failed to parse at the client.
type AuditPosition struct {
	ChainID string `json:"chain_id"`
	Head    string `json:"head"`
	Seq     int64  `json:"seq"`
}

type Provenance struct {
	Modules   map[string]any `json:"modules"`
	Degraded  []string       `json:"degraded"`
	ElapsedMs float64        `json:"elapsed_ms"`
	Audit     AuditPosition  `json:"audit"`
}

type Retention struct {
	Seconds   int64  `json:"seconds"`
	Mode      string `json:"mode"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Stored    string `json:"stored"`
}

// Envelope is the answer to every analysis call. The sections are named for how
// the engine came to know each one, and nothing crosses between them.
type Envelope struct {
	RequestID      string            `json:"request_id"`
	Status         string            `json:"status"`
	Engine         map[string]string `json:"engine"`
	Input          Input             `json:"input"`
	Classification map[string]any    `json:"classification"`
	Observed       Section           `json:"observed"`
	Derived        Section           `json:"derived"`
	Inferred       Section           `json:"inferred"`
	Validated      Section           `json:"validated"`
	Safety         Section           `json:"safety"`
	Privacy        Section           `json:"privacy"`
	Security       Section           `json:"security"`
	Compliance     Section           `json:"compliance"`
	Provenance     Provenance        `json:"provenance"`
	Retention      Retention         `json:"retention"`
	Actions        []any             `json:"actions"`
	CreatedAt      string            `json:"created_at"`
}

type Job struct {
	ID               string    `json:"id"`
	Status           string    `json:"status"`
	RetentionSeconds int64     `json:"retention_seconds,omitempty"`
	CreatedAt        string    `json:"created_at"`
	Result           *Envelope `json:"result,omitempty"`
}

// Done reports whether the job has settled either way.
func (j Job) Done() bool { return j.Status == "completed" || j.Status == "failed" }

// Declaration is what a collection call declares about itself. It is required
// on any operation whose personal_data flag is true: the server refuses rather
// than assumes.
type Declaration struct {
	LegalBasis       string
	Purpose          string
	Controller       string
	BasisEvidence    string
	SpecialCondition string
	Projection       string
}

func (d Declaration) headers() map[string]string {
	out := map[string]string{}
	for name, value := range map[string]string{
		"X-Legal-Basis":       d.LegalBasis,
		"X-Purpose":           d.Purpose,
		"X-Controller":        d.Controller,
		"X-Basis-Evidence":    d.BasisEvidence,
		"X-Special-Condition": d.SpecialCondition,
		"X-Projection":        d.Projection,
	} {
		if value != "" {
			out[name] = value
		}
	}
	return out
}

type CollectionMeta struct {
	Source     string  `json:"source"`
	SourceKind string  `json:"source_kind"`
	DurationMs float64 `json:"duration_ms"`
	Records    int     `json:"records"`
	// Attempts is every source tried and how each one went, in order -- the
	// reason a record came from the source it did. It was declared a count.
	Attempts []Attempt `json:"attempts"`
	Cached   bool      `json:"cached,omitempty"`
}

type Attempt struct {
	Source  string `json:"source"`
	Outcome string `json:"outcome"`
	Reason  string `json:"reason,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Collection is the answer to a collection operation. Data is one record or an
// array of them, depending on whether the operation is a list.
type Collection struct {
	RequestID  string          `json:"request_id"`
	Operation  string          `json:"operation"`
	Entity     string          `json:"entity"`
	Data       json.RawMessage `json:"data"`
	Collection CollectionMeta  `json:"collection"`
	Compliance map[string]any  `json:"compliance"`
	Paging     *struct {
		NextCursor string `json:"next_cursor,omitempty"`
		Total      *int64 `json:"total,omitempty"`
	} `json:"paging,omitempty"`
}

// Subject names a person on a platform for the rights endpoints. The identifier
// is never logged by the service: the audit record keeps a salted digest.
type Subject struct {
	Platform   string `json:"platform"`
	Identifier string `json:"identifier"`
	Reference  string `json:"reference,omitempty"`
}
