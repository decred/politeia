package api

type ApiAsset struct {
	URL           string `json:"url"`
	Name          string `json:"name"`
	DownloadCount int    `json:"download_count"`
}

type ApiAuthor struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Date  string `json:"date"`
}

type ApiCommit struct {
	Author    ApiAuthor `json:"author"`
	Committer ApiAuthor `json:"committer"`
	Message   string    `json:"message"`
	URL       string    `json:"url"`
}

type ApiCommitParent struct {
	SHA string `json:"sha"`
	URL string `json:"url"`
}

type ApiCommitStats struct {
	Additions int `json:"additions"`
	Deletions int `json:"deletions"`
	Total     int `json:"total"`
}

type ApiCommitTree struct {
	SHA string `json:"sha"`
	URL string `json:"url"`
}

type ApiEvent struct {
	ID        int64   `json:"id"`
	NodeID    string  `json:"node_id"`
	URL       string  `json:"url"`
	Actor     ApiUser `json:"actor"`
	Event     string  `json:"event"`
	CommitID  string  `json:"commit_id"`
	CommitURL string  `json:"commit_url"`
	CreatedAt string  `json:"created_at"`
}

// repos/:org:/:repo:/pulls
type ApiPullsRequest struct {
	URL            string  `json:"url"`
	Number         int     `json:"number"`
	State          string  `json:"state"`
	Title          string  `json:"title"`
	User           ApiUser `json:"user"`
	UpdatedAt      string  `json:"updated_at"`
	MergedAt       string  `json:"merged_at"`
	MergeCommitSHA string  `json:"merge_commit_sha"`
	CommitsURL     string  `json:"commits_url"`
}

type ApiPullRequest struct {
	URL       string  `json:"url"`
	Number    int     `json:"number"`
	User      ApiUser `json:"user"`
	UpdatedAt string  `json:"updated_at"`
	ClosedAt  string  `json:"closed_at"`
	MergedAt  string  `json:"merged_at"`
	Merged    bool    `json:"merged"`
	State     string  `json:"state"`
	Additions int     `json:"additions"`
	Deletions int     `json:"deletions"`
	MergedBy  ApiUser `json:"merged_by"`
}

type ApiPullRequestCommit struct {
	SHA       string            `json:"sha"`
	Commit    ApiCommit         `json:"commit"`
	URL       string            `json:"url"`
	Author    ApiUser           `json:"author"`
	Committer ApiUser           `json:"committer"`
	Parents   []ApiCommitParent `json:"parents"`
	Stats     ApiCommitStats    `json:"stats"`

	// local change
	Discarded bool `json:"discarded"`
}

type ApiRateLimitRule struct {
	Limit     int   `json:"limit"`
	Remaining int   `json:"remaining"`
	Reset     int64 `json:"reset"`
}

type ApiRateLimitResource struct {
	Core                ApiRateLimitRule `json:"core"`
	Search              ApiRateLimitRule `json:"search"`
	GraphQL             ApiRateLimitRule `json:"graphql"`
	IntegrationManifest ApiRateLimitRule `json:"integration_manifest"`
}

type ApiRateLimit struct {
	Resources ApiRateLimitResource `json:"resources"`
	Rate      ApiRateLimitRule     `json:"rate"`
}

type ApiRelease struct {
	URL     string     `json:"url"`
	TagName string     `json:"tag_name"`
	Author  ApiAuthor  `json:"author"`
	Assets  []ApiAsset `json:"assets"`
}

type ApiRepository struct {
	Name     string  `json:"name"`
	FullName string  `json:"full_name"`
	Private  bool    `json:"private"`
	Owner    ApiUser `json:"owner"`
	Fork     bool    `json:"fork"`
	URL      string  `json:"url"`
}

type ApiPullRequestReview struct {
	ID          int64   `json:"id"`
	User        ApiUser `json:"user"`
	State       string  `json:"state"`
	SubmittedAt string  `json:"submitted_at"`
	CommitID    string  `json:"commit_id"`
}

type ApiTimeline struct {
	ID           int64             `json:"id"`
	NodeID       string            `json:"node_id"`
	URL          string            `json:"url"`
	Actor        ApiUser           `json:"actor"`
	Event        string            `json:"event"`
	CommitID     string            `json:"commit_id"`
	CommitURL    string            `json:"commit_url"`
	CreatedAt    string            `json:"created_at"`
	SubmittedAt  string            `json:"submitted_at"`
	State        string            `json:"state"`
	User         ApiUser           `json:"user"`
	SHA          string            `json:"sha"`
	Author       ApiAuthor         `json:"author"`
	Committer    ApiAuthor         `json:"committer"`
	CommitParent []ApiCommitParent `json:"parents"`
	CommitTree   ApiCommitTree     `json:"tree"`
}

type ApiUser struct {
	ID        int64  `json:"id"`
	NodeID    string `json:"node_id"`
	Login     string `json:"login"`
	URL       string `json:"url"`
	HtmlURL   string `json:"html_url"`
	Type      string `json:"type"`
	SiteAdmin bool   `json:"site_admin"`
}
