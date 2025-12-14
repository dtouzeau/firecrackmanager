package Compose2FC

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"firecrackmanager/internal/futils"
	"firecrackmanager/internal/proxyconfig"

	"github.com/compose-spec/compose-go/v2/cli"
)

type DockerHubSearchResponse struct {
	Count    int                 `json:"count"`
	Next     string              `json:"next"`
	Previous string              `json:"previous"`
	Results  []DockerHubRepoItem `json:"results"`
}

// DockerHubRepoItem is one repository entry in the results list.
type DockerHubRepoItem struct {
	RepoName         string `json:"repo_name"`
	ShortDescription string `json:"short_description"`
	StarCount        int    `json:"star_count"`
	// pull_count can be large → use int64
	PullCount   int64  `json:"pull_count"`
	RepoOwner   string `json:"repo_owner"`
	IsAutomated bool   `json:"is_automated"`
	IsOfficial  bool   `json:"is_official"`
}

// ImageHit is a unified result across registries.
type ImageHit struct {
	Registry    string `json:"registry"`
	Name        string `json:"name"`
	FullName    string `json:"full_name"`
	Description string `json:"description"`
	Stars       int    `json:"stars"`
	Pulls       int64  `json:"pulls"`
}

// SearchOptions control the search behavior.
type SearchOptions struct {
	// Max results per registry (overall results are merged).
	Limit int
	// Outbound HTTP(S) proxy, e.g. "http://user:pass@proxy.local:3128".
	ProxyURL string
	// Optional tokens (improves rate limits / access in some cases):
	// Docker Hub: supply either a JWT token (Authorization: JWT ...) or a bearer (Authorization: Bearer ...)
	DockerHubToken string
	// Quay: personal access token -> "Authorization: Bearer <token>"
	QuayToken string
	// GitLab: "PRIVATE-TOKEN: <token>"
	GitLabToken string

	// HTTP timeout for each registry call
	Timeout time.Duration
}

// SearchPublicImages searches Docker Hub, Quay.io, and GitLab for repositories matching `query`.
func SearchPublicImages(ctx context.Context, query string, opts SearchOptions) ([]ImageHit, error) {
	if opts.Limit <= 0 {
		opts.Limit = 25
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 20 * time.Second
	}
	httpClient, err := makeHTTPClient(opts.Timeout, opts.ProxyURL)
	if err != nil {
		return nil, err
	}

	type res struct {
		hits []ImageHit
		err  error
	}

	out := make(chan res, 3)

	// Docker Hub
	go func() {
		h, e := searchDockerHub(ctx, httpClient, query, opts.Limit, opts.DockerHubToken)
		out <- res{h, e}
	}()
	// Quay
	go func() {
		h, e := searchQuay(ctx, httpClient, query, opts.Limit, opts.QuayToken)
		out <- res{h, e}
	}()
	// GitLab
	go func() {
		h, e := searchGitLab(ctx, httpClient, query, opts.Limit, opts.GitLabToken)
		out <- res{h, e}
	}()

	var all []ImageHit
	var errs []string
	for i := 0; i < 3; i++ {
		r := <-out
		if r.err != nil {
			errs = append(errs, r.err.Error())
			continue
		}
		all = append(all, r.hits...)
	}

	// Simple ranking: by stars, then pulls, then name.
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Stars != all[j].Stars {
			return all[i].Stars > all[j].Stars
		}
		if all[i].Pulls != all[j].Pulls {
			return all[i].Pulls > all[j].Pulls
		}
		return all[i].Name < all[j].Name
	})

	if len(all) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf(strings.Join(errs, " | "))
	}

	return all, nil
}

/* ---------------- Docker Hub ---------------- */

func searchDockerHub(ctx context.Context, c *http.Client, q string, limit int, token string) ([]ImageHit, error) {
	// v2 search (still broadly available):
	// GET https://hub.docker.com/v2/search/repositories/?query=<q>&page_size=<n>
	u := "https://hub.docker.com/v2/search/repositories/?page_size=" + strconv.Itoa(limit) + "&query=" + url.QueryEscape(q)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	withDockerHubAuth(req, token)

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dockerhub search: %w", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	if resp.StatusCode >= 400 {
		return searchDockerHubContentAPI(ctx, c, q, limit, token)
	}

	var r DockerHubSearchResponse

	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("dockerhub decode: %w", err)
	}

	hits := make([]ImageHit, 0, len(r.Results))
	for _, it := range r.Results {
		it.RepoName = strings.TrimSpace(it.RepoName)
		if it.RepoName == "" {
			continue
		}

		// RepoName from Docker Hub already contains namespace/name (e.g., "cornel71/bookworm")
		// For official images, it's just the name (e.g., "nginx")
		name := it.RepoName
		full := "docker.io/" + name
		if it.IsOfficial && !strings.Contains(name, "/") {
			// Official images live under "library"
			full = "docker.io/library/" + name
		}
		desc := futils.Base64Encode(it.ShortDescription)
		hits = append(hits, ImageHit{
			Registry:    "dockerhub",
			Name:        name,
			FullName:    full,
			Description: desc,
			Stars:       it.StarCount,
			Pulls:       it.PullCount,
		})
	}
	return hits, nil
}

func searchDockerHubContentAPI(ctx context.Context, c *http.Client, q string, limit int, token string) ([]ImageHit, error) {
	// GET https://hub.docker.com/api/content/v1/products/search?q=<q>&type=image&page_size=<n>
	u := "https://hub.docker.com/api/content/v1/products/search?q=" + url.QueryEscape(q) + "&type=image&page_size=" + strconv.Itoa(limit)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	withDockerHubAuth(req, token)
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dockerhub (content api) search: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("dockerhub content api status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var r struct {
		Summaries []struct {
			Name      string `json:"name"` // e.g., library/nginx
			ShortDesc string `json:"short_description"`
			Publisher string `json:"publisher"`
			Slug      string `json:"slug"`
			RepoName  string `json:"repo_name"` // sometimes present
			StarCount int    `json:"star_count"`
			PullCount int64  `json:"pull_count"`
		} `json:"summaries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("dockerhub content api decode: %w", err)
	}
	var hits []ImageHit
	for _, s := range r.Summaries {
		name := s.Name
		if name == "" && s.RepoName != "" {
			name = s.RepoName
		}
		if name == "" {
			continue
		}
		full := "docker.io/" + name
		hits = append(hits, ImageHit{
			Registry:    "dockerhub",
			Name:        name,
			FullName:    full,
			Description: futils.Base64Encode(s.ShortDesc),
			Stars:       s.StarCount,
			Pulls:       s.PullCount,
		})
	}
	return hits, nil
}

func withDockerHubAuth(req *http.Request, token string) {
	t := strings.TrimSpace(token)
	if t == "" {
		return
	}
	// Accept either "JWT ..." or raw token; if raw, use Bearer.
	if strings.HasPrefix(strings.ToLower(t), "jwt ") || strings.HasPrefix(strings.ToLower(t), "bearer ") {
		req.Header.Set("Authorization", t)
	} else {
		req.Header.Set("Authorization", "Bearer "+t)
	}
}

/* ---------------- Quay.io ---------------- */

func searchQuay(ctx context.Context, c *http.Client, q string, limit int, token string) ([]ImageHit, error) {
	// GET https://quay.io/api/v1/find/repositories?query=<q>&public=true&popularity=true&limit=<n>
	u := "https://quay.io/api/v1/find/repositories?public=true&popularity=true&limit=" + strconv.Itoa(limit) +
		"&query=" + url.QueryEscape(q)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("quay search: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("quay status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	// Quay's payload shape can differ slightly; use partial decoding.
	var r struct {
		Results []struct {
			Name        string  `json:"name"`        // namespace/repo
			Description string  `json:"description"` // may be ""
			Popularity  float64 `json:"popularity"`  // 0..1
			IsPublic    bool    `json:"is_public"`
		} `json:"results"`
		Repositories []struct { // some deployments use "repositories"
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"repositories"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("quay decode: %w", err)
	}
	var hits []ImageHit
	if len(r.Results) > 0 {
		for _, it := range r.Results {
			n := strings.TrimSpace(it.Name)
			if n == "" {
				continue
			}
			hits = append(hits, ImageHit{
				Registry:    "quay",
				Name:        n,
				FullName:    "quay.io/" + n,
				Description: futils.Base64Encode(strings.TrimSpace(it.Description)),
				Stars:       0,
				Pulls:       0,
			})
		}
	} else {
		for _, it := range r.Repositories {
			n := strings.TrimSpace(it.Name)
			if n == "" {
				continue
			}
			hits = append(hits, ImageHit{
				Registry:    "quay",
				Name:        n,
				FullName:    "quay.io/" + n,
				Description: it.Description,
			})
		}
	}
	return hits, nil
}

/* ---------------- GitLab.com ---------------- */

func searchGitLab(ctx context.Context, c *http.Client, q string, limit int, token string) ([]ImageHit, error) {
	// 1) find public projects by text
	projectsURL := "https://gitlab.com/api/v4/projects?visibility=public&simple=true&per_page=" + strconv.Itoa(limit) +
		"&search=" + url.QueryEscape(q)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, projectsURL, nil)
	if token != "" {
		req.Header.Set("PRIVATE-TOKEN", token)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gitlab search projects: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("gitlab status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var projects []struct {
		ID                int    `json:"id"`
		PathWithNamespace string `json:"path_with_namespace"`
		Description       string `json:"description"`
		StarCount         int    `json:"star_count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&projects); err != nil {
		return nil, fmt.Errorf("gitlab decode projects: %w", err)
	}

	// 2) for each project, try to list its registry repositories
	type repo struct {
		Path     string `json:"path"`     // e.g. "group/project/image"
		Location string `json:"location"` // e.g. "registry.gitlab.com/group/project/image"
	}
	var hits []ImageHit
	for _, p := range projects {
		if len(hits) >= limit {
			break
		}
		reposURL := "https://gitlab.com/api/v4/projects/" + strconv.Itoa(p.ID) + "/registry/repositories?per_page=50"
		rreq, _ := http.NewRequestWithContext(ctx, http.MethodGet, reposURL, nil)
		if token != "" {
			rreq.Header.Set("PRIVATE-TOKEN", token)
		}
		rresp, err := c.Do(rreq)
		if err != nil {
			continue // skip project on error
		}
		func() {
			defer rresp.Body.Close()
			if rresp.StatusCode >= 400 {
				return
			}
			var repos []repo
			if err := json.NewDecoder(rresp.Body).Decode(&repos); err != nil {
				return
			}
			for _, rr := range repos {
				if len(hits) >= limit {
					break
				}
				name := strings.TrimSpace(rr.Path)
				if name == "library/" {
					continue
				}
				full := rr.Location
				if full == "" && name != "" {
					full = "registry.gitlab.com/" + name
				}
				if name == "" || full == "" {
					continue
				}
				hits = append(hits, ImageHit{
					Registry:    "gitlab",
					Name:        name,
					FullName:    full,
					Description: futils.Base64Encode(p.Description),
					Stars:       p.StarCount,
					Pulls:       0,
				})
			}
		}()
	}
	return hits, nil
}

/* ---------------- HTTP helpers ---------------- */

func makeHTTPClient(timeout time.Duration, overrideProxyURL string) (*http.Client, error) {
	// Use override proxy URL if provided, otherwise use global config
	proxyURL := strings.TrimSpace(overrideProxyURL)
	if proxyURL == "" {
		proxyURL = proxyconfig.GetProxyURL()
	}

	transport, err := proxyconfig.NewHTTPTransport()
	if err != nil {
		return nil, err
	}

	// Override with specific proxy if provided
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL %q: %w", proxyURL, err)
		}
		transport.Proxy = http.ProxyURL(u)
	}

	return &http.Client{Transport: transport, Timeout: timeout}, nil
}

/* ---------------- Optional: integrate with your compose loader ---------------- */

// ListComposeImages lists only images (ignores services with build:)
// so you can feed them into Compose2FC with UseDocker=false
func ListComposeImages(ctx context.Context, composePath string) ([]string, error) {
	opts, err := cli.NewProjectOptions(
		[]string{composePath},
		cli.WithWorkingDirectory(filepath.Dir(composePath)),
		cli.WithOsEnv,
	)
	if err != nil {
		return nil, err
	}
	proj, err := opts.LoadProject(ctx)
	if err != nil {
		return nil, err
	}
	var images []string
	for name, svc := range proj.Services {
		if strings.TrimSpace(svc.Image) == "" {
			continue
		}
		// normalize a bit
		img := svc.Image
		if !strings.Contains(img, "/") && !strings.Contains(img, ".") {
			img = "docker.io/library/" + addLatestIfMissing(img)
		} else if !strings.Contains(img, "@sha256:") && !strings.Contains(img, ":") {
			img = addLatestIfMissing(img)
		}
		_ = name
		images = append(images, img)
	}
	sort.Strings(images)
	return images, nil
}

func addLatestIfMissing(s string) string {
	if strings.Contains(s, "@sha256:") || strings.Contains(s, ":") {
		return s
	}
	return s + ":latest"
}

// SearchImages searches public registries and optionally saves results to a file
func SearchImages(query string, limit int, resultPath string) ([]ImageHit, error) {
	ctx := context.Background()

	hits, err := SearchPublicImages(ctx, query, SearchOptions{
		Limit:          limit,
		DockerHubToken: "", // optional
		QuayToken:      "", // optional
		GitLabToken:    "", // optional
	})
	if err != nil {
		return []ImageHit{}, err
	}

	if resultPath != "" {
		jsonBytes, _ := json.MarshalIndent(hits, "", "  ")
		_ = os.WriteFile(resultPath, jsonBytes, 0644)
	}

	return hits, nil
}
