package vuln

import (
	"fmt"
	"net/http"
	"strings"
)

// VulnerableHandler demonstrates a reflected XSS vulnerability.
// It takes user input and renders it directly in HTML without sanitization.
// THIS IS INTENTIONALLY VULNERABLE - for educational purposes only.
func VulnerableHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")

	// VULNERABLE: directly interpolating user input into HTML
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head><title>Delta XSS Demo - Vulnerable</title></head>
<body>
	<h1>Welcome, %s!</h1>
	<p>This page is intentionally vulnerable to XSS.</p>
	<form method="GET">
		<input name="name" value="%s" />
		<button type="submit">Submit</button>
	</form>
</body>
</html>`, name, name)

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// SecureHandler demonstrates the fixed version of the same endpoint.
// It sanitizes user input before rendering it in HTML.
func SecureHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")

	// SECURE: sanitize input before rendering
	safe := sanitize(name)

	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head><title>Delta XSS Demo - Secure</title></head>
<body>
	<h1>Welcome, %s!</h1>
	<p>This page is protected against XSS.</p>
	<form method="GET">
		<input name="name" value="%s" />
		<button type="submit">Submit</button>
	</form>
</body>
</html>`, safe, safe)

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// StoredVulnerableHandler demonstrates stored XSS.
// Comments are stored and rendered without sanitization.
var comments []string

func StoredVulnerableHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		comment := r.FormValue("comment")
		comments = append(comments, comment) // VULNERABLE: storing raw input
	}

	var commentHTML strings.Builder
	for _, c := range comments {
		commentHTML.WriteString(fmt.Sprintf("<div class='comment'>%s</div>", c))
	}

	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head><title>Delta XSS Demo - Stored</title></head>
<body>
	<h1>Comments (Stored XSS Demo)</h1>
	<form method="POST">
		<textarea name="comment" placeholder="Leave a comment..."></textarea>
		<button type="submit">Post</button>
	</form>
	<h2>Comments:</h2>
	%s
</body>
</html>`, commentHTML.String())

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

func sanitize(input string) string {
	// step 1: escape HTML entities
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
		"/", "&#47;",
		"(", "&#40;",
		")", "&#41;",
		"=", "&#61;",
	)
	return replacer.Replace(input)
}
