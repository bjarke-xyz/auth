package html

import (
	"embed"
	"html/template"
	"io"

	"firebase.google.com/go/v4/auth"
)

//go:embed pages/*.html
var files embed.FS

var (
	indexTemplate = parse("pages/index.html")
	adminTemplate = parse("pages/admin.html")
	userTemplate  = parse("pages/user.html")
)

type IndexParams struct {
	Title string
	Error string
}

func IndexPage(w io.Writer, p IndexParams) error {
	return indexTemplate.Execute(w, p)
}

type AdminParams struct {
	Title string
	Users []*auth.UserRecord
}

func AdminPage(w io.Writer, p AdminParams) error {
	return adminTemplate.Execute(w, p)
}

type UserParams struct {
	Title                string
	Error                string
	User                 *auth.UserRecord
	UserCustomClaimsJson string
}

func UserPage(w io.Writer, p UserParams) error {
	return userTemplate.Execute(w, p)
}

func parse(file string) *template.Template {
	return template.Must(
		template.New("layout.html").ParseFS(files, "pages/layout.html", file))
}
