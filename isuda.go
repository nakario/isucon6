package main

import (
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"net/http/pprof"
	"sort"

	"github.com/Songmu/strrand"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/unrolled/render"
	"github.com/newrelic/go-agent"
	"golang.org/x/sync/syncmap"
	"time"
)

const (
	sessionName   = "isuda_session"
	sessionSecret = "tonymoris"
	sleepTime = 2 * time.Second
)

var (
	isutarEndpoint string
	isupamEndpoint string

	baseUrl *url.URL
	db      *sql.DB
	re      *render.Render
	store   *sessions.CookieStore
	app		newrelic.Application

	errInvalidUser = errors.New("Invalid User")
	htmlCache = make(map[string]string)
	keywords = syncmap.Map{}
	insert = make(chan string, 0)
	del = make(chan string, 0)
	get = make(chan []string, 0)
)

func setName(w http.ResponseWriter, r *http.Request, txn newrelic.Transaction) error {
	session := getSession(w, r, txn)
	userID, ok := session.Values["user_id"]
	if !ok {
		return nil
	}
	setContext(r, "user_id", userID, txn)
	s := newrelic.DatastoreSegment{
		StartTime: txn.StartSegmentNow(),
		Product: newrelic.DatastoreMySQL,
		Collection: "user",
		Operation: "GET",
	}
	row := db.QueryRow(`SELECT name FROM user WHERE id = ?`, userID)
	user := User{}
	err := row.Scan(&user.Name)
	s.End()
	if err != nil {
		if err == sql.ErrNoRows {
			return errInvalidUser
		}
		panicIf(err)
	}
	setContext(r, "user_name", user.Name, txn)
	return nil
}

func authenticate(w http.ResponseWriter, r *http.Request, txn newrelic.Transaction) error {
	if u := getContext(r, "user_id", txn); u != nil {
		return nil
	}
	return errInvalidUser
}

func initializeHandler(w http.ResponseWriter, r *http.Request) {
	txn := app.StartTransaction("initializeHandler", w, r)
	defer txn.End()
	s := newrelic.DatastoreSegment{
		StartTime: txn.StartSegmentNow(),
		Product: newrelic.DatastoreMySQL,
		Collection: "entry",
		Operation: "DELETE",
	}
	_, err := db.Exec(`DELETE FROM entry WHERE id > 7101`)
	s.End()
	panicIf(err)

	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/initialize", isutarEndpoint), nil)
	s2 := newrelic.StartExternalSegment(txn, req)
	resp, err := http.DefaultClient.Do(req)
	s2.End()
	panicIf(err)
	defer resp.Body.Close()

	re.JSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func topHandler(w http.ResponseWriter, r *http.Request) {
	txn := app.StartTransaction("topHandler", w, r)
	defer txn.End()
	if err := setName(w, r, txn); err != nil {
		forbidden(w)
		return
	}

	perPage := 10
	p := r.URL.Query().Get("page")
	if p == "" {
		p = "1"
	}
	page, _ := strconv.Atoi(p)

	s := newrelic.DatastoreSegment{
		StartTime: txn.StartSegmentNow(),
		Product: newrelic.DatastoreMySQL,
		Collection: "entry",
		Operation: "SELECT",
	}
	rows, err := db.Query(fmt.Sprintf(
		"SELECT * FROM entry ORDER BY updated_at DESC LIMIT %d OFFSET %d",
		perPage, perPage*(page-1),
	))
	if err != nil && err != sql.ErrNoRows {
		s.End()
		panicIf(err)
	}
	entries := make([]*Entry, 0, 10)
	for rows.Next() {
		e := Entry{}
		err := rows.Scan(&e.ID, &e.AuthorID, &e.Keyword, &e.Description, &e.UpdatedAt, &e.CreatedAt)
		panicIf(err)
		e.Html = htmlify(w, r, e.Description, txn)
		e.Stars = loadStars(e.Keyword, txn)
		entries = append(entries, &e)
	}
	rows.Close()
	s.End()

	var totalEntries int
	s2 := newrelic.DatastoreSegment{
		StartTime: txn.StartSegmentNow(),
		Product: newrelic.DatastoreMySQL,
		Collection: "entry",
		Operation: "SELECT",
	}
	row := db.QueryRow(`SELECT COUNT(*) FROM entry`)
	err = row.Scan(&totalEntries)
	s2.End()
	if err != nil && err != sql.ErrNoRows {
		panicIf(err)
	}

	lastPage := int(math.Ceil(float64(totalEntries) / float64(perPage)))
	pages := make([]int, 0, 10)
	start := int(math.Max(float64(1), float64(page-5)))
	end := int(math.Min(float64(lastPage), float64(page+5)))
	for i := start; i <= end; i++ {
		pages = append(pages, i)
	}

	re.HTML(w, http.StatusOK, "index", struct {
		Context  context.Context
		Entries  []*Entry
		Page     int
		LastPage int
		Pages    []int
	}{
		r.Context(), entries, page, lastPage, pages,
	})
}

func robotsHandler(w http.ResponseWriter, r *http.Request) {
	txn := app.StartTransaction("robotsHandler", w, r)
	defer txn.End()
	notFound(w)
}

func keywordPostHandler(w http.ResponseWriter, r *http.Request) {
	txn := app.StartTransaction("keywordPostHandler", w, r)
	defer txn.End()
	if err := setName(w, r, txn); err != nil {
		forbidden(w)
		return
	}
	if err := authenticate(w, r, txn); err != nil {
		forbidden(w)
		return
	}

	keyword := r.FormValue("keyword")
	if keyword == "" {
		badRequest(w)
		return
	}
	userID := getContext(r, "user_id", txn).(int)
	description := r.FormValue("description")

	if isSpamContents(description, txn) || isSpamContents(keyword, txn) {
		log.Println("SPAM! kyeword:", keyword)
		http.Error(w, "SPAM!", http.StatusBadRequest)
		return
	}
	s := newrelic.DatastoreSegment{
		StartTime: txn.StartSegmentNow(),
		Product: newrelic.DatastoreMySQL,
		Collection: "entry",
		Operation: "INSERT",
	}
	_, err := db.Exec(`
		INSERT INTO entry (author_id, keyword, description, created_at, updated_at)
		VALUES (?, ?, ?, NOW(), NOW())
		ON DUPLICATE KEY UPDATE
		author_id = ?, keyword = ?, description = ?, updated_at = NOW()
	`, userID, keyword, description, userID, keyword, description)
	s.End()
	panicIf(err)
	log.Println("INSERT INTO entry", keyword)
	insert <- keyword
	keywords.Store(keyword, "isuda_" + fmt.Sprintf("%x", sha1.Sum([]byte(keyword))))
	http.Redirect(w, r, "/", http.StatusFound)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	txn := app.StartTransaction("loginHandler", w, r)
	defer txn.End()
	if err := setName(w, r, txn); err != nil {
		forbidden(w)
		return
	}

	re.HTML(w, http.StatusOK, "authenticate", struct {
		Context context.Context
		Action  string
	}{
		r.Context(), "login",
	})
}

func loginPostHandler(w http.ResponseWriter, r *http.Request) {
	txn := app.StartTransaction("loginPostHandler", w, r)
	defer txn.End()
	name := r.FormValue("name")
	s := newrelic.DatastoreSegment{
		StartTime: txn.StartSegmentNow(),
		Product: newrelic.DatastoreMySQL,
		Collection: "user",
		Operation: "SELECT",
	}
	row := db.QueryRow(`SELECT * FROM user WHERE name = ?`, name)
	user := User{}
	err := row.Scan(&user.ID, &user.Name, &user.Salt, &user.Password, &user.CreatedAt)
	s.End()
	if err == sql.ErrNoRows || user.Password != fmt.Sprintf("%x", sha1.Sum([]byte(user.Salt+r.FormValue("password")))) {
		forbidden(w)
		return
	}
	panicIf(err)
	session := getSession(w, r, txn)
	session.Values["user_id"] = user.ID
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	txn := app.StartTransaction("logoutHandler", w, r)
	defer txn.End()
	session := getSession(w, r, txn)
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	txn := app.StartTransaction("registerHandler", w, r)
	defer txn.End()
	if err := setName(w, r, txn); err != nil {
		forbidden(w)
		return
	}

	re.HTML(w, http.StatusOK, "authenticate", struct {
		Context context.Context
		Action  string
	}{
		r.Context(), "register",
	})
}

func registerPostHandler(w http.ResponseWriter, r *http.Request) {
	txn := app.StartTransaction("registerPostHandler", w, r)
	defer txn.End()
	name := r.FormValue("name")
	pw := r.FormValue("password")
	if name == "" || pw == "" {
		badRequest(w)
		return
	}
	userID := register(name, pw, txn)
	session := getSession(w, r, txn)
	session.Values["user_id"] = userID
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func register(user string, pass string, txn newrelic.Transaction) int64 {
	salt, err := strrand.RandomString(`....................`)
	panicIf(err)
	s := newrelic.DatastoreSegment{
		StartTime: txn.StartSegmentNow(),
		Product: newrelic.DatastoreMySQL,
		Collection: "user",
		Operation: "INSERT",
	}
	res, err := db.Exec(`INSERT INTO user (name, salt, password, created_at) VALUES (?, ?, ?, NOW())`,
		user, salt, fmt.Sprintf("%x", sha1.Sum([]byte(salt+pass))))
	s.End()
	panicIf(err)
	log.Println("INSERT INTO user", user)
	lastInsertID, _ := res.LastInsertId()
	return lastInsertID
}

func keywordByKeywordHandler(w http.ResponseWriter, r *http.Request) {
	txn := app.StartTransaction("keywordByKeywordHandler", w, r)
	defer txn.End()
	if err := setName(w, r, txn); err != nil {
		forbidden(w)
		return
	}

	keyword, err := url.PathUnescape(mux.Vars(r)["keyword"])
	panicIf(err)
	s := newrelic.DatastoreSegment{
		StartTime: txn.StartSegmentNow(),
		Product: newrelic.DatastoreMySQL,
		Collection: "entry",
		Operation: "SELECT",
	}
	row := db.QueryRow(`SELECT * FROM entry WHERE keyword = ?`, keyword)
	e := Entry{}
	err = row.Scan(&e.ID, &e.AuthorID, &e.Keyword, &e.Description, &e.UpdatedAt, &e.CreatedAt)
	s.End()
	if err == sql.ErrNoRows {
		notFound(w)
		return
	}
	e.Html = htmlify(w, r, e.Description, txn)
	e.Stars = loadStars(e.Keyword, txn)

	re.HTML(w, http.StatusOK, "keyword", struct {
		Context context.Context
		Entry   Entry
	}{
		r.Context(), e,
	})
}

func keywordByKeywordDeleteHandler(w http.ResponseWriter, r *http.Request) {
	txn := app.StartTransaction("keywordByKeywordDeleteHandler", w, r)
	defer txn.End()
	if err := setName(w, r, txn); err != nil {
		forbidden(w)
		return
	}
	if err := authenticate(w, r, txn); err != nil {
		forbidden(w)
		return
	}

	keyword, err := url.PathUnescape(mux.Vars(r)["keyword"])
	panicIf(err)
	if keyword == "" {
		badRequest(w)
		return
	}
	if r.FormValue("delete") == "" {
		badRequest(w)
		return
	}
	s := newrelic.DatastoreSegment{
		StartTime: txn.StartSegmentNow(),
		Product: newrelic.DatastoreMySQL,
		Collection: "entry",
		Operation: "SELECT",
	}
	row := db.QueryRow(`SELECT * FROM entry WHERE keyword = ?`, keyword)
	e := Entry{}
	err = row.Scan(&e.ID, &e.AuthorID, &e.Keyword, &e.Description, &e.UpdatedAt, &e.CreatedAt)
	s.End()
	if err == sql.ErrNoRows {
		notFound(w)
		return
	}
	s2 := newrelic.DatastoreSegment{
		StartTime: txn.StartSegmentNow(),
		Product: newrelic.DatastoreMySQL,
		Collection: "entry",
		Operation: "DELETE",
	}
	_, err = db.Exec(`DELETE FROM entry WHERE keyword = ?`, keyword)
	s2.End()
	panicIf(err)
	log.Println("DELETE FROM entry", keyword)
	del <- keyword
	keywords.Delete(keyword)
	http.Redirect(w, r, "/", http.StatusFound)
}

func htmlify(w http.ResponseWriter, r *http.Request, content string, txn newrelic.Transaction) string {
	if content == "" {
		return ""
	}

	kw2sha := make(map[string]string)
	keywords_slice := <- get
	keywords.Range(func(key, value interface{}) bool {
		key_s, _ := key.(string)
		kw2sha[key_s] = value.(string)
		return true
	})
	concat := strings.Join(keywords_slice, "/")
	tmp_content, ok := htmlCache[content + "/" + concat]
	if !ok {
		tmp_content = recursiveReplace(content, keywords_slice, func(kw string) string {
			return kw2sha[kw]
		})
		htmlCache[content + "/" + concat] = tmp_content
	}
	content = html.EscapeString(tmp_content)
	for kw, hash := range kw2sha {
		u := baseUrl.String()+"/keyword/" + pathURIEscape(kw)
		link := fmt.Sprintf("<a href=\"%s\">%s</a>", u, html.EscapeString(kw))
		content = strings.Replace(content, hash, link, -1)
	}
	return strings.Replace(content, "\n", "<br />\n", -1)
}

func recursiveReplace(source string, spliters []string, repl func(string)string) string {
	if len(spliters) == 0 {
		return source
	}
	parts := []string{}
	for _, part := range strings.Split(source, spliters[0]){
		parts = append(parts, recursiveReplace(part, spliters[1:], repl))
	}
	return strings.Join(parts, repl(spliters[0]))
}

func loadStars(keyword string, txn newrelic.Transaction) []*Star {
	v := url.Values{}
	v.Set("keyword", keyword)
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/stars", isutarEndpoint) + "?" + v.Encode(), nil)
	panicIf(err)
	s := newrelic.StartExternalSegment(txn, req)
	resp, err := http.DefaultClient.Do(req)
	s.End()
	panicIf(err)
	defer resp.Body.Close()

	var data struct {
		Result []*Star `json:result`
	}
	err = json.NewDecoder(resp.Body).Decode(&data)
	panicIf(err)
	return data.Result
}

func isSpamContents(content string, txn newrelic.Transaction) bool {
	v := url.Values{}
	v.Set("content", content)
	req, err := http.NewRequest(http.MethodPost, isupamEndpoint, nil)
	panicIf(err)
	req.PostForm = v
	s := newrelic.StartExternalSegment(txn, req)
	resp, err := http.PostForm(isupamEndpoint, v)
	s.End()
	panicIf(err)
	defer resp.Body.Close()

	var data struct {
		Valid bool `json:valid`
	}
	err = json.NewDecoder(resp.Body).Decode(&data)
	panicIf(err)
	return !data.Valid
}

func getContext(r *http.Request, key interface{}, txn newrelic.Transaction) interface{} {
	return r.Context().Value(key)
}

func setContext(r *http.Request, key, val interface{}, txn newrelic.Transaction) {
	if val == nil {
		return
	}

	r2 := r.WithContext(context.WithValue(r.Context(), key, val))
	*r = *r2
}

func getSession(w http.ResponseWriter, r *http.Request, txn newrelic.Transaction) *sessions.Session {
	session, _ := store.Get(r, sessionName)
	return session
}

func AttachProfiler(router *mux.Router) {
	router.HandleFunc("/debug/pprof/", pprof.Index)
	router.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	router.HandleFunc("/debug/pprof/profile", pprof.Profile)
	router.HandleFunc("/debug/pprof/symbol", pprof.Symbol)

	// Manually add support for paths linked to by index page at /debug/pprof/
	router.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	router.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	router.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))
	router.Handle("/debug/pprof/block", pprof.Handler("block"))
}

func sortedKeywords() {
	sorted := make([]string, 0, 500)
	keywords.Range(func(key, value interface{}) bool {
		key_s, _ := key.(string)
		sorted = append(sorted, key_s)
		return true
	})
	sort.Strings(sorted)
	sort.Slice(sorted, func(i, j int) bool {
		return len([]rune(sorted[i])) > len([]rune(sorted[j]))
	})
	for {
		select {
			case word := <- insert:
				sorted = append(sorted, word)
				sort.Strings(sorted)
				sort.Slice(sorted, func(i, j int) bool {
					return len([]rune(sorted[i])) > len([]rune(sorted[j]))
				})
			case word := <- del:
				index := -1
				for i, w := range sorted {
					if w == word {
						index = i
					}
				}
				if index >= 0 {
					sorted = append(sorted[:index], sorted[:index]...)
				}
			case get <- sorted:
		}
	}
}

func main() {
	host := os.Getenv("ISUDA_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	portstr := os.Getenv("ISUDA_DB_PORT")
	if portstr == "" {
		portstr = "3306"
	}
	port, err := strconv.Atoi(portstr)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUDA_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUDA_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUDA_DB_PASSWORD")
	dbname := os.Getenv("ISUDA_DB_NAME")
	if dbname == "" {
		dbname = "isuda"
	}

	db, err = sql.Open("mysql", fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?loc=Local&parseTime=true",
		user, password, host, port, dbname,
	))
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	db.Exec("SET SESSION sql_mode='TRADITIONAL,NO_AUTO_VALUE_ON_ZERO,ONLY_FULL_GROUP_BY'")
	db.Exec("SET NAMES utf8mb4")

	isutarEndpoint = os.Getenv("ISUTAR_ORIGIN")
	if isutarEndpoint == "" {
		isutarEndpoint = "http://localhost:5001"
	}
	isupamEndpoint = os.Getenv("ISUPAM_ORIGIN")
	if isupamEndpoint == "" {
		isupamEndpoint = "http://localhost:5050"
	}

	store = sessions.NewCookieStore([]byte(sessionSecret))

	re = render.New(render.Options{
		Directory: "views",
		Funcs: []template.FuncMap{
			{
				"url_for": func(path string) string {
					return baseUrl.String() + path
				},
				"title": func(s string) string {
					return strings.Title(s)
				},
				"raw": func(text string) template.HTML {
					return template.HTML(text)
				},
				"add": func(a, b int) int { return a + b },
				"sub": func(a, b int) int { return a - b },
				"entry_with_ctx": func(entry Entry, ctx context.Context) *EntryWithCtx {
					return &EntryWithCtx{Context: ctx, Entry: entry}
				},
			},
		},
	})

	rows, err := db.Query(`
		SELECT * FROM entry ORDER BY CHARACTER_LENGTH(keyword) DESC
	`)
	panicIf(err)
	entries := make([]*Entry, 0, 500)
	for rows.Next() {
		e := Entry{}
		err := rows.Scan(&e.ID, &e.AuthorID, &e.Keyword, &e.Description, &e.UpdatedAt, &e.CreatedAt)
		panicIf(err)
		entries = append(entries, &e)
	}
	rows.Close()
	for _, entry := range entries {
		keywords.Store(entry.Keyword, "isuda_" + fmt.Sprintf("%x", sha1.Sum([]byte(entry.Keyword))))
	}
	go sortedKeywords()

	cfg := newrelic.NewConfig("isuda", os.Getenv("NEW_RELIC_KEY"))
	cfg.Enabled = false
	app, err = newrelic.NewApplication(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to New Relic: %s.", err.Error())
	}

	r := mux.NewRouter()
	r.UseEncodedPath()
	AttachProfiler(r)
	r.HandleFunc("/", myHandler(topHandler))
	r.HandleFunc("/initialize", myHandler(initializeHandler)).Methods("GET")
	r.HandleFunc("/robots.txt", myHandler(robotsHandler))
	r.HandleFunc("/keyword", myHandler(keywordPostHandler)).Methods("POST")

	l := r.PathPrefix("/login").Subrouter()
	l.Methods("GET").HandlerFunc(myHandler(loginHandler))
	l.Methods("POST").HandlerFunc(myHandler(loginPostHandler))
	r.HandleFunc("/logout", myHandler(logoutHandler))

	g := r.PathPrefix("/register").Subrouter()
	g.Methods("GET").HandlerFunc(myHandler(registerHandler))
	g.Methods("POST").HandlerFunc(myHandler(registerPostHandler))

	k := r.PathPrefix("/keyword/{keyword}").Subrouter()
	k.Methods("GET").HandlerFunc(myHandler(keywordByKeywordHandler))
	k.Methods("POST").HandlerFunc(myHandler(keywordByKeywordDeleteHandler))

	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./public/")))
	log.Fatal(http.ListenAndServe(":5000", r))
}
