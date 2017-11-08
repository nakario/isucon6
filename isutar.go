package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"net/http/pprof"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/unrolled/render"
	"github.com/newrelic/go-agent"
)

var (
	baseUrl *url.URL
	db      *sql.DB
	re      *render.Render
)

func initializeHandler(w http.ResponseWriter, r *http.Request) {
	_, err := db.Exec("TRUNCATE star")
	panicIf(err)
	re.JSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func starsHandler(w http.ResponseWriter, r *http.Request) {
	keyword := r.FormValue("keyword")
	rows, err := db.Query(`SELECT * FROM star WHERE keyword = ?`, keyword)
	if err != nil && err != sql.ErrNoRows {
		panicIf(err)
		return
	}

	stars := make([]Star, 0, 10)
	for rows.Next() {
		s := Star{}
		err := rows.Scan(&s.ID, &s.Keyword, &s.UserName, &s.CreatedAt)
		panicIf(err)
		stars = append(stars, s)
	}
	rows.Close()

	re.JSON(w, http.StatusOK, map[string][]Star{
		"result": stars,
	})
}

func starsPostHandler(w http.ResponseWriter, r *http.Request) {
	keyword := r.FormValue("keyword")

	origin := os.Getenv("ISUDA_ORIGIN")
	if origin == "" {
		origin = "http://localhost:5000"
	}
	u, err := r.URL.Parse(fmt.Sprintf("%s/keyword/%s", origin, pathURIEscape(keyword)))
	panicIf(err)
	resp, err := http.Get(u.String())
	panicIf(err)
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		notFound(w)
		return
	}

	user := r.FormValue("user")
	_, err = db.Exec(`INSERT INTO star (keyword, user_name, created_at) VALUES (?, ?, NOW())`, keyword, user)
	panicIf(err)

	re.JSON(w, http.StatusOK, map[string]string{"result": "ok"})
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

func main() {
	host := os.Getenv("ISUTAR_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	portstr := os.Getenv("ISUTAR_DB_PORT")
	if portstr == "" {
		portstr = "3306"
	}
	port, err := strconv.Atoi(portstr)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUTAR_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUTAR_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUTAR_DB_PASSWORD")
	dbname := os.Getenv("ISUTAR_DB_NAME")
	if dbname == "" {
		dbname = "isutar"
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

	cfg := newrelic.NewConfig("isutar", os.Getenv("NEW_RELIC_KEY"))
	app, err := newrelic.NewApplication(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to New Relic: %s.", err.Error())
	}

	re = render.New(render.Options{Directory: "dummy"})

	r := mux.NewRouter()
	AttachProfiler(r)
	r.HandleFunc("/initialize", myHandler(app, "initializeHandler", initializeHandler))
	s := r.PathPrefix("/stars").Subrouter()
	s.Methods("GET").HandlerFunc(myHandler(app, "starsHandler", starsHandler))
	s.Methods("POST").HandlerFunc(myHandler(app, "starsPostHandler", starsPostHandler))

	log.Fatal(http.ListenAndServe(":5001", r))
}
