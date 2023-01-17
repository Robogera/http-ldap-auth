package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sync"
	"time"
)

// user session datastruct
type Session struct {
	username       string
	expirationTime time.Time
}

// basic async map session storage and default session parameters
type SessionStorage struct {
	hashmap               map[string]*Session
	mux                   *sync.Mutex
	defaultCookieName     string        // name of the client browser cookie
	defaultSessionTimeout time.Duration // session ends after this much time of inactivity
}

func initSessionStorage(cookie_name string, timeout time.Duration) *SessionStorage {
	return &SessionStorage{
		hashmap:               map[string]*Session{},
		mux:                   new(sync.Mutex),
		defaultCookieName:     cookie_name,
		defaultSessionTimeout: timeout,
	}
}

// concurrently get map entry, returns error on non-existent key
func (session_storage *SessionStorage) get(key string) (*Session, error) {
	var session *Session
	var exists bool

	session_storage.mux.Lock()
	defer session_storage.mux.Unlock()

	session, exists = session_storage.hashmap[key]
	if !exists {
		return nil, fmt.Errorf("Key error: session %s does not exist", key)
	}

	return session, nil
}

// concurrently set map entry
func (session_storage *SessionStorage) set(key string, value *Session) {
	session_storage.mux.Lock()
	defer session_storage.mux.Unlock()

	session_storage.hashmap[key] = value
}

// concurrently delete map entry
func (session_storage *SessionStorage) delete(key string) {
	session_storage.mux.Lock()
	defer session_storage.mux.Unlock()

	delete(session_storage.hashmap, key)
}

// deletes opened sessions with expiration time before <time>
// returns slice of usernames from closed sessions
// TODO: run as a coroutine
func (session_storage *SessionStorage) cleanupOlder(time time.Time) []string {
	var result []string = []string{}
	session_storage.mux.Lock()
	defer session_storage.mux.Unlock()

	for key, value := range session_storage.hashmap {
		if value.expirationTime.Before(time) {
			result = append(result, value.username)
			delete(session_storage.hashmap, key)
		}
	}
	return result
}

type pageUrl int

const (
	MAIN pageUrl = iota
	LOGIN
	PROJECT
	DOWNLOADS
	FILE
	LOGOUT
)

func (page pageUrl) String() string {
	switch page {
	case MAIN:
		return "/"
	case LOGIN:
		return "/login"
	case PROJECT:
		return "/project/{}"
	case DOWNLOADS:
		return "/downloads"
	case FILE:
		return "/file/{name}"
	case LOGOUT:
		return "/logout"
	}
	return "/"
}

func authMiddleware(next http.HandlerFunc, session_storage *SessionStorage) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		var redirect_handler http.Handler = http.RedirectHandler(LOGIN.String(), http.StatusFound)
		var cookie *http.Cookie
		var session *Session
		var err error

		cookie, err = request.Cookie(session_storage.defaultCookieName)
		if err != nil {
			redirect_handler.ServeHTTP(writer, request)
			return
		}

		session, err = session_storage.get(cookie.Value)
		if err != nil {
			redirect_handler.ServeHTTP(writer, request)
			return
		}
		if session.expirationTime.Before(time.Now()) {
			session_storage.delete(cookie.Value)
			redirect_handler.ServeHTTP(writer, request)
			return
		}

		session.expirationTime = time.Now().Add(session_storage.defaultSessionTimeout)
		next(writer, request)
	}
}

func pageLogin(bot *LdapBot, session_storage *SessionStorage) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		var tmpl *template.Template
		var err error

		// on GET
		if request.Method != http.MethodPost {
			tmpl, err = template.ParseFiles("templates/login.html")
			if err != nil {
				http.Error(writer, "not found", http.StatusNotFound)
				log.Fatal("No template file found")
			}

			tmpl.Execute(writer, nil)
			return
		}

		// on POST
		err = request.ParseForm()
		if err != nil {
			log.Println("Form could not be processed")
			http.Redirect(writer, request, LOGIN.String(), http.StatusFound)
			return
		}

		var uuid string
		uuid, err = (*bot).authorizeUser(request.Form["username"][0], request.Form["password"][0])
		if err != nil {
			log.Printf("Error while authorizing user: %s\n", err)
			http.Redirect(writer, request, LOGIN.String(), http.StatusSeeOther)
			return
		}

		log.Printf("Logged in as: %s\n", request.Form["username"][0])

		session_storage.set(uuid, &Session{
			username:       request.Form["username"][0],
			expirationTime: time.Now().Add(session_storage.defaultSessionTimeout),
		})

		http.Redirect(writer, request, MAIN.String(), http.StatusFound)
	}
}

func pageMain() http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		// STUB
		http.Error(writer, "You have found an EASTER EGG", http.StatusNotFound)
	}
}

func pageProject() http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		// STUB
		http.Error(writer, "You have found an EASTER EGG", http.StatusNotFound)
	}
}

func pageDownload() http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		// STUB
		http.Error(writer, "You have found an EASTER EGG", http.StatusNotFound)
	}
}

func logout(session_storage *SessionStorage) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodDelete {
			http.Error(writer, "Accepts delete requests only", http.StatusBadRequest)
		}

		var cookie *http.Cookie
		var err error

		cookie, err = request.Cookie(session_storage.defaultCookieName)
		if err != nil {
			http.Error(writer, "not logged in", http.StatusForbidden)
			return
		}

		_, err = session_storage.get(cookie.Value)
		if err != nil {
			http.Error(writer, "not logged in", http.StatusForbidden)
			return
		}
		session_storage.delete(cookie.Value)
		http.Redirect(writer, request, MAIN.String(), http.StatusFound)
	}
}

func main() {
	var err error
	var config *Config

	config, err = readBuilderConfigFile("config.toml")
	if err != nil {
		log.Panicf("Couldnt read the config.toml file. Error: %s", err)
	}

	var session_storage *SessionStorage = initSessionStorage(
		config.Settings.Web.CookieName,
		time.Minute*time.Duration(config.Settings.Web.SessionTimeout))

	var bot *LdapBot = initLdapBot(
		config.Settings.Ldap.Server, config.Settings.Ldap.Dn,
		config.Settings.Ldap.Password, config.Settings.Ldap.SearchBaseDn,
		config.Settings.Ldap.SearchBaseFilter)

	http.HandleFunc(LOGIN.String(), pageLogin(bot, session_storage))
	http.HandleFunc(MAIN.String(), authMiddleware(pageMain(), session_storage))
	http.HandleFunc(DOWNLOADS.String(), authMiddleware(pageMain(), session_storage))
	http.HandleFunc(PROJECT.String(), authMiddleware(pageProject(), session_storage))

	log.Printf("Starting web server on port %d", config.Settings.Web.Port)
	err = http.ListenAndServe(fmt.Sprintf(":%d", config.Settings.Web.Port), nil)
	if err != nil {
		log.Panicf("Http server stopped with fatal error: %s", err)
	}
}
