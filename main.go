package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
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
		return "/project/{id}"
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
			tmpl, err = template.ParseFiles("templates/login.gohtml")
			if err != nil {
				http.Error(writer, "not found", http.StatusNotFound)
				log.Panicln("No template file found")
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

// the stuff that goes into pageMain template generation
type Project struct {
	Name       string
	Url        string
	LastChange string
}

type ProjectsList []*Project

type MainPageTemplateData struct {
	Projects ProjectsList
	Username string
}

func pageMain(synapse_objects *localRepo) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			http.Error(writer, "responds to GET requests only", http.StatusBadRequest)
		}

		var tmpl *template.Template
		var err error

		tmpl, err = template.ParseFiles("templates/main.gohtml")
		if err != nil {
			http.Error(writer, "not found", http.StatusNotFound)
			log.Panicln("No template file found")
		}

		// TODO: add a timer to localRepo and checkoutIfOlder() method
		// to prevent frequent checkouts
		err = synapse_objects.checkout(BRANCH, "main")
		if err != nil {
			http.Error(writer, "not found", http.StatusNotFound)
			log.Printf("Can't checkout main at synapse_objects repo. Error: %s", err)
		}

		var file_info []os.FileInfo
		file_info, err = synapse_objects.getSynapseObjects()
		if err != nil {
			log.Printf("Couldn't get a list of projects: %s", err)
		}

		var data *MainPageTemplateData
		// TODO: maybe pass session_storage to this handler
		// or read browser cookie (might be a bad idea)
		data.Username = "placeholder"
		data.Projects = make([]*Project, len(file_info))

		for i, folder := range file_info {
			data.Projects[i] = &Project{
				Name:       folder.Name(),
				LastChange: folder.ModTime().String(),
				// TODO: this is terrible, find some way to not hardcode the url
				Url: fmt.Sprint("/get/%s", folder.Name()),
			}
		}

		tmpl.Execute(writer, data)
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

	var synapse_engine, synapse_objects *localRepo

	synapse_engine, err = initizalizeLocalRepo(
		config.Settings.Engine.Url, config.Settings.Engine.User,
		config.Settings.Engine.Token, config.Settings.Local.Directory)
	if err != nil {
		log.Panicf("Error initializing synapse engine local repo: %s", err)
	}

	synapse_objects, err = initizalizeLocalRepo(
		config.Settings.Objects.Url, config.Settings.Objects.User,
		config.Settings.Objects.Token, config.Settings.Local.Directory)
	if err != nil {
		log.Panicf("Error initializing synapse objects local repo: %s", err)
	}

	var session_storage *SessionStorage = initSessionStorage(
		config.Settings.Web.CookieName,
		time.Minute*time.Duration(config.Settings.Web.SessionTimeout))

	var bot *LdapBot = initLdapBot(
		config.Settings.Ldap.Server, config.Settings.Ldap.Dn,
		config.Settings.Ldap.Password, config.Settings.Ldap.SearchBaseDn,
		config.Settings.Ldap.SearchBaseFilter)

	http.HandleFunc(LOGIN.String(), pageLogin(bot, session_storage))
	http.HandleFunc(MAIN.String(), authMiddleware(pageMain(synapse_objects), session_storage))
	// http.HandleFunc(DOWNLOADS.String(), authMiddleware(pageMain(), session_storage))
	// http.HandleFunc(PROJECT.String(), authMiddleware(pageProject(), session_storage))

	log.Printf("Starting web server on port %d", config.Settings.Web.Port)
	err = http.ListenAndServe(fmt.Sprintf(":%d", config.Settings.Web.Port), nil)
	if err != nil {
		log.Panicf("Http server stopped with fatal error: %s", err)
	}
}
