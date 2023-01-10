package main

import (
	"fmt"
	"hash"
	"hash/fnv"
	"html/template"
	"log"
	"net/http"
	"sync"
	"time"
	// external
	"github.com/go-ldap/ldap/v3"
)

// Ldap searcher bot credentials and persistent data
type LdapBot struct {
	server           string
	dn               string
	password         string
	searchBaseFilter string
	searchBaseDn     string
}

// opened session representation
type Session struct {
	username       string
	expirationTime time.Time
}

// basic async map session storage and default session parameters
type SessionStorage struct {
	hashmap               map[string]*Session
	mux                   *sync.Mutex
	defaultCookieName     string
	defaultSessionTimeout time.Duration
}

func initSessionStorage(cookie_name string, timeout time.Duration) *SessionStorage {
	return &SessionStorage{
		hashmap:               map[string]*Session{},
		mux:                   new(sync.Mutex),
		defaultCookieName:     cookie_name,
		defaultSessionTimeout: timeout,
	}
}

func (ses *SessionStorage) get(key string) (*Session, error) {
	var session *Session
	var exists bool

	ses.mux.Lock()
	defer ses.mux.Unlock()

	session, exists = ses.hashmap[key]
	if !exists {
		return nil, fmt.Errorf("Key error: session %s does not exist", key)
	}

	return session, nil
}

func (ses *SessionStorage) set(key string, value *Session) {
	ses.mux.Lock()
	defer ses.mux.Unlock()

	ses.hashmap[key] = value
}

func (ses *SessionStorage) delete(key string) {
	ses.mux.Lock()
	defer ses.mux.Unlock()

	delete(ses.hashmap, key)
}

func initLdapBot(server, dn, password, search_base_dn, search_base_filter string) *LdapBot {
	return &LdapBot{
		server:           server,
		dn:               dn,
		password:         password,
		searchBaseFilter: search_base_filter,
		searchBaseDn:     search_base_dn,
	}
}

// LDAP auth using the LdapSearcherBot
func (bot *LdapBot) authorizeUser(username, password string) (string, error) {
	var ldap_con *ldap.Conn
	var search_result *ldap.SearchResult
	var err error

	ldap_con, err = ldap.DialURL(bot.server)
	if err != nil {
		return "", fmt.Errorf("Could not connect to ldap server at: %s. Error: %s", bot.server, err)
	}
	defer ldap_con.Close()

	// Binding as a read-only bot
	err = ldap_con.Bind(bot.dn, bot.password)
	if err != nil {
		return "", fmt.Errorf("Invalid LDAP bot credentials, cant bind as %s", bot.dn)
	}

	// Searching for user with specified sAMAccountname
	search_result, err = ldap_con.Search(ldap.NewSearchRequest(
		bot.searchBaseDn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf(bot.searchBaseFilter, username),
		[]string{"dn", "cn"},
		nil))
	if err != nil {
		return "", fmt.Errorf("LDAP seach couldn't be performed: %s", err)
	} else if len(search_result.Entries) != 1 {
		return "", fmt.Errorf("User %s not found", username)
	}

	// Trying to authentificate user
	err = ldap_con.Bind(search_result.Entries[0].DN, password)
	if err != nil {
		return "", fmt.Errorf("Invalid password for user %s", username)
	}

	var uuid_hash hash.Hash32 = fnv.New32a()
	uuid_hash.Write([]byte(username + password))

	return fmt.Sprint(uuid_hash.Sum32()), nil
}

func authMiddleware(next http.HandlerFunc, session_storage *SessionStorage) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		var redirect_handler http.Handler = http.RedirectHandler("/login", http.StatusSeeOther)
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
			tmpl, err = template.ParseFiles("login.html")
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
			http.Redirect(writer, request, "/login", http.StatusSeeOther)
			return
		}

		var uuid string
		uuid, err = (*bot).authorizeUser(request.Form["username"][0], request.Form["password"][0])
		if err != nil {
			log.Printf("Error while authorizing user: %s\n", err)
			http.Redirect(writer, request, "/login", http.StatusSeeOther)
			return
		}

		log.Printf("Logged in as: %s\n", request.Form["username"][0])

		session_storage.set(uuid, &Session{
			username:       request.Form["username"][0],
			expirationTime: time.Now().Add(session_storage.defaultSessionTimeout),
		})

		http.Redirect(writer, request, "/", http.StatusSeeOther)
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

func main() {
	var err error
	var session_storage *SessionStorage = initSessionStorage("synapse_builder_session", time.Hour)
	var bot *LdapBot = initLdapBot(
		"", "",
		"", "",
		"")

	http.HandleFunc("/login", pageLogin(bot, session_storage))
	http.HandleFunc("/", authMiddleware(pageMain(), session_storage))
	http.HandleFunc("/download", authMiddleware(pageMain(), session_storage))
	http.HandleFunc("/project/{id}", authMiddleware(pageProject(), session_storage))

	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("Http server fatal error: ", err)
	}
}
