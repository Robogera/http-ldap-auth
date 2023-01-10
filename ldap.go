package main

import (
	"fmt"
	"hash"
	"hash/fnv"
	"regexp"
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
	var username_regexp_filter *regexp.Regexp = regexp.MustCompile(`^[a-zA-Z0-9_-\.]{4,20}$`)
	var password_regexp_filter *regexp.Regexp = regexp.MustCompile(`^[a-zA-Z0-9_-!@#$%^\.]{4,20}$`)
	var ldap_con *ldap.Conn
	var search_result *ldap.SearchResult
	var ok bool
	var err error

	ok = username_regexp_filter.MatchString(username)
	if !ok {
		return "", fmt.Errorf("Invalid username: %s", username)
	}

	ok = password_regexp_filter.MatchString(password)
	if !ok {
		return "", fmt.Errorf("Invalid password")
	}

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
