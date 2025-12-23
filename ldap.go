package main

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

func ldapAuthenticate(username, password string) (*User, error) {
	user, _, err := ldapAuthenticateAccess(username, password)
	return user, err
}

func ldapAuthenticateAccess(username, password string) (*User, []Access, error) {
	conn, err := dialLDAP(ldapCfg)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	mail := username
	if !strings.Contains(username, "@") && ldapCfg.UserMailDomain != "" {
		domain := ldapCfg.UserMailDomain
		if !strings.HasPrefix(domain, "@") {
			domain = "@" + domain
		}
		mail = username + domain
	}

	// Bind as the user using only the mail/UPN form.
	bindIDs := []string{mail}

	var bindErr error
	for _, id := range bindIDs {
		if id == "" {
			continue
		}
		if err := conn.Bind(id, password); err == nil {
			bindErr = nil
			break
		} else {
			bindErr = err
		}
	}
	if bindErr != nil {
		return nil, nil, fmt.Errorf("ldap bind failed: %w", bindErr)
	}

	filter := fmt.Sprintf(ldapCfg.UserFilter, username)
	searchReq := ldap.NewSearchRequest(
		ldapCfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 1, 0, false,
		filter,
		nil,
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, nil, fmt.Errorf("ldap search: %w", err)
	}
	if len(sr.Entries) == 0 {
		return nil, nil, fmt.Errorf("user %s not found", mail)
	}

	entry := sr.Entries[0]

	groups := entry.GetAttributeValues(ldapCfg.GroupAttribute)
	access, user := accessFromGroups(username, groups, ldapCfg.GroupNamePrefix)
	if user == nil {
		return nil, nil, fmt.Errorf("no authorized groups for %s", username)
	}

	return user, access, nil
}

func dialLDAP(cfg LDAPConfig) (*ldap.Conn, error) {

	// #nosec G402 -- skip TLS verification if configured
	conn, err := ldap.DialURL(cfg.URL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify}))
	if err != nil {
		return nil, err
	}

	if cfg.StartTLS && strings.HasPrefix(cfg.URL, "ldap://") {
		// #nosec G402 -- skip TLS verification if configured
		if err := conn.StartTLS(&tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify}); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}

	return conn, nil
}

func accessFromGroups(username string, groups []string, prefix string) ([]Access, *User) {
	var selected *User
	var access []Access

	for _, g := range groups {
		groupName := groupNameFromDN(g)
		if prefix != "" && !strings.HasPrefix(groupName, prefix) {
			continue
		}

		ns, pullOnly, deleteAllowed, ok := permissionsFromGroup(groupName)
		if !ok {
			continue
		}

		access = append(access, Access{
			Group:         groupName,
			Namespace:     ns,
			PullOnly:      pullOnly,
			DeleteAllowed: deleteAllowed,
		})

		candidate := &User{
			Name:          username,
			Group:         groupName,
			Namespace:     ns,
			PullOnly:      pullOnly,
			DeleteAllowed: deleteAllowed,
		}

		if selected == nil || morePermissive(candidate, selected) {
			selected = candidate
		}
	}

	return access, selected
}

func groupNameFromDN(dn string) string {
	parts := strings.SplitN(dn, ",", 2)
	if len(parts) == 0 {
		return dn
	}

	first := strings.TrimSpace(parts[0])
	firstLower := strings.ToLower(first)

	switch {
	case strings.HasPrefix(firstLower, "cn="):
		return first[3:]
	case strings.HasPrefix(firstLower, "ou="):
		return first[3:]
	default:
		return dn
	}
}

func permissionsFromGroup(group string) (namespace string, pullOnly bool, deleteAllowed bool, ok bool) {
	switch {
	case strings.HasSuffix(group, "_rwd"):
		ns := strings.TrimSuffix(group, "_rwd")
		return ns, false, true, true
	case strings.HasSuffix(group, "_rw"):
		ns := strings.TrimSuffix(group, "_rw")
		return ns, false, false, true
	case strings.HasSuffix(group, "_rd"):
		ns := strings.TrimSuffix(group, "_rd")
		return ns, true, true, true
	case strings.HasSuffix(group, "_r"):
		ns := strings.TrimSuffix(group, "_r")
		return ns, true, false, true
	default:
		// Bare group name defaults to read/write without delete
		return group, false, false, true
	}
}

func morePermissive(a, b *User) bool {
	if a.DeleteAllowed != b.DeleteAllowed {
		return a.DeleteAllowed
	}
	if a.PullOnly != b.PullOnly {
		return !a.PullOnly
	}
	return false
}
