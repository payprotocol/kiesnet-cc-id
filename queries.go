// Copyright Key Inside Co., Ltd. 2018 All Rights Reserved.

package main

import "fmt"

// QueryNotRevokedCertificates _
/*
{
	"selector": {
		"@certificate": "%s",
		"revoke_time": {
			"$exists": false
		}
	},
	"use_index": ["certificate", "not-revoked"]
}
*/
const QueryNotRevokedCertificates = `{"selector":{"@certificate":"%s","revoke_time":{"$exists":false}},"use_index":["certificate","not-revoked"]}`

// CreateQueryNotRevokedCertificates _
func CreateQueryNotRevokedCertificates(kid string) string {
	return fmt.Sprintf(QueryNotRevokedCertificates, kid)
}

// QueryKIDByID _
/*
{
	"selector": {
		"@kid": "%s"
	},
	"limit": 1,
	"use_index": ["kid", "id"]
}
*/
const QueryKIDByID = `{"selector":{"@kid":"%s"},"limit":1,"use_index":["kid","id"]}`

// CreateQueryKIDByID _
func CreateQueryKIDByID(kid string) string {
	return fmt.Sprintf(QueryKIDByID, kid)
}
