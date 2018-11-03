// Copyright Key Inside Co., Ltd. 2018 All Rights Reserved.

package main

// QueryNotRevokedCertificates _
/*
{
	"selector": {
		"@certificate": "%s",
		"revoke_time": {
			"$exists": false
		}
	},
	"use_index": "certificate"
}
*/
const QueryNotRevokedCertificates = `{"selector":{"@certificate":"%s","revoke_time":{"$exists":false}},"use_index":"certificate"}`

// QueryKIDByID _
/*
{
	"selector": {
		"@kid": {
			"$exists": true
		},
		"id": "%s"
	},
	"limit": 1,
	"use_index": "kid"
}
*/
const QueryKIDByID = `{"selector":{"@kid":{"$exists":true},"id":"%s"},"limit":1,"use_index":"kid"}`
