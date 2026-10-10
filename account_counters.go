package main

import (
    "crypto/sha256"
    "encoding/json"
    "fmt"
)

// accountFailureKey scopes a failure streak to the declared authcid and
// directly connected peer IP. The hash avoids raw account names in Redis keys.
func accountFailureKey(username, ip string) string {
    data, _ := json.Marshal([]string{username, ip})
    return fmt.Sprintf("proxy:auth:failure:%x", sha256.Sum256(data))
}
