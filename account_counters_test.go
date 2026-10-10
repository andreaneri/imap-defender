package main

import "testing"

func TestAccountFailureKeyScope(t *testing.T) {
    base := accountFailureKey("alice", "192.0.2.1")
    if base == accountFailureKey("bob", "192.0.2.1") { t.Fatal("accounts share a key") }
    if base == accountFailureKey("alice", "192.0.2.2") { t.Fatal("sources share a key") }
    if base != accountFailureKey("alice", "192.0.2.1") { t.Fatal("key not stable") }
    if base == accountFailureKey("Alice", "192.0.2.1") { t.Fatal("username normalization changed") }
}
