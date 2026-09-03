package main

import (
	"fmt"
	"html"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: cspnonce <header nonce> <HTML script nonce>")
		os.Exit(2)
	}

	headerNonce := os.Args[1]
	serializedScriptNonce := os.Args[2]
	decodedScriptNonce := html.UnescapeString(serializedScriptNonce)
	if headerNonce == "" || serializedScriptNonce == "" || headerNonce != decodedScriptNonce {
		fmt.Fprintln(os.Stderr, "CSP header nonce does not match the script nonce")
		os.Exit(1)
	}
}
