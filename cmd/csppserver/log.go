package main

import (
	"log"
	"os"
	"strings"
)

func init() {
	flags := log.LstdFlags | log.Lmicroseconds
	for _, f := range strings.Split(os.Getenv("LOGFLAGS"), ",") {
		switch f {
		case "longfile":
			flags |= log.Llongfile
		case "shortfile":
			flags |= log.Lshortfile
		case "UTC":
			flags |= log.LUTC
		case "nodatetime":
			flags &^= log.Ldate | log.Ltime | log.Lmicroseconds
		}
	}
	log.SetFlags(flags)
}
