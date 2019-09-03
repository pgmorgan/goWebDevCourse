package config

import (
	"fmt"

	_ "github.com/lib/pq"
	"gopkg.in/mgo.v2"
)

// database
var DB *mgo.Database

// collections
var Books *mgo.Collection

func init() {
	// get a mongo sessions
	//s, err := mgo.Dial("mongodb://bond:moneypenny007@localhost/bookstore")
	// s, err := mgo.Dial("mongodb://localhost/bookstore")
	s, err := mgo.Dial("mongodb://root:root@mycluster-a6bbr.mongodb.net:27017/test2?retryWrites=true&w=majority")
	if err != nil {
		panic(err)
	}

	if err = s.Ping(); err != nil {
		panic(err)
	}

	DB = s.DB("test")
	Books = DB.C("books")

	fmt.Println("You connected to your mongo database.")
}
