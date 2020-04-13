package utils_test

import (
	"os"
	"testing"

	"github.com/anuvu/zot/pkg/extensions/search/utils"
)

const filePath = "./testdata/db/Test.db"
const dbName = "NvdJSON"

func TestConn(t *testing.T) {
	db := utils.Conn(filePath)
	if db == nil {
		t.Fatal("Unable to open db")
	}
	defer db.Close()
}

func TestCreateDb(t *testing.T) {
	db := utils.Conn(filePath)
	if db == nil {
		t.Fatal("Unable to open db")
	}

	hasCreated := utils.CreateDB(dbName, db)
	if !hasCreated {
		t.Fatal("Unable to create bucket")
	}
	err := os.Remove("./testdata/db/Test.db")
	if err != nil {
		t.Fatal("Not able to remove Test Db file")
	}
	defer db.Close()
}
