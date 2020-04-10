package utils_test

import (
	"os"
	"testing"

	"github.com/anuvu/zot/pkg/extensions/search/utils"
)

func TestUtil(t *testing.T) {
	db := utils.InitSearch("./testdata/db/Test.db")
	if db == nil {
		t.Fatal("Unable to open db")
	}
	err := utils.GetNvdData("./testdata/", 2002, 2003, db)
	if err != nil {
		t.Fatal("Unable to Get the Data")
	}
	defer db.Close()
	err = os.Remove("./testdata/db/Test.db")
	if err != nil {
		t.Fatal("Not able to remove Test Db file")
	}
	err = os.Remove("./testdata/2002.json.zip")
	if err != nil {
		t.Fatal("Not able to remove Test Json Zip file")
	}
	err = os.Remove("./testdata/2002.meta")
	if err != nil {
		t.Fatal("Not able to remove Test Meta file")
	}
	err = os.Remove("./testdata/nvdcve-1.1-2002.json")
	if err != nil {
		t.Fatal("Not able to remove Test Json file")
	}

}
