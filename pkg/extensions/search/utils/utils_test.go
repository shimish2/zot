package utils_test

import (
	"os"
	"testing"

	"github.com/anuvu/zot/pkg/extensions/search/utils"
)

func TestUtil(t *testing.T) {
	db := utils.InitSearch("./testdata/db/Test.db")
	defer db.Close()

	if db == nil {
		t.Fatal("Unable to open db")
	}

	err := utils.GetNvdData("./testdata/", 2002, 2003, db)
	if err != nil {
		t.Fatal("Unable to Get the Data")
	}
}
func TestSearchCveId(t *testing.T) {
	db := utils.InitSearch("./testdata/db/Test.db")

	result := utils.SearchByCVEId(db, "CVE-1999-0001")
	if result == nil {
		t.Fatal("Not able to search CVEID")
	} else {
		if result.CveID != "CVE-1999-0001" {
			t.Fatal("Retrieved Incorrect CVEId")
		} else {
			//nolint : lll
			if result.VulDesc != "ip_input.c in BSD-derived TCP/IP implementations allows remote attackers to cause a denial of service (crash or hang) via crafted packets." {
				t.Fatal("Retrieved Incorrect Vulnerability Description")
			} else if len(result.VulDetails) == 0 {
				t.Fatal("Empty list of packages")
			}
		}
	}
	defer db.Close()
}

func TestSearchPkgVendor(t *testing.T) {
	db := utils.InitSearch("./testdata/db/Test.db")
	result := utils.SearchByPkgType("NvdPkgVendor", db, "freebsd")
	if result == nil {
		t.Fatal("Not able to search freebsd package vendor")
	} else if len(result) == 0 {
		t.Fatal("Empty list of CVEIDs")
	}
	defer db.Close()
}
func TestSearchPkgName(t *testing.T) {
	db := utils.InitSearch("./testdata/db/Test.db")
	result := utils.SearchByPkgType("NvdPkgName", db, "bsd_os")
	if result == nil {
		t.Fatal("Not able to search freebsd package vendor")
	} else if len(result) == 0 {
		t.Fatal("Empty list of CVEIDs")
	}
	defer db.Close()
}

func TestSearchPkgNameVer(t *testing.T) {
	db := utils.InitSearch("./testdata/db/Test.db")
	result := utils.SearchByPkgType("NvdPkgNameVer", db, "bsd_os3.1")
	if result == nil {
		t.Fatal("Not able to search freebsd package vendor")
	} else if len(result) == 0 {
		t.Fatal("Empty list of CVEIDs")
	}
	defer db.Close()
}

func TestRemoveData(t *testing.T) {
	err := os.Remove("./testdata/db/Test.db")
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
