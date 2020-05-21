package cveinfo

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/internal/standalone"
	"github.com/anuvu/zot/internal/standalone/config"
	"github.com/anuvu/zot/pkg/log"

	"go.etcd.io/bbolt"
)

const (
	// NvdDB ...
	NvdDB = "NvdJSON"
	// VendorDB ...
	VendorDB = "NvdPkgVendor"
	// NameDB ...
	NameDB = "NvdPkgName"
	// NameverDB ...
	NameverDB = "NvdPkgNameVer"
	// NvdmetaDB ...
	NvdmetaDB = "NvdMeta"
)

/*Connect ... Create a database connection to. */
func (cve CveInfo) Connect(dbPath string, readOnly bool) *bbolt.DB {
	// Opening the connection on DB on given port
	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{ReadOnly: readOnly})
	if err != nil {
		cve.Log.Error().Err(err).Msg("Not able to open a database")
		return nil
	}

	return db
}

// UpdateCVEDb ...
func UpdateCVEDb(dbDir string, log log.Logger, interval time.Duration, readOnly bool) {
	config, err := config.NewDbConfig(dbDir)
	if err != nil {
		log.Error().Err(err).Msg("Unable to get config")
	}
	for {
		err = standalone.RunDb(config)
		if err != nil {
			log.Error().Err(err).Msg("Unable to update DB ")
		}

		time.Sleep(interval * time.Hour)
	}
}

// Close ...
// nolint:interfacer
func Close(db *bbolt.DB) error {
	err := db.Close()
	return err
}

// CreateBucket ...
func (cve CveInfo) CreateBucket(dbname string, db *bbolt.DB) bool {
	// Creating the bucket on already open DB
	uerr := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(dbname))
		if err != nil {
			cve.Log.Error().Err(err).Msg("Not able to create a bucket")

			return err
		}
		return nil
	})

	return uerr == nil
}

func (cve CveInfo) updateNVD(schemas []Schema, mapList []map[string][]CVEId, db *bbolt.DB) error {
	err := db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(NvdDB))

		for _, schema := range schemas {
			encoded, err := json.Marshal(schema)
			if err != nil {
				return err
			}

			err = b.Put([]byte(schema.CveID), encoded)
			if err != nil {
				return err
			}
		}
		return nil
	})

	uerr := cve.updateNVDPkg(VendorDB, mapList[0], db)
	if uerr != nil {
		cve.Log.Error().Err(uerr).Msg("Unable to Update Vendor Package Bucket")

		return uerr
	}

	uerr = cve.updateNVDPkg(NameDB, mapList[1], db)
	if uerr != nil {
		cve.Log.Error().Err(uerr).Msg("Unable to Update Name Package Bucket")

		return uerr
	}

	uerr = cve.updateNVDPkg(NameverDB, mapList[2], db)
	if uerr != nil {
		cve.Log.Error().Err(uerr).Msg("Unable to Update Name-Version Package Bucket")

		return uerr
	}

	return err
}

/*UpdateNVD ... Updating the NVD database. */
func (cve CveInfo) updateNVDPkg(name string, pkgList map[string][]CVEId, db *bbolt.DB) error {
	var dbcveidlist []CVEId

	err := db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(name))
		for pkg, cveidlist := range pkgList {
			v := b.Get([]byte(pkg))
			if v == nil {
				encode, err := json.Marshal(cveidlist)
				if err != nil {
					cve.Log.Error().Err(err).Msg("Unable to Marshal Data")

					return err
				}

				err = b.Put([]byte(pkg), encode)
				if err != nil {
					cve.Log.Error().Err(err).Msg("Unable to Insert Data from PkgVendor Bucket")

					return err
				}
			} else {
				err := json.Unmarshal(v, &dbcveidlist)
				if err != nil {
					cve.Log.Error().Err(err).Msg("Unable to Unmarshal Data from PkgVendor Bucket")

					return err
				}

				// Here we need to check if cveid is already added in our package
				cveidMap := map[string]struct{}{}

				for _, dbcveid := range dbcveidlist {
					cveidMap[dbcveid.Name] = struct{}{}
				}

				for _, cveid := range cveidlist {
					_, ok := cveidMap[cveid.Name]

					if !ok {
						dbcveidlist = append(dbcveidlist, cveid)
					}
				}

				encode, err := json.Marshal(dbcveidlist)
				if err != nil {
					cve.Log.Error().Err(err).Msg("Unable to marshal Data CveId List")

					return err
				}

				err = b.Put([]byte(pkg), encode)
				if err != nil {
					cve.Log.Error().Err(err).Msg("Unable to Insert Data from PkgVendor Bucket")

					return err
				}
			}
		}

		return nil
	})

	return err
}

/* Updating the NVD Meta Database. */
func (cve CveInfo) updateNVDMeta(filepath string, hashcode string, db *bbolt.DB) error {
	err := db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("NvdMeta"))

		err := b.Put([]byte(filepath), []byte(hashcode))
		if err != nil {
			cve.Log.Error().Err(err).Msg("Unable to Update Nvd Meta Data Bucket")

			return err
		}

		return nil
	})

	return err
}

// Method to check if file content is already present in DB.
func (cve CveInfo) isPresent(filename string, hashcode string, db *bbolt.DB) bool {
	var v []byte

	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(NvdmetaDB))

		v = b.Get([]byte(filename))

		return nil
	})
	if err != nil {
		cve.Log.Error().Err(err).Msg("Unable to Search Data on NvdMeta bucket")

		return false
	}

	if v == nil {
		return false
	}

	res := bytes.Compare(v, ([]byte)(hashcode))

	return res == 0
}

// QueryByCVEId ...
func (cve CveInfo) QueryByCVEId(db *bbolt.DB, key string) *Schema {
	var schema Schema

	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(NvdDB))

		v := b.Get([]byte(key))
		if v == nil {
			schema = Schema{}
		} else {
			err := json.Unmarshal(v, &schema)
			if err != nil {
				cve.Log.Error().Err(err).Msg("Unable to Unmarshal CveId Data")
				schema = Schema{}
			}
		}

		return nil
	})
	if err != nil {
		cve.Log.Error().Err(err).Msg("Unable to Search given CveId")
	}

	return &schema
}

// QueryByPkgType ...
func (cve CveInfo) QueryByPkgType(name string, db *bbolt.DB, key string) []CVEId {
	var cveidlist []CVEId

	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(name))
		if b != nil {
			v := b.Get([]byte(key))
			if v == nil {
				cveidlist = []CVEId{}
			} else {
				err := json.Unmarshal(v, &cveidlist)
				if err != nil {
					cve.Log.Error().Err(err).Msg("Unable to unmarshal given package")
					cveidlist = []CVEId{}
				}
			}
			return nil
		}
		cveidlist = []CVEId{}
		return errors.ErrInvalidBucket
	})
	if err != nil {
		cve.Log.Error().Err(err).Msg("Unable to search given package")
	}

	return cveidlist
}
