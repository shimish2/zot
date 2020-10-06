package storage

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/anuvu/zot/errors"
	zlog "github.com/anuvu/zot/pkg/log"
	apexlog "github.com/apex/log"
	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/umoci"
	"github.com/opencontainers/umoci/oci/casext"
	"github.com/rs/zerolog"
)

const (
	// BlobUploadDir defines the upload directory for blob uploads.
	BlobUploadDir = ".uploads"
	schemaVersion = 2
	gcDelay       = 1 * time.Hour
)

// BlobUpload models and upload request.
type BlobUpload struct {
	StoreName string
	ID        string
}

// ImageStore provides the image storage operations.
type ImageStore struct {
	rootDir     string
	lock        *sync.RWMutex
	blobUploads map[string]BlobUpload
	cache       *Cache
	gc          bool
	dedupe      bool
	log         zerolog.Logger
}

// NewImageStore returns a new image store backed by a file storage.
func NewImageStore(rootDir string, gc bool, dedupe bool, log zlog.Logger) *ImageStore {
	if _, err := os.Stat(rootDir); os.IsNotExist(err) {
		if err := os.MkdirAll(rootDir, 0700); err != nil {
			log.Error().Err(err).Str("rootDir", rootDir).Msg("unable to create root dir")
			return nil
		}
	}

	is := &ImageStore{
		rootDir:     rootDir,
		lock:        &sync.RWMutex{},
		blobUploads: make(map[string]BlobUpload),
		gc:          gc,
		dedupe:      dedupe,
		log:         log.With().Caller().Logger(),
	}

	if dedupe {
		is.cache = NewCache(rootDir, "cache", log)
	}

	if gc {
		// we use umoci GC to perform garbage-collection, but it uses its own logger
		// - so capture those logs, could be useful
		apexlog.SetLevel(apexlog.DebugLevel)
		apexlog.SetHandler(apexlog.HandlerFunc(func(entry *apexlog.Entry) error {
			e := log.Debug()
			for k, v := range entry.Fields {
				e = e.Interface(k, v)
			}
			e.Msg(entry.Message)
			return nil
		}))
	}

	return is
}

// RLock read-lock.
func (is *ImageStore) RLock() {
	is.lock.RLock()
}

// RUnlock read-unlock.
func (is *ImageStore) RUnlock() {
	is.lock.RUnlock()
}

// Lock write-lock.
func (is *ImageStore) Lock() {
	is.lock.Lock()
}

// Unlock write-unlock.
func (is *ImageStore) Unlock() {
	is.lock.Unlock()
}

// InitRepo creates an image repository under this store.
func (is *ImageStore) InitRepo(name string) error {
	repoDir := path.Join(is.rootDir, name)

	if fi, err := os.Stat(repoDir); err == nil && fi.IsDir() {
		return nil
	}

	// create "blobs" subdir
	ensureDir(path.Join(repoDir, "blobs"), is.log)
	// create BlobUploadDir subdir
	ensureDir(path.Join(repoDir, BlobUploadDir), is.log)

	// "oci-layout" file - create if it doesn't exist
	ilPath := path.Join(repoDir, ispec.ImageLayoutFile)
	if _, err := os.Stat(ilPath); err != nil {
		il := ispec.ImageLayout{Version: ispec.ImageLayoutVersion}
		buf, err := json.Marshal(il)

		if err != nil {
			is.log.Panic().Err(err).Msg("unable to marshal JSON")
		}

		if err := ioutil.WriteFile(ilPath, buf, 0644); err != nil { //nolint: gosec
			is.log.Error().Err(err).Str("file", ilPath).Msg("unable to write file")
			return err
		}
	}

	// "index.json" file - create if it doesn't exist
	indexPath := path.Join(repoDir, "index.json")
	if _, err := os.Stat(indexPath); err != nil {
		index := ispec.Index{}
		index.SchemaVersion = 2
		buf, err := json.Marshal(index)

		if err != nil {
			is.log.Panic().Err(err).Msg("unable to marshal JSON")
		}

		if err := ioutil.WriteFile(indexPath, buf, 0644); err != nil { //nolint: gosec
			is.log.Error().Err(err).Str("file", indexPath).Msg("unable to write file")
			return err
		}
	}

	return nil
}

// ValidateRepo validates that the repository layout is complaint with the OCI repo layout.
func (is *ImageStore) ValidateRepo(name string) (bool, error) {
	// https://github.com/opencontainers/image-spec/blob/master/image-layout.md#content
	// at least, expect at least 3 entries - ["blobs", "oci-layout", "index.json"]
	// and an additional/optional BlobUploadDir in each image store
	dir := path.Join(is.rootDir, name)
	if !dirExists(dir) {
		return false, errors.ErrRepoNotFound
	}

	files, err := ioutil.ReadDir(dir)
	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("unable to read directory")
		return false, errors.ErrRepoNotFound
	}
	// nolint:gomnd
	if len(files) < 3 {
		return false, errors.ErrRepoBadVersion
	}

	found := map[string]bool{
		"blobs":               false,
		ispec.ImageLayoutFile: false,
		"index.json":          false,
	}

	for _, file := range files {
		if file.Name() == "blobs" && !file.IsDir() {
			return false, nil
		}

		found[file.Name()] = true
	}

	for k, v := range found {
		if !v && k != BlobUploadDir {
			return false, nil
		}
	}

	buf, err := ioutil.ReadFile(path.Join(dir, ispec.ImageLayoutFile))
	if err != nil {
		return false, err
	}

	var il ispec.ImageLayout
	if err := json.Unmarshal(buf, &il); err != nil {
		return false, err
	}

	if il.Version != ispec.ImageLayoutVersion {
		return false, errors.ErrRepoBadVersion
	}

	return true, nil
}

// GetRepositories returns a list of all the repositories under this store.
func (is *ImageStore) GetRepositories() ([]string, error) {
	dir := is.rootDir

	is.log.Debug().Msg("acquiring read lock to read all repositories")

	is.RLock()
	defer is.RUnlock()

	_, err := ioutil.ReadDir(dir)
	if err != nil {
		is.log.Error().Err(err).Msg("failure walking storage root-dir")
		return nil, err
	}

	stores := make([]string, 0)
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(is.rootDir, path)
		if err != nil {
			return nil
		}

		if ok, err := is.ValidateRepo(rel); !ok || err != nil {
			return nil
		}

		//is.log.Debug().Str("dir", path).Str("name", info.Name()).Msg("found image store")
		stores = append(stores, rel)

		return nil
	})

	is.log.Debug().Msg("release read lock acquire to read all repositories")

	return stores, err
}

// GetImageTags returns a list of image tags available in the specified repository.
func (is *ImageStore) GetImageTags(repo string) ([]string, error) {
	dir := path.Join(is.rootDir, repo)
	if !dirExists(dir) {
		return nil, errors.ErrRepoNotFound
	}

	is.log.Debug().Str("image", repo).Int("goroutine id", goid()).Msg("Acquiring read lock for reading image tags")

	is.RLock()
	defer is.RUnlock()

	buf, err := ioutil.ReadFile(path.Join(dir, "index.json"))
	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")
		return nil, errors.ErrRepoNotFound
	}

	var index ispec.Index
	if err := json.Unmarshal(buf, &index); err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("invalid JSON")
		return nil, errors.ErrRepoNotFound
	}

	tags := make([]string, 0)

	for _, manifest := range index.Manifests {
		v, ok := manifest.Annotations[ispec.AnnotationRefName]
		if ok {
			tags = append(tags, v)
		}
	}

	is.log.Debug().Msg("Releasing read lock that is acquired for reading image tags")

	return tags, nil
}

// GetImageManifest returns the image manifest of an image in the specific repository.
func (is *ImageStore) GetImageManifest(repo string, reference string) ([]byte, string, string, error) {
	dir := path.Join(is.rootDir, repo)
	if !dirExists(dir) {
		return nil, "", "", errors.ErrRepoNotFound
	}

	is.log.Debug().Str("image", repo).Int("goroutine id", goid()).Msg("Acquiring read lock for reading image manifests")

	is.RLock()
	defer is.RUnlock()

	buf, err := ioutil.ReadFile(path.Join(dir, "index.json"))

	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")

		if os.IsNotExist(err) {
			return nil, "", "", errors.ErrRepoNotFound
		}

		return nil, "", "", err
	}

	var index ispec.Index
	if err := json.Unmarshal(buf, &index); err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("invalid JSON")
		return nil, "", "", err
	}

	found := false

	var digest godigest.Digest

	mediaType := ""

	for _, m := range index.Manifests {
		if reference == m.Digest.String() {
			digest = m.Digest
			mediaType = m.MediaType
			found = true

			break
		}

		v, ok := m.Annotations[ispec.AnnotationRefName]
		if ok && v == reference {
			digest = m.Digest
			mediaType = m.MediaType
			found = true

			break
		}
	}

	if !found {
		return nil, "", "", errors.ErrManifestNotFound
	}

	p := path.Join(dir, "blobs", digest.Algorithm().String(), digest.Encoded())

	buf, err = ioutil.ReadFile(p)

	if err != nil {
		is.log.Error().Err(err).Str("blob", p).Msg("failed to read manifest")

		if os.IsNotExist(err) {
			return nil, "", "", errors.ErrManifestNotFound
		}

		return nil, "", "", err
	}

	var manifest ispec.Manifest
	if err := json.Unmarshal(buf, &manifest); err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("invalid JSON")
		return nil, "", "", err
	}

	is.log.Debug().Str("image", repo).Msg("Releasing read lock that is acquired for reading image manifest")

	return buf, digest.String(), mediaType, nil
}

// PutImageManifest adds an image manifest to the repository.
func (is *ImageStore) PutImageManifest(repo string, reference string, mediaType string,
	body []byte) (string, error) {
	is.log.Debug().Str("image", repo).Int("goroutine id", goid()).Msg("Acquiring lock for putting image manifest")

	is.Lock()
	defer is.Unlock()

	if err := is.InitRepo(repo); err != nil {
		is.log.Debug().Err(err).Msg("init repo")
		return "", err
	}

	if mediaType != ispec.MediaTypeImageManifest {
		is.log.Debug().Interface("actual", mediaType).
			Interface("expected", ispec.MediaTypeImageManifest).Msg("bad manifest media type")
		return "", errors.ErrBadManifest
	}

	if len(body) == 0 {
		is.log.Debug().Int("len", len(body)).Msg("invalid body length")
		return "", errors.ErrBadManifest
	}

	var m ispec.Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		is.log.Error().Err(err).Msg("unable to unmarshal JSON")
		return "", errors.ErrBadManifest
	}

	if m.SchemaVersion != schemaVersion {
		is.log.Error().Int("SchemaVersion", m.SchemaVersion).Msg("invalid manifest")
		return "", errors.ErrBadManifest
	}

	for _, l := range m.Layers {
		digest := l.Digest
		blobPath := is.BlobPath(repo, digest)
		is.log.Info().Str("blobPath", blobPath).Str("reference", reference).Msg("manifest layers")

		if _, err := os.Stat(blobPath); err != nil {
			is.log.Error().Err(err).Str("blobPath", blobPath).Msg("unable to find blob")
			return digest.String(), errors.ErrBlobNotFound
		}
	}

	mDigest := godigest.FromBytes(body)
	refIsDigest := false
	d, err := godigest.Parse(reference)

	if err == nil {
		if d.String() != mDigest.String() {
			is.log.Error().Str("actual", mDigest.String()).Str("expected", d.String()).
				Msg("manifest digest is not valid")
			return "", errors.ErrBadManifest
		}

		refIsDigest = true
	}

	dir := path.Join(is.rootDir, repo)
	buf, err := ioutil.ReadFile(path.Join(dir, "index.json"))

	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")
		return "", err
	}

	var index ispec.Index
	if err := json.Unmarshal(buf, &index); err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("invalid JSON")
		return "", errors.ErrRepoBadVersion
	}

	updateIndex := true
	// create a new descriptor
	desc := ispec.Descriptor{MediaType: mediaType, Size: int64(len(body)), Digest: mDigest,
		Platform: &ispec.Platform{Architecture: "amd64", OS: "linux"}}
	if !refIsDigest {
		desc.Annotations = map[string]string{ispec.AnnotationRefName: reference}
	}

	for i, m := range index.Manifests {
		if reference == m.Digest.String() {
			// nothing changed, so don't update
			desc = m
			updateIndex = false

			break
		}

		v, ok := m.Annotations[ispec.AnnotationRefName]
		if ok && v == reference {
			if m.Digest.String() == mDigest.String() {
				// nothing changed, so don't update
				desc = m
				updateIndex = false

				break
			}
			// manifest contents have changed for the same tag,
			// so update index.json descriptor
			is.log.Info().
				Int64("old size", desc.Size).
				Int64("new size", int64(len(body))).
				Str("old digest", desc.Digest.String()).
				Str("new digest", mDigest.String()).
				Msg("updating existing tag with new manifest contents")

			desc = m
			desc.Size = int64(len(body))
			desc.Digest = mDigest

			index.Manifests = append(index.Manifests[:i], index.Manifests[i+1:]...)

			break
		}
	}

	if !updateIndex {
		return desc.Digest.String(), nil
	}

	// write manifest to "blobs"
	dir = path.Join(is.rootDir, repo, "blobs", mDigest.Algorithm().String())
	ensureDir(dir, is.log)
	file := path.Join(dir, mDigest.Encoded())

	if err := ioutil.WriteFile(file, body, 0600); err != nil {
		is.log.Error().Err(err).Str("file", file).Msg("unable to write")
		return "", err
	}

	// now update "index.json"
	index.Manifests = append(index.Manifests, desc)
	dir = path.Join(is.rootDir, repo)
	file = path.Join(dir, "index.json")
	buf, err = json.Marshal(index)

	if err != nil {
		is.log.Error().Err(err).Str("file", file).Msg("unable to marshal JSON")
		return "", err
	}

	if err := ioutil.WriteFile(file, buf, 0644); err != nil { //nolint: gosec
		is.log.Error().Err(err).Str("file", file).Msg("unable to write")
		return "", err
	}

	if is.gc {
		oci, err := umoci.OpenLayout(dir)
		if err != nil {
			return "", err
		}
		defer oci.Close()

		if err := oci.GC(context.Background(), ifOlderThan(is, repo, gcDelay)); err != nil {
			return "", err
		}
	}

	is.log.Debug().Str("image", repo).Msg("Release write lock that is acquired for putting image manifest")

	return desc.Digest.String(), nil
}

// DeleteImageManifest deletes the image manifest from the repository.
func (is *ImageStore) DeleteImageManifest(repo string, reference string) error {
	dir := path.Join(is.rootDir, repo)
	if !dirExists(dir) {
		return errors.ErrRepoNotFound
	}

	is.log.Debug().Str("image", repo).Int("goroutine id", goid()).Msg("Acquiring write lock for deleting image manifest")

	is.Lock()
	defer is.Unlock()

	// as per spec "reference" can only be a digest and not a tag
	digest, err := godigest.Parse(reference)
	if err != nil {
		is.log.Error().Err(err).Msg("invalid reference")
		return errors.ErrBadManifest
	}

	buf, err := ioutil.ReadFile(path.Join(dir, "index.json"))

	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")
		return err
	}

	var index ispec.Index
	if err := json.Unmarshal(buf, &index); err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("invalid JSON")
		return err
	}

	found := false

	var m ispec.Descriptor

	// we are deleting, so keep only those manifests that don't match
	outIndex := index
	outIndex.Manifests = []ispec.Descriptor{}

	for _, m = range index.Manifests {
		if reference == m.Digest.String() {
			found = true
			continue
		}

		outIndex.Manifests = append(outIndex.Manifests, m)
	}

	if !found {
		return errors.ErrManifestNotFound
	}

	// now update "index.json"
	dir = path.Join(is.rootDir, repo)
	file := path.Join(dir, "index.json")
	buf, err = json.Marshal(outIndex)

	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(file, buf, 0644); err != nil { //nolint: gosec
		return err
	}

	if is.gc {
		oci, err := umoci.OpenLayout(dir)
		if err != nil {
			return err
		}
		defer oci.Close()

		if err := oci.GC(context.Background(), ifOlderThan(is, repo, gcDelay)); err != nil {
			return err
		}
	}

	p := path.Join(dir, "blobs", digest.Algorithm().String(), digest.Encoded())

	_ = os.Remove(p)

	is.log.Debug().Str("image", repo).Msg("Releasing write lock for deleting image manifests")

	return nil
}

// BlobUploadPath returns the upload path for a blob in this store.
func (is *ImageStore) BlobUploadPath(repo string, uuid string) string {
	dir := path.Join(is.rootDir, repo)
	blobUploadPath := path.Join(dir, BlobUploadDir, uuid)

	return blobUploadPath
}

// NewBlobUpload returns the unique ID for an upload in progress.
func (is *ImageStore) NewBlobUpload(repo string) (string, error) {
	is.log.Debug().Str("image", repo).Int("goroutine id", goid()).Msg("Acquiring write lock at new blob upload")
	is.Lock()

	if err := is.InitRepo(repo); err != nil {
		is.log.Debug().Str("image", repo).Int("goroutine id", goid()).Msg("Error initializing repo, releasing acquired write lock at new blob upload")
		is.Unlock()
		return "", err
	}

	is.Unlock()

	is.log.Debug().Str("image", repo).Msg("Releasing write lock acquired at new blob upload")

	uuid, err := guuid.NewV4()
	if err != nil {
		return "", err
	}

	u := uuid.String()
	blobUploadPath := is.BlobUploadPath(repo, u)
	file, err := os.OpenFile(blobUploadPath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0600)

	if err != nil {
		return "", errors.ErrRepoNotFound
	}
	defer file.Close()

	return u, nil
}

// GetBlobUpload returns the current size of a blob upload.
func (is *ImageStore) GetBlobUpload(repo string, uuid string) (int64, error) {
	blobUploadPath := is.BlobUploadPath(repo, uuid)
	fi, err := os.Stat(blobUploadPath)

	if err != nil {
		if os.IsNotExist(err) {
			return -1, errors.ErrUploadNotFound
		}

		return -1, err
	}

	return fi.Size(), nil
}

// PutBlobChunkStreamed appends another chunk of data to the specified blob. It returns
// the number of actual bytes to the blob.
func (is *ImageStore) PutBlobChunkStreamed(repo string, uuid string, body io.Reader) (int64, error) {
	is.log.Debug().Str("image", repo).Int("goroutine id", goid()).Msg("Acquiring write lock on init repo while running put blob chunk streamed method")
	is.Lock()

	if err := is.InitRepo(repo); err != nil {
		is.log.Debug().Str("image", repo).Msg("Error initializing repo, releasing acquired write lock at put blob chunk streamed upload")
		is.Unlock()
		return -1, err
	}

	is.Unlock()

	is.log.Debug().Str("image", repo).Int("goroutine id", goid()).Msg("Releasing write lock on init repo while running put blob chunk streamed method")

	blobUploadPath := is.BlobUploadPath(repo, uuid)

	_, err := os.Stat(blobUploadPath)
	if err != nil {
		return -1, errors.ErrUploadNotFound
	}

	file, err := os.OpenFile(
		blobUploadPath,
		os.O_WRONLY|os.O_CREATE,
		0600,
	)
	if err != nil {
		is.log.Fatal().Err(err).Msg("failed to open file")
	}
	defer file.Close()

	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		is.log.Fatal().Err(err).Msg("failed to seek file")
	}

	goroutineID := goid()

	is.log.Debug().Str("image", repo).Int("Goroutine id for put blob chunk streamed method", goroutineID).Msg("")

	n, err := io.Copy(file, body)
	if err != nil {
		is.log.Error().Err(err).Str("image", repo).Int("goroutine id", goid()).Str("file", blobUploadPath).Msg("put blob chunk streamed method")
	}

	return n, err
}

// PutBlobChunk writes another chunk of data to the specified blob. It returns
// the number of actual bytes to the blob.
func (is *ImageStore) PutBlobChunk(repo string, uuid string, from int64, to int64,
	body io.Reader) (int64, error) {
	is.log.Debug().Str("image", repo).Int("goroutine id", goid()).Msg("Acquiring write lock for putting blob chunk method")
	is.Lock()

	if err := is.InitRepo(repo); err != nil {
		is.log.Debug().Str("image", repo).Msg("Error initializing repo, releasing acquired write lock at put blob chunk upload")
		is.Unlock()
		return -1, err
	}

	is.Unlock()

	is.log.Debug().Str("image", repo).Int("goroutine id", goid()).Msg("Releasing write lock for putting blob chunk method")

	blobUploadPath := is.BlobUploadPath(repo, uuid)

	fi, err := os.Stat(blobUploadPath)
	if err != nil {
		return -1, errors.ErrUploadNotFound
	}

	if from != fi.Size() {
		is.log.Error().Int64("expected", from).Int64("actual", fi.Size()).
			Msg("invalid range start for blob upload")
		return -1, errors.ErrBadUploadRange
	}

	file, err := os.OpenFile(
		blobUploadPath,
		os.O_WRONLY|os.O_CREATE,
		0600,
	)
	if err != nil {
		is.log.Fatal().Err(err).Msg("failed to open file")
	}
	defer file.Close()

	if _, err := file.Seek(from, io.SeekStart); err != nil {
		is.log.Fatal().Err(err).Msg("failed to seek file")
	}

	goroutineId := goid()

	is.log.Debug().Str("image", repo).Int("goroutineid for put blob chunk", goroutineId).Msg("")

	n, err := io.Copy(file, body)
	if err != nil {
		is.log.Error().Err(err).Str("image", repo).Str("file", blobUploadPath).Msg("put blob chunk streamed method")
	}

	return n, err
}

// BlobUploadInfo returns the current blob size in bytes.
func (is *ImageStore) BlobUploadInfo(repo string, uuid string) (int64, error) {
	blobUploadPath := is.BlobUploadPath(repo, uuid)
	fi, err := os.Stat(blobUploadPath)

	if err != nil {
		is.log.Error().Err(err).Str("blob", blobUploadPath).Msg("failed to stat blob")
		return -1, err
	}

	size := fi.Size()

	return size, nil
}

// FinishBlobUpload finalizes the blob upload and moves blob the repository.
func (is *ImageStore) FinishBlobUpload(repo string, uuid string, body io.Reader, digest string) error {
	dstDigest, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")
		return errors.ErrBadBlobDigest
	}

	src := is.BlobUploadPath(repo, uuid)

	_, err = os.Stat(src)
	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to stat blob")
		return errors.ErrUploadNotFound
	}

	f, err := os.Open(src)
	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to open blob")
		return errors.ErrUploadNotFound
	}

	srcDigest, err := godigest.FromReader(f)
	f.Close()

	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to open blob")
		return errors.ErrBadBlobDigest
	}

	if srcDigest != dstDigest {
		is.log.Error().Str("srcDigest", srcDigest.String()).
			Str("dstDigest", dstDigest.String()).Msg("actual digest not equal to expected digest")
		return errors.ErrBadBlobDigest
	}

	dir := path.Join(is.rootDir, repo, "blobs", dstDigest.Algorithm().String())

	is.log.Debug().Str("image", repo).Int("goroutine id", goid()).Msg("Acquiring write lock for finishing blob upload")

	is.Lock()
	is.log.Debug().Str("image", repo).Int("goroutine id", goid()).Msg("Acquired write lock for finishing blob upload")
	defer is.Unlock()

	ensureDir(dir, is.log)
	dst := is.BlobPath(repo, dstDigest)

	if is.dedupe && is.cache != nil {
		if err := is.DedupeBlob(src, dstDigest, dst); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
				Str("dst", dst).Msg("unable to dedupe blob")
			return err
		}
	} else {
		if err := os.Rename(src, dst); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
				Str("dst", dst).Msg("unable to finish blob")
			return err
		}
	}

	is.log.Debug().Str("image", repo).Int("goroutine id", goid()).Msg("Releasing write lock that is acquired for finishing blob upload")

	return nil
}

// FullBlobUpload handles a full blob upload, and no partial session is created.
func (is *ImageStore) FullBlobUpload(repo string, body io.Reader, digest string) (string, int64, error) {
	is.log.Debug().Str("image", repo).Int("goroutine id", goid()).Msg("Acquiring write lock for full blob upload init repo call")
	is.Lock()

	if err := is.InitRepo(repo); err != nil {
		is.log.Debug().Str("image", repo).Msg("Error initializing repo, releasing acquired write lock during full blob upload")
		is.Unlock()
		return "", -1, err
	}

	is.Unlock()

	is.log.Debug().Str("image", repo).Int("goroutine id", goid()).Msg("Release lock for full blob upload init repo call")

	dstDigest, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")
		return "", -1, errors.ErrBadBlobDigest
	}

	u, err := guuid.NewV4()
	if err != nil {
		return "", -1, err
	}

	uuid := u.String()

	src := is.BlobUploadPath(repo, uuid)

	f, err := os.Create(src)
	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to open blob")
		return "", -1, errors.ErrUploadNotFound
	}

	defer f.Close()

	digester := sha256.New()
	mw := io.MultiWriter(f, digester)
	n, err := io.Copy(mw, body)

	if err != nil {
		return "", -1, err
	}

	srcDigest := godigest.NewDigestFromEncoded(godigest.SHA256, fmt.Sprintf("%x", digester.Sum(nil)))
	if srcDigest != dstDigest {
		is.log.Error().Str("srcDigest", srcDigest.String()).
			Str("dstDigest", dstDigest.String()).Msg("actual digest not equal to expected digest")
		return "", -1, errors.ErrBadBlobDigest
	}

	dir := path.Join(is.rootDir, repo, "blobs", dstDigest.Algorithm().String())

	is.log.Debug().Str("image", repo).Int("goroutine id", goid()).Msg("Acquiring write lock for full blob upload")
	is.Lock()
	is.log.Debug().Str("image", repo).Int("goroutine id", goid()).Msg("Acquired write lock for full blob upload")
	defer is.Unlock()

	ensureDir(dir, is.log)
	dst := is.BlobPath(repo, dstDigest)

	if is.dedupe && is.cache != nil {
		if err := is.DedupeBlob(src, dstDigest, dst); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
				Str("dst", dst).Msg("unable to dedupe blob")
			return "", -1, err
		}
	} else {
		if err := os.Rename(src, dst); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
				Str("dst", dst).Msg("unable to finish blob")
			return "", -1, err
		}
	}

	is.log.Debug().Str("image", repo).Msg("Release write lock for acquiring full blob upload")

	return uuid, n, nil
}

// nolint:interfacer
func (is *ImageStore) DedupeBlob(src string, dstDigest godigest.Digest, dst string) error {
retry:
	is.log.Debug().Str("src", src).Str("dstDigest", dstDigest.String()).Str("dst", dst).Msg("dedupe: ENTER")

	dstRecord, err := is.cache.GetBlob(dstDigest.String())

	// nolint:goerr113
	if err != nil && err != errors.ErrCacheMiss {
		is.log.Error().Err(err).Str("blobPath", dst).Msg("dedupe: unable to lookup blob record")
		return err
	}

	if dstRecord == "" {
		if err := is.cache.PutBlob(dstDigest.String(), dst); err != nil {
			is.log.Error().Err(err).Str("blobPath", dst).Msg("dedupe: unable to insert blob record")

			return err
		}

		// move the blob from uploads to final dest
		if err := os.Rename(src, dst); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("dst", dst).Msg("dedupe: unable to rename blob")

			return err
		}

		is.log.Debug().Str("src", src).Str("dst", dst).Msg("dedupe: rename")
	} else {
		dstRecord = path.Join(is.rootDir, dstRecord)

		dstRecordFi, err := os.Stat(dstRecord)
		if err != nil {
			is.log.Error().Err(err).Str("blobPath", dstRecord).Msg("dedupe: unable to stat")
			// the actual blob on disk may have been removed by GC, so sync the cache
			if err := is.cache.DeleteBlob(dstDigest.String(), dstRecord); err != nil {
				// nolint:lll
				is.log.Error().Err(err).Str("dstDigest", dstDigest.String()).Str("dst", dst).Msg("dedupe: unable to delete blob record")

				return err
			}
			goto retry
		}
		dstFi, err := os.Stat(dst)
		if err != nil && !os.IsNotExist(err) {
			is.log.Error().Err(err).Str("blobPath", dstRecord).Msg("dedupe: unable to stat")

			return err
		}
		if !os.SameFile(dstFi, dstRecordFi) {
			if err := os.Link(dstRecord, dst); err != nil {
				is.log.Error().Err(err).Str("blobPath", dst).Str("link", dstRecord).Msg("dedupe: unable to hard link")

				return err
			}
		}
		if err := os.Remove(src); err != nil {
			is.log.Error().Err(err).Str("src", src).Msg("dedupe: uname to remove blob")
			return err
		}
		is.log.Debug().Str("src", src).Msg("dedupe: remove")
	}

	return nil
}

// DeleteBlobUpload deletes an existing blob upload that is currently in progress.
func (is *ImageStore) DeleteBlobUpload(repo string, uuid string) error {
	blobUploadPath := is.BlobUploadPath(repo, uuid)
	if err := os.Remove(blobUploadPath); err != nil {
		is.log.Error().Err(err).Str("blobUploadPath", blobUploadPath).Msg("error deleting blob upload")
		return err
	}

	return nil
}

// BlobPath returns the repository path of a blob.
func (is *ImageStore) BlobPath(repo string, digest godigest.Digest) string {
	return path.Join(is.rootDir, repo, "blobs", digest.Algorithm().String(), digest.Encoded())
}

// CheckBlob verifies a blob and returns true if the blob is correct.
func (is *ImageStore) CheckBlob(repo string, digest string,
	mediaType string) (bool, int64, error) {
	d, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")
		return false, -1, errors.ErrBadBlobDigest
	}

	blobPath := is.BlobPath(repo, d)

	blobInfo, err := os.Stat(blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")
		return false, -1, errors.ErrBlobNotFound
	}

	return true, blobInfo.Size(), nil
}

// GetBlob returns a stream to read the blob.
// FIXME: we should probably parse the manifest and use (digest, mediaType) as a
// blob selector instead of directly downloading the blob.
func (is *ImageStore) GetBlob(repo string, digest string, mediaType string) (io.Reader, int64, error) {
	d, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")
		return nil, -1, errors.ErrBadBlobDigest
	}

	blobPath := is.BlobPath(repo, d)

	blobInfo, err := os.Stat(blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")
		return nil, -1, errors.ErrBlobNotFound
	}

	is.log.Debug().Str("image", repo).Msg("Acquiring read lock for reading blobs")

	is.RLock()
	defer is.RUnlock()

	blobReader, err := os.Open(blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to open blob")
		return nil, -1, err
	}

	is.log.Debug().Str("image", repo).Msg("Releasing read lock that is acquired for reading blobs")

	return blobReader, blobInfo.Size(), nil
}

// DeleteBlob removes the blob from the repository.
func (is *ImageStore) DeleteBlob(repo string, digest string) error {
	d, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")
		return errors.ErrBlobNotFound
	}

	blobPath := is.BlobPath(repo, d)

	_, err = os.Stat(blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")
		return errors.ErrBlobNotFound
	}

	if is.cache != nil {
		if err := is.cache.DeleteBlob(digest, blobPath); err != nil {
			is.log.Error().Err(err).Str("digest", digest).Str("blobPath", blobPath).Msg("unable to remove blob path from cache")
			return err
		}
	}

	is.log.Debug().Str("image", repo).Msg("Acquiring write lock for deleting image blobs")
	is.Lock()
	defer is.Unlock()

	if err := os.Remove(blobPath); err != nil {
		is.log.Error().Err(err).Str("blobPath", blobPath).Msg("unable to remove blob path")
		return err
	}

	is.log.Debug().Str("image", repo).Msg("Release write lock that is acquired for deleting image blobs")

	return nil
}

// garbage collection

// Scrub will clean up all unreferenced blobs.
// TODO.
func Scrub(dir string, fix bool) error {
	return nil
}

// utility routines

func dirExists(d string) bool {
	fi, err := os.Stat(d)
	if err != nil && os.IsNotExist(err) {
		return false
	}

	if !fi.IsDir() {
		return false
	}

	return true
}

func ensureDir(dir string, log zerolog.Logger) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Panic().Err(err).Str("dir", dir).Msg("unable to create dir")
	}
}

func ifOlderThan(is *ImageStore, repo string, delay time.Duration) casext.GCPolicy {
	return func(ctx context.Context, digest godigest.Digest) (bool, error) {
		blobPath := is.BlobPath(repo, digest)
		fi, err := os.Stat(blobPath)

		if err != nil {
			return false, err
		}

		if fi.ModTime().Add(delay).After(time.Now()) {
			return false, nil
		}

		is.log.Info().Str("digest", digest.String()).Str("blobPath", blobPath).Msg("perform GC on blob")

		return true, nil
	}
}

// Used from https://gist.github.com/metafeather/3615b23097836bc36579100dac376906
func goid() int {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	idField := strings.Fields(strings.TrimPrefix(string(buf[:n]), "goroutine "))[0]
	id, err := strconv.Atoi(idField)
	if err != nil {
		panic(fmt.Sprintf("cannot get goroutine id: %v", err))
	}
	return id
}
