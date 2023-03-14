package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"math/rand"
	"net"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/valyala/fasthttp"
)

var isSaveFs = flag.Bool("save", false, "Save all targets to file system")

func fileMode(path string) (fs.FileMode, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return fi.Mode(), nil
}

func ensureDir(targetDir string, stop bool) {
	targetDir = strings.TrimRight(targetDir, "/\\")
	mode, err := fileMode(targetDir)
	if err == nil {
		// exist
		if mode.IsDir() {
			// is dir
			return
		}
		if mode.IsRegular() {
			// is file
			// move file
			targetFile := targetDir + strconv.FormatUint(rand.Uint64(), 36)
			os.Rename(targetDir, targetFile)
			os.Mkdir(targetDir, 0755)
			os.Rename(targetFile, targetDir+"/index.html")
			return
		}
		return
	}

	// not exists
	err = os.Mkdir(targetDir, 0755)
	if err == nil {
		return
	}

	if stop {
		return
	}

	curDir := "."
	for _, dir := range strings.Split(targetDir, "/") {
		curDir += "/" + dir
		ensureDir(curDir, true)
	}
}

// GetResponseBody return plain response body of resp
func GetResponseBody(resp *fasthttp.Response) ([]byte, error) {
	var contentEncoding = string(resp.Header.Peek("Content-Encoding"))
	if len(contentEncoding) < 1 {
		return resp.Body(), nil
	}
	if hasToken(contentEncoding, "br") {
		return resp.BodyUnbrotli()
	}
	if hasToken(contentEncoding, "gzip") {
		return resp.BodyGunzip()
	}
	if hasToken(contentEncoding, "deflate") {
		return resp.BodyInflate()
	}
	return nil, errors.New("unsupported response content encoding: " + string(contentEncoding))
}

func logReqResp(isHTTPS bool, req *fasthttp.Request, resp *fasthttp.Response) {
	if !*isSaveFs {
		fmt.Println(isHTTPS, req, resp)
		return
	}
	body, err := GetResponseBody(resp)
	if err != nil {
		log.Println(err)
		return
	}
	host := string(req.URI().Host())
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		if err1, ok := err.(*net.AddrError); ok && strings.Contains(err1.Err, "missing port") {
			hostname, _, err = net.SplitHostPort(host + ":80")
		}
		if err != nil {
			log.Println(err)
			return
		}
	}

	targetFile := hostname + "/" + string(req.URI().Path())
	targetDir, targetFile := path.Split(targetFile)
	ensureDir(targetDir, false)

	// file 644
	// dir 755
	targetFile = targetDir + "/" + targetFile
	mode, err := os.Stat(targetFile)
	if err == nil {
		// exists
		if mode.IsDir() {
			// is dir
			targetFile = targetFile + "/index.html"
		}
		// is regular file?
		// pass
	}
	// not exists
	// pass
	// expect file
	err = os.WriteFile(targetFile, body, 0644)
	if err != nil {
		log.Println(targetFile, err)
	}
}
