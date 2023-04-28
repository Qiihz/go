package main

import (
    "fmt"
    "time"
    "log"
    "io"
    "bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
    "math/rand"
    "unsafe"
    "strings"
    "net/http"
    "net/url"
    "errors"
    "encoding/base64"
    "encoding/json"
    "os"
    "os/exec"
    
    "golang.org/x/net/html"
)

var src = rand.NewSource(time.Now().UnixNano())
const (
    // 6 bits to represent a letter index
    letterIdBits = 6
    // All 1-bits as many as letterIdBits
    letterIdMask = 1<<letterIdBits - 1
    letterIdMax  = 63 / letterIdBits
    a_9 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

func randStr(n int, letters string) string {
    b := make([]byte, n)
    // A rand.Int63() generates 63 random bits, enough for letterIdMax letters!
    for i, cache, remain := n-1, src.Int63(), letterIdMax; i >= 0; {
        if remain == 0 {
            cache, remain = src.Int63(), letterIdMax
        }
        if idx := int(cache & letterIdMask); idx < len(letters) {
            b[i] = letters[idx]
            i--
        }
        cache >>= letterIdBits
        remain--
    }
    return *(*string)(unsafe.Pointer(&b))
}

var (
	// ErrInvalidBlockSize indicates hash blocksize <= 0.
	ErrInvalidBlockSize = errors.New("invalid blocksize")

	// ErrInvalidPKCS7Data indicates bad input to PKCS7 pad or unpad.
	ErrInvalidPKCS7Data = errors.New("invalid PKCS7 data (empty or not padded)")

	// ErrInvalidPKCS7Padding indicates PKCS7 unpad fails to bad input.
	ErrInvalidPKCS7Padding = errors.New("invalid padding on input")
)

// pkcs7Pad right-pads the given byte slice with 1 to n bytes, where
// n is the block size. The size of the result is x times n, where x
// is at least 1.
func pkcs7Pad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}

// pkcs7Unpad validates and unpads data from the given bytes slice.
// The returned value will be 1 to n bytes smaller depending on the
// amount of padding, where n is the block size.
func pkcs7Unpad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	if len(b)%blocksize != 0 {
		return nil, ErrInvalidPKCS7Padding
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, ErrInvalidPKCS7Padding
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, ErrInvalidPKCS7Padding
		}
	}
	return b[:len(b)-n], nil
}

func termuxShare(s string) {
    _, err := exec.Command("bash", "-c", fmt.Sprintf("echo '%s' | termux-share -a send", s)).Output()
    if err != nil {
        log.Println("Error on setTermuxClipboard.\n[ERROR] -", err)
    }
}

type Media struct {
    url string
}

type surf struct {
    url      *url.URL
    client   *http.Client
    header   http.Header
    request  *http.Request
    response *http.Response
}

func NewSurf(s string) *surf {
    u, err := url.Parse(s)
	if err != nil {
	    log.Fatal("Error on NewSurf.\n[ERROR] -", err)
    }
    header := http.Header{
        "Authority": {u.Host},
        "Accept": {`text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9`},
        "Accept-Language": {`zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-HK;q=0.6`},
        "Cache-Control": {`no-cache`},
        "Pragma": {`no-cache`},
        "Sec-Ch-Ua": {`"Chromium";v="111", "Not(A:Brand";v="8"`},
        "Sec-Ch-Ua-Mobile": {`?1`},
        "Sec-Ch-Ua-Platform": {`"Android"`},
        "Sec-Fetch-Dest": {`document`},
        "Sec-Fetch-Mode": {`navigate`},
        "Sec-Fetch-Site": {`none`},
        "Sec-Fetch-User": {`?1`},
        "Upgrade-Insecure-Requests": {`1`},
        "User-Agent": {`Mozilla/5.0 (Linux; Android 13; Pixel 4a) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36`},
    }
    var request *http.Request
    request, err = http.NewRequest("GET", u.String(), nil)
    if err != nil {
        log.Fatal("Error on NewSurf.\n[ERROR] -", err)
    }
    request.Header = header
    request.Header.Set("Sec-Fetch-User", "?1")
    request.Header.Set("Upgrade-Insecure-Requests", "1")
    
    var response *http.Response
    client := &http.Client{}
    response, err = client.Do(request)
    if err != nil {
        log.Fatal("Error on NewSurf.\n[ERROR] -", err)
    }
    
    header.Set("Accept", `application/json, text/javascript, */*; q=0.01`)
    header.Set("Referer", u.String()+"/")
    header.Set("Sec-Fetch-Dest", `empty`)
    header.Set("Sec-Fetch-Mode", `cors`)
    header.Set("Sec-Fetch-Site", `same-origin`)
    
    return &surf{ u, client, header, request, response }
}

func (surf *surf) NewRequest(method, s string, body io.Reader) {
    req, err := http.NewRequest(method, s, body)
    fmt.Printf("%s %s", method, s)
    if err != nil {
        log.Fatal("\nError on surf#NewRequest.\n[ERROR] -", err)
    }
    surf.request = req
    surf.request.Header = surf.header
}

func (surf *surf) Do() {
    res, err := surf.client.Do(surf.request)
    fmt.Printf(" %d\n", res.StatusCode)
    if err != nil {
        surf.Close()
        log.Fatal("Error on surf#Do.\n[ERROR] -", err)
    }
    surf.response = res
}

func (surf *surf) ReadAll() {
    io.ReadAll(surf.response.Body)
    surf.Close()
}

func (surf *surf) Close() {
    surf.response.Body.Close()
}

func (surf *surf) SetHeader(k, v string) {
    surf.request.Header.Set(k, v)
}

func fodownloader(parseLink string) (medias []Media) {
    surf := NewSurf("https://www.fodownloader.com/bilibili-video-downloader")
    surf.ReadAll()
    surf.NewRequest("GET", "https://www.fodownloader.com/csgeturl?urlInfo=" + url.QueryEscape(parseLink) + "&lang=zh", nil)
    surf.Do()
    defer surf.Close()
    
    doc, err := html.Parse(surf.response.Body)
	if err != nil {
		log.Fatal("Error on videoNodes.\n[ERROR] -", err)
	}
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "video" {
			for _, video := range n.Attr {
				if video.Key == "src" {
					medias = append(medias, Media { video.Val })
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
	return
}

func iiilabReverse(r []byte) {
    j := len(r)-1
    for r[j] == 61 {
        j--
    }
    l := (j+1)/2
    for i := 0; i < l; i++ {
        r[i], r[j] = r[j], r[i]
        j--
    }
}

type IiilabMedia struct {
	Code int                 `json:"code"`
	Succ bool                `json:"succ"`
	Data *IiilabMediaDataBytes `json:"data"`
}

type IiilabMediaData struct {
	Text   string `json:"text"`
	Medias []struct {
		MediaType   string `json:"media_type"`
		ResourceURL string `json:"resource_url"`
		PreviewURL  string `json:"preview_url"`
	} `json:"medias"`
	Overseas int `json:"overseas"`
}

func NewIiilabMediaData(r io.Reader) *IiilabMediaData {
	var im IiilabMedia
	if err := json.NewDecoder(r).Decode(&im); err != nil {
		log.Fatal("Error on IiilabMedia#json.Decode.\n[ERROR] -", err)
	}
    if im.Code != 200 {
        fmt.Printf("%+v\n", im)
        log.Fatal("Error on IiilabMedia Decode")
    }
	
	imd := &IiilabMediaData{}
    err := json.Unmarshal(*im.Data, imd)
	if err != nil {
	    log.Fatal("Error on IiilabMediaData#json.Unmarshal.\n[ERROR] -", err)
	}
	return imd
}

type IiilabMediaDataBytes []byte

func (imrd *IiilabMediaDataBytes) UnmarshalText(text []byte) error {
    //log.Println(len(text), len(string(text)))
    data := text[16:]
    log.Printf("s - %d", len(data))
    iiilabReverse(data)
    dst := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
    n, err := base64.StdEncoding.Decode(dst, data)
	if err != nil {
	    log.Fatal("Error on IiilabMediaData#base64.DecodeString.\n[ERROR] -", err)
	}
	log.Printf("%d - %s", len(dst), dst)
    *imrd = dst[:n]
	//log.Println("-" + string(*imrd))
	return nil
}

func iiilabBase64(s string) string {
    plaintext := []byte(s)
	key := []byte("H0GM7TGBw193GYf8")
	iv, _ := hex.DecodeString("00000000000000000000000000000000")
	
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	plaintext, _ = pkcs7Pad(plaintext, block.BlockSize())
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)
	
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(ciphertext)))
	base64.StdEncoding.Encode(dst, ciphertext)
    
    return string(dst)
}

func iiilabEncode(s string) string {
    data := []byte(s)
    dst := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(dst, data)
	iiilabReverse(dst)
    return randStr(16, a_9) + string(dst)
}

func iiilabCal(s string) int {
    a := 0
    for _, v := range s {
        a += int(v) % 10;
    }
    return a << 8;
}

func iiilabUC(s string) string {
    hostname := "bilibili.iiilab.com"
    hn1 := []rune(strings.Split(hostname, ".")[0])
    r := []rune(s)
    //fmt.Println(string(hn1[r[0] % 8]) + s + string(hn1[r[len(r) - 1] % 8]))
    return iiilabBase64(string(hn1[r[0] % 8]) + s + string(hn1[r[len(r) - 1] % 8]))
}

type LinkData struct {
    Link string `json:"link"`
}

func NewLinkData(s string) *LinkData {
    en := iiilabEncode(s)
    e := randStr(17, "0123456789")
    cal := iiilabCal(s + "@" + e)
    link := fmt.Sprintf("%s@%s@%v", en, e, cal)
    log.Println(link)
    return &LinkData{ link }
}

func iiilabLinkDataReader(link string) io.Reader {
    r, w := io.Pipe()
    go func() {
		json.NewEncoder(w).Encode(NewLinkData(link))
		w.Close()
	}()
	return r
}

func iiilabPhpsessid(header *http.Header) string {
    setCookie := header.Get("set-cookie")
    if _, found := strings.CutPrefix(setCookie, "PHPSESSID="); !found {
        log.Fatal("Error on iiilab.\n[ERROR] - Not PHPSESSID")
    }
    return setCookie[:strings.Index(setCookie, ";")+1]
}

func iiilab(s string) (medias []Media) {
    surf := NewSurf("https://bilibili.iiilab.com")
    surf.ReadAll()
    surf.NewRequest("POST", "https://bilibili.iiilab.com/media", iiilabLinkDataReader(s))
    surf.SetHeader("Accept-Patch", iiilabUC(s))
    surf.SetHeader("Content-Type", "application/json; charset=UTF-8")
    surf.SetHeader("Cookie", iiilabPhpsessid(&surf.response.Header) + " lab0626=1")
    surf.SetHeader("Origin", "https://bilibili.iiilab.com")
    surf.Do()
    defer surf.Close()
    
    imd := NewIiilabMediaData(surf.response.Body)
    if len(imd.Medias) != 1 {
        fmt.Printf("%+v\n", imd)
        return
    }
    for _, v := range imd.Medias {
        medias = append(medias, Media{ v.ResourceURL })
    }
    return
}

func main() {
    args := os.Args
    if len(args) != 3 {
        return
    }
    
    var medias []Media
    switch args[1] {
    case "iiilab":
        medias = iiilab(args[2])
    case "fodownloader":
        medias = fodownloader(args[2])
    default:
        return
    }
    
    if len(medias) != 1 {
        fmt.Printf("%+v\n", medias)
        return
    }
    termuxShare(medias[0].url)
}

