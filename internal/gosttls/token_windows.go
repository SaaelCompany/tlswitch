//go:build windows

package gosttls

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"go.cypherpunks.ru/gogost/v5/gost3410"
	"golang.org/x/sys/windows"
)

// CryptoPro CALG_GR3411_2012_256 / _512: ALG_CLASS_HASH | ALG_SID.
const (
	calgGR3411_2012_256 = 0x8021
	calgGR3411_2012_512 = 0x8022
	ppKeyExchangePIN    = 32
	ppSignaturePIN      = 33
	certFindSHA1Hash    = 1 << 16
)

var (
	advapi32              = windows.NewLazySystemDLL("advapi32.dll")
	procCryptCreateHash   = advapi32.NewProc("CryptCreateHash")
	procCryptHashData     = advapi32.NewProc("CryptHashData")
	procCryptSignHashW    = advapi32.NewProc("CryptSignHashW")
	procCryptDestroyHash  = advapi32.NewProc("CryptDestroyHash")
	procCryptSetProvParam = advapi32.NewProc("CryptSetProvParam")
	ncrypt                = windows.NewLazySystemDLL("ncrypt.dll")
	procNCryptFreeObject  = ncrypt.NewProc("NCryptFreeObject")
)

// cryptHashBlob is CRYPT_HASH_BLOB. On amd64 the pointer is aligned to 8.
type cryptHashBlob struct {
	cbData uint32
	pbData *byte
}

type tokenSigner struct {
	sum []byte
	pin string
	alg uint32
}

type acquiredKey struct {
	prov windows.Handle
	spec uint32
	free bool
}

// LoadToken finds the certificate in the Current User or Local Machine
// personal store and signs with its CryptoPro key. The key is not exported.
func LoadToken(thumb, pin string) (*Identity, error) {
	sum, err := parseThumb(thumb)
	if err != nil {
		return nil, err
	}
	ctx, err := findContext(sum)
	if err != nil {
		return nil, err
	}
	defer windows.CertFreeCertificateContext(ctx)
	der := bytes.Clone(unsafe.Slice(ctx.EncodedCert, ctx.Length))
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("клиентский сертификат не разбирается: %w", err)
	}
	pub, _, err := gostPublic(leaf)
	if err != nil {
		return nil, fmt.Errorf("клиентский сертификат не ГОСТ: %w", err)
	}
	signer := &tokenSigner{
		sum: append([]byte{}, sum...),
		pin: pin,
		alg: hashAlg(pub),
	}
	if err := signer.probe(); err != nil {
		return nil, err
	}
	return &Identity{Certs: attachChain(leaf), Sign: signer.sign}, nil
}

func hashAlg(pub *gost3410.PublicKey) uint32 {
	if pub != nil && pub.C.PointSize() == 64 {
		return calgGR3411_2012_512
	}
	return calgGR3411_2012_256
}

func (s *tokenSigner) probe() error {
	ctx, err := findContext(s.sum)
	if err != nil {
		return err
	}
	defer windows.CertFreeCertificateContext(ctx)
	key, err := acquireKey(ctx, s.pin)
	if err != nil {
		return err
	}
	key.release()
	return nil
}

func (s *tokenSigner) sign(transcript []byte) ([]byte, error) {
	if len(transcript) == 0 {
		return nil, errors.New("клиентский сертификат: пустая запись рукопожатия")
	}
	ctx, err := findContext(s.sum)
	if err != nil {
		return nil, err
	}
	defer windows.CertFreeCertificateContext(ctx)
	key, err := acquireKey(ctx, s.pin)
	if err != nil {
		return nil, err
	}
	defer key.release()
	sig, err := signHash(key.prov, s.alg, key.spec, transcript)
	if err != nil {
		other := uint32(calgGR3411_2012_512)
		if s.alg == calgGR3411_2012_512 {
			other = calgGR3411_2012_256
		}
		sig, err = signHash(key.prov, other, key.spec, transcript)
	}
	if err != nil && key.spec == windows.AT_KEYEXCHANGE {
		sig, err = signHash(key.prov, s.alg, windows.AT_SIGNATURE, transcript)
	}
	if err != nil {
		return nil, fmt.Errorf("клиентский сертификат: КриптоПро не подписал запрос: %w", err)
	}
	return sig, nil
}

func acquireKey(ctx *windows.CertContext, pin string) (*acquiredKey, error) {
	var prov windows.Handle
	var spec uint32
	var callerFree bool
	err := windows.CryptAcquireCertificatePrivateKey(
		ctx,
		windows.CRYPT_ACQUIRE_SILENT_FLAG|windows.CRYPT_ACQUIRE_USE_PROV_INFO_FLAG,
		nil,
		&prov,
		&spec,
		&callerFree,
	)
	if err != nil || prov == 0 {
		if err == nil {
			err = syscall.EINVAL
		}
		return nil, fmt.Errorf("клиентский сертификат есть, но токен не отдал ключ: %w. Вставьте токен, укажите upstream.client_pin и запустите программу в сеансе пользователя, а не службой", err)
	}
	key := &acquiredKey{prov: prov, spec: spec, free: callerFree}
	if spec == windows.CERT_NCRYPT_KEY_SPEC {
		key.release()
		return nil, errors.New("клиентский сертификат привязан к CNG, а не к КриптоПро CSP. Установите его из контейнера КриптоПро")
	}
	if spec == 0 {
		key.spec = windows.AT_KEYEXCHANGE
	}
	if pin != "" {
		if err := setPIN(prov, pin); err != nil {
			key.release()
			return nil, fmt.Errorf("клиентский сертификат: токен не принял PIN: %w", err)
		}
	}
	return key, nil
}

func (k *acquiredKey) release() {
	if k == nil || !k.free || k.prov == 0 {
		return
	}
	if k.spec == windows.CERT_NCRYPT_KEY_SPEC {
		procNCryptFreeObject.Call(uintptr(k.prov))
		k.prov = 0
		return
	}
	_ = windows.CryptReleaseContext(k.prov, 0)
	k.prov = 0
}

func setPIN(prov windows.Handle, pin string) error {
	buf := append([]byte(pin), 0)
	var last error
	for _, param := range []uintptr{ppKeyExchangePIN, ppSignaturePIN} {
		r, _, e := procCryptSetProvParam.Call(uintptr(prov), param, uintptr(unsafe.Pointer(&buf[0])), 0)
		if r != 0 {
			return nil
		}
		last = callErr(e)
	}
	return last
}

func signHash(prov windows.Handle, alg, keySpec uint32, data []byte) ([]byte, error) {
	var hash uintptr
	r, _, e := procCryptCreateHash.Call(uintptr(prov), uintptr(alg), 0, 0, uintptr(unsafe.Pointer(&hash)))
	if r == 0 {
		return nil, callErr(e)
	}
	defer procCryptDestroyHash.Call(hash)
	r, _, e = procCryptHashData.Call(hash, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0)
	if r == 0 {
		return nil, callErr(e)
	}
	buf := make([]byte, 128)
	n := uint32(len(buf))
	r, _, e = procCryptSignHashW.Call(hash, uintptr(keySpec), 0, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	if r == 0 && n > uint32(len(buf)) && n <= 256 {
		buf = make([]byte, n)
		r, _, e = procCryptSignHashW.Call(hash, uintptr(keySpec), 0, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	}
	if r == 0 {
		return nil, callErr(e)
	}
	if n == 0 || n > uint32(len(buf)) {
		return nil, fmt.Errorf("неожиданная длина подписи %d", n)
	}
	return buf[:n], nil
}

func callErr(e error) error {
	if e != nil && e != windows.ERROR_SUCCESS {
		return e
	}
	return syscall.EINVAL
}

func findContext(sum []byte) (*windows.CertContext, error) {
	locations := []uint32{
		windows.CERT_SYSTEM_STORE_CURRENT_USER,
		windows.CERT_SYSTEM_STORE_LOCAL_MACHINE,
	}
	var openErr error
	for _, loc := range locations {
		store, err := openStore(loc, "MY")
		if err != nil {
			openErr = err
			continue
		}
		ctx, err := findInStore(store, sum)
		_ = windows.CertCloseStore(store, 0)
		if err != nil {
			openErr = err
			continue
		}
		if ctx != nil {
			return ctx, nil
		}
	}
	msg := fmt.Sprintf("клиентский сертификат с отпечатком %s не найден в хранилище «Личное». В КриптоПро CSP: Сервис → Просмотреть сертификаты в контейнере → Установить. Запустите tlswitch в том же сеансе Windows, куда вставлен токен: служба от имени системы токен не видит", hex.EncodeToString(sum))
	if openErr != nil {
		return nil, fmt.Errorf("%s (%v)", msg, openErr)
	}
	return nil, errors.New(msg)
}

func openStore(location uint32, name string) (windows.Handle, error) {
	ptr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	return windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0,
		0,
		location|windows.CERT_STORE_READONLY_FLAG,
		uintptr(unsafe.Pointer(ptr)),
	)
}

func findInStore(store windows.Handle, sum []byte) (*windows.CertContext, error) {
	if len(sum) == 20 {
		blob := cryptHashBlob{cbData: uint32(len(sum)), pbData: &sum[0]}
		ctx, err := windows.CertFindCertificateInStore(
			store,
			windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
			0,
			certFindSHA1Hash,
			unsafe.Pointer(&blob),
			nil,
		)
		if err != nil || ctx == nil {
			return nil, nil
		}
		return ctx, nil
	}
	var prev *windows.CertContext
	for {
		next, err := windows.CertEnumCertificatesInStore(store, prev)
		if err != nil || next == nil {
			return nil, nil
		}
		prev = next
		der := unsafe.Slice(next.EncodedCert, next.Length)
		if !certMatches(der, sum) {
			continue
		}
		dup := windows.CertDuplicateCertificateContext(next)
		for {
			next, err = windows.CertEnumCertificatesInStore(store, prev)
			if err != nil || next == nil {
				break
			}
			prev = next
		}
		return dup, nil
	}
}

func certMatches(der, want []byte) bool {
	switch len(want) {
	case 20:
		sum := sha1.Sum(der)
		return bytes.Equal(sum[:], want)
	case 32:
		sum := sha256.Sum256(der)
		if bytes.Equal(sum[:], want) {
			return true
		}
		return bytes.Equal(streebog(der), want)
	default:
		return false
	}
}

func attachChain(leaf *x509.Certificate) []*x509.Certificate {
	out := []*x509.Certificate{leaf}
	cur := leaf
	seen := map[string]bool{string(leaf.Raw): true}
	for i := 0; i < 4; i++ {
		if bytes.Equal(cur.RawSubject, cur.RawIssuer) {
			break
		}
		next := storeIssuer(cur.RawIssuer)
		if next == nil || seen[string(next.Raw)] || bytes.Equal(next.RawSubject, next.RawIssuer) {
			break
		}
		seen[string(next.Raw)] = true
		out = append(out, next)
		cur = next
	}
	return out
}

func storeIssuer(rawIssuer []byte) *x509.Certificate {
	locations := []uint32{
		windows.CERT_SYSTEM_STORE_CURRENT_USER,
		windows.CERT_SYSTEM_STORE_LOCAL_MACHINE,
	}
	for _, name := range []string{"CA", "MY"} {
		for _, loc := range locations {
			store, err := openStore(loc, name)
			if err != nil {
				continue
			}
			got := issuerInStore(store, rawIssuer)
			_ = windows.CertCloseStore(store, 0)
			if got != nil {
				return got
			}
		}
	}
	return nil
}

func issuerInStore(store windows.Handle, rawIssuer []byte) *x509.Certificate {
	var prev *windows.CertContext
	for {
		next, err := windows.CertEnumCertificatesInStore(store, prev)
		if err != nil || next == nil {
			return nil
		}
		prev = next
		der := bytes.Clone(unsafe.Slice(next.EncodedCert, next.Length))
		cert, err := x509.ParseCertificate(der)
		if err != nil || !bytes.Equal(cert.RawSubject, rawIssuer) {
			continue
		}
		for {
			next, err = windows.CertEnumCertificatesInStore(store, prev)
			if err != nil || next == nil {
				break
			}
			prev = next
		}
		return cert
	}
}
