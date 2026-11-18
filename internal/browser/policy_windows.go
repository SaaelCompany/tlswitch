//go:build windows

package browser

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func writePolicy(roots, hints []string) error {
	targets := []struct {
		path string
		vals []string
	}{
		{`Software\Policies\Google\Chrome\CACertificates`, roots},
		{`Software\Policies\Google\Chrome\CAHintCertificates`, hints},
		{`Software\Policies\Microsoft\Edge\CACertificates`, roots},
		{`Software\Policies\Microsoft\Edge\CAHintCertificates`, hints},
	}
	// A Windows service runs as LocalSystem. That account has no loaded user
	// profile, so HKCU returns Access is denied. Machine policy is what Chrome
	// and Edge read in that case.
	hives := []registry.Key{registry.LOCAL_MACHINE, registry.CURRENT_USER}
	var last error
	ok := 0
	for _, hive := range hives {
		for _, t := range targets {
			if err := writeList(hive, t.path, t.vals); err != nil {
				last = err
				continue
			}
			ok++
		}
	}
	if ok == 0 {
		return fmt.Errorf("не удалось записать политику Chrome/Edge: %w", last)
	}
	return nil
}

func writeList(root registry.Key, path string, values []string) error {
	k, _, err := registry.CreateKey(root, path, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer k.Close()
	names, _ := k.ReadValueNames(0)
	for _, name := range names {
		_ = k.DeleteValue(name)
	}
	for i, v := range values {
		if err := k.SetStringValue(itoa(i+1), v); err != nil {
			return err
		}
	}
	return nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

var procCertAdd = windows.NewLazySystemDLL("crypt32.dll").NewProc("CertAddEncodedCertificateToStore")

// trustPlatform puts the same certificates into the Windows store Chrome uses
// when enterprise policy cannot be written.
func trustPlatform(roots, hints [][]byte) error {
	if err := addToStores(roots, "ROOT"); err != nil {
		return fmt.Errorf("не удалось добавить корневой сертификат в хранилище Windows: %w", err)
	}
	if err := addToStores(hints, "CA"); err != nil {
		return fmt.Errorf("не удалось добавить промежуточный сертификат в хранилище Windows: %w", err)
	}
	return nil
}

func addToStores(ders [][]byte, name string) error {
	if len(ders) == 0 {
		return nil
	}
	var last error
	for _, flags := range []uint32{
		windows.CERT_SYSTEM_STORE_LOCAL_MACHINE | windows.CERT_STORE_OPEN_EXISTING_FLAG,
		windows.CERT_SYSTEM_STORE_CURRENT_USER | windows.CERT_STORE_OPEN_EXISTING_FLAG,
	} {
		if err := addEncoded(flags, name, ders); err != nil {
			last = err
			continue
		}
		return nil
	}
	if last == nil {
		last = fmt.Errorf("хранилище %s недоступно", name)
	}
	return last
}

func addEncoded(flags uint32, name string, ders [][]byte) error {
	ptr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0, flags, uintptr(unsafe.Pointer(ptr)))
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	for _, der := range ders {
		if len(der) == 0 {
			continue
		}
		r, _, callErr := procCertAdd.Call(
			uintptr(store),
			uintptr(windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING),
			uintptr(unsafe.Pointer(unsafe.SliceData(der))),
			uintptr(len(der)),
			uintptr(windows.CERT_STORE_ADD_REPLACE_EXISTING),
			0,
		)
		if r == 0 {
			if callErr != nil && callErr != windows.ERROR_SUCCESS {
				return callErr
			}
			return fmt.Errorf("CertAddEncodedCertificateToStore")
		}
	}
	return nil
}
