package certinstall

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"go.uber.org/zap"
	"golang.org/x/sys/windows"
)

var (

	//errors

	// ErrNoJAVACaCertsStoreFound is returned when we can't find the java ca certs trust store
	ErrNoJAVACaCertsStoreFound = errors.New("Could not find java cacerts trust store")
	// ErrNoJAVAKeyToolFound is returned we can't find the JAVA key tool used to import certificates in the cacerts jks
	ErrNoJAVAKeyToolFound = errors.New("Cloud not find java keytool")
	// ErrNoFirefoxCertUtilToolFound is returned when we can't find the nss certutil tool
	//https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Reference/NSS_tools_:_certutil
	ErrNoFirefoxCertUtilToolFound = errors.New("Cloud not find cert util")
	// ErrNoFirefoxNoCertDBFound  is returned when we can't find the firefox certdb database which stores the default certs
	// https://www.mankier.com/5/cert9.db
	ErrNoFirefoxNoCertDBFound = errors.New("Cloud not find firefox cert DB")
	// ErrNoFirefoxInstalled is returned when firefox validation fails
	ErrNoFirefoxInstalled = errors.New("Firefox not installed or configured properly")
	// ErrOSNotSupportedFound is showed if using any other OS than window
	ErrOSNotSupportedFound = errors.New("OS is not supported")

	// nss tool url
	nssToolURL = "https://nexus.dev.dyploy.net/repository/artifacts/nss/nss-tools.msi"

	//windows trust store related
	modcrypt32                           = syscall.NewLazyDLL("crypt32.dll")
	procCertAddEncodedCertificateToStore = modcrypt32.NewProc("CertAddEncodedCertificateToStore")
	procCertCloseStore                   = modcrypt32.NewProc("CertCloseStore")
	procCertDeleteCertificateFromStore   = modcrypt32.NewProc("CertDeleteCertificateFromStore")
	procCertDuplicateCertificateContext  = modcrypt32.NewProc("CertDuplicateCertificateContext")
	procCertEnumCertificatesInStore      = modcrypt32.NewProc("CertEnumCertificatesInStore")
	procCertOpenSystemStoreW             = modcrypt32.NewProc("CertOpenSystemStoreW")
)

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func isAdmin() (bool, error) {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(&windows.SECURITY_NT_AUTHORITY, 2, windows.SECURITY_BUILTIN_DOMAIN_RID, windows.DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &sid)
	if err != nil {
		return false, err
	}
	token := windows.Token(0)
	return token.IsMember(sid)
}
func binaryExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

//IsJavaInstalled checks if we have java installed
func IsJavaInstalled(logger *zap.Logger) bool {
	var haskeytool bool
	var hasCaCerts bool

	switch runtime.GOOS {
	case "windows":
		keytoolPath := filepath.Join("bin", "keytool.exe")
		if v := os.Getenv("JAVA_HOME"); v != "" {
			if pathExists(filepath.Join(v, keytoolPath)) {
				keytoolPath = filepath.Join("bin", "keytool.exe")
				keytoolPath = filepath.Join(v, keytoolPath)
				logger.Sugar().Debugw("found keytool",
					"path", keytoolPath,
					"java_home", v,
				)
				haskeytool = true
			}
			if pathExists(filepath.Join(v, "lib", "security", "cacerts")) {
				hasCaCerts = true
				cacertsPath := filepath.Join(v, "lib", "security", "cacerts")
				logger.Sugar().Debugw("found java lib security cacerts path",
					"path", cacertsPath,
					"java_home", v,
				)
			}

			if pathExists(filepath.Join(v, "jre", "lib", "security", "cacerts")) {
				hasCaCerts = true
				cacertsPath := filepath.Join(v, "jre", "lib", "security", "cacerts")
				logger.Sugar().Debugw("found jre cacerts path",
					"path", cacertsPath,
					"java_home", v,
				)
			}

			//check java version

			if haskeytool && hasCaCerts {
				return true
			}

		}
	default:
		logger.Sugar().Debugw("OS not supported",
			"OS", runtime.GOOS,
		)
		return false

	}
	return false
}

// JavaCertImporter imports the cert into the JAVA HOME security trust store
func JavaCertImporter(logger *zap.Logger, caFile *x509.Certificate, caSerialNumber *big.Int) error {
	//	var cacertsPath string
	var keytoolPath string
	var storePass string = "changeit"

	//check if java is installed and configured
	if !IsJavaInstalled(logger) {
		return ErrNoJAVAKeyToolFound
	}

	javaPath := os.Getenv("JAVA_HOME")
	keytoolPath = filepath.Join(javaPath, "bin/keytool.exe")
	logger.Sugar().Debugw("keytool path",
		"path", keytoolPath,
		"JAVA_HOME", javaPath,
	)

	cacertfile, err := ioutil.TempFile("", "cacert.*.crt")
	if err != nil {
		log.Fatal(err)
	}

	if _, err := cacertfile.Write(caFile.Raw); err != nil {
		cacertfile.Close()
		logger.Sugar().Fatalw("encountered error while writing ca cert to file", "file", cacertfile.Name(), err)
	}
	logger.Sugar().Debugw("wrote cert to file",
		"file", cacertfile.Name(),
	)

	if err := cacertfile.Close(); err != nil {
		logger.Sugar().Fatalw("encountered error while closing file", "file", cacertfile.Name(), err)
	}

	//see if cert is already imported
	argslist := []string{
		"-list", "-noprompt", "-cacerts",
		"-storepass", storePass,
		"-alias", caSerialNumber.String(),
	}

	cmd := exec.Command(keytoolPath, argslist...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		//"keytool error: java.lang.Exception: Alias <146025> does not exist\r\n"
		var aliasExists = regexp.MustCompile(`Alias <\+?\d+> does not exist`)
		if !aliasExists.Match(out) {
			logger.Sugar().Debugw("keytoolcmd list returned error",
				"cmd", cmd.Path,
				"cmd args", cmd.Args,
				"cmd out", string(out),
			)
			return err
		}
		//exec keytool import
		argsimport := []string{
			"-importcert", "-cacerts",
			"-storepass", storePass,
			"-file", cacertfile.Name(),
			"-alias", caSerialNumber.String(),
		}

		// if not elevated, relaunch  with runas administrator
		admin, err := isAdmin()
		if err != nil {
			return err
		}
		if !admin {
			return errors.New("no admin right provided, can't import certificate")
		}
		cmd = exec.Command(keytoolPath, argsimport...)
		out, err = cmd.CombinedOutput()
		if err != nil {
			logger.Sugar().Debugw("keytoolcmd error",
				"cmd", cmd.Path,
				"cmd args", cmd.Args,
				"cmd out", string(out),
			)
			return err
		}
		logger.Sugar().Debugw("keytoolcmd success",
			"cmd", cmd.Path,
			"cmd args", cmd.Args,
			"cmd out", string(out),
		)
		return nil

	}
	logger.Sugar().Debugw("nothing to do, cert already imported",
		"cmd", cmd.Path,
		"cmd args", cmd.Args,
		"cmd out", string(out),
	)
	return nil
}

// IsFirefoxInstalled checks if firefox is installed on the machine
func IsFirefoxInstalled(logger *zap.Logger) bool {
	var hasCertutil bool
	var certutilPath string

	switch runtime.GOOS {
	case "windows":
		switch {
		case binaryExists("mcertutil.exe"):
			certutilPath, _ = exec.LookPath("mcertutil")
			logger.Sugar().Debugw("Certutil found",
				"path", certutilPath,
			)
			hasCertutil = true
		case binaryExists("C:\\Program Files (x86)\\NSS\\NSS3\\mcertutil.exe"):
			certutilPath = "C:\\Program Files (x86)\\NSS\\NSS3\\mcertutil.exe"
			logger.Sugar().Debugw("Certutil found",
				"path", certutilPath,
			)
			hasCertutil = true
		default:
			logger.Sugar().Debugw("Certutil not found, please install the msi from URL",
				"url", nssToolURL,
			)
		}
		if !hasCertutil {
			return false
		}

	default:
		logger.Sugar().Debugw("OS not supported",
			"OS", runtime.GOOS,
		)
		return false

	}
	return true
}

// FirefoxCertImporter imports the CA in firefox
func FirefoxCertImporter(logger *zap.Logger, caFile *x509.Certificate, caSerialNumber *big.Int) error {

	//check if firefox is installed and configured
	if !IsFirefoxInstalled(logger) {
		return ErrNoFirefoxInstalled
	}

	cacertfile, err := ioutil.TempFile("", "cacert.*.crt")
	if err != nil {
		log.Fatal(err)
	}

	if _, err := cacertfile.Write(caFile.Raw); err != nil {
		cacertfile.Close()
		logger.Sugar().Fatalw("encountered error while writing ca cert to file", "file", cacertfile.Name(), err)
	}
	logger.Sugar().Debugw("wrote cert to file",
		"file", cacertfile.Name(),
	)

	if err := cacertfile.Close(); err != nil {
		logger.Sugar().Fatalw("encountered error while closing file", "file", cacertfile.Name(), err)
	}

	var firefoxProfile = os.Getenv("USERPROFILE") + "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*"

	certutilPath, err := exec.LookPath("mcertutil.exe")
	if err != nil {
		logger.Sugar().Debugw("mcertutil.exe not found",
			"OS", runtime.GOOS,
			"err", err.Error(),
		)
		return ErrNoFirefoxCertUtilToolFound
	}

	profiles, _ := filepath.Glob(firefoxProfile)
	logger.Sugar().Debugw("found firefox profiles",
		"profiles", profiles,
	)
	for _, profile := range profiles {
		if stat, err := os.Stat(profile); err != nil || !stat.IsDir() {
			continue
		}
		//new firefox type db format 9
		if pathExists(filepath.Join(profile, "cert9.db")) {
			logger.Sugar().Debugw("found firefox certdb9",
				"profile", profile,
			)

			//Check if ca is already imported
			cmdCALister := exec.Command(certutilPath, "-L", "-n", caSerialNumber.String(), "-d", profile)

			cmdCAListOutput, errCAList := cmdCALister.CombinedOutput()
			logger.Sugar().Debugw("certutil list",
				"profile", profile,
				"caSerialNumber", caSerialNumber.String(),
				"caListCommand", strings.Join(cmdCALister.Args, " "),
				"cmdCAImportedOutput", string(cmdCAListOutput),
			)
			if errCAList != nil { //ca is not imported so we try to import it
				cmdImport := exec.Command(certutilPath, "-A", "-d", profile, "-t", "C,,", "-n", caSerialNumber.String(), "-i", cacertfile.Name())

				cmdImportOutput, errcmdImport := cmdImport.CombinedOutput()
				logger.Sugar().Debugw("certutil import",
					"profile", profile,
					"caSerialNumber", caSerialNumber.String(),
					"caImportCommand", strings.Join(cmdImport.Args, " "),
					"cmdImportOutput", string(cmdImportOutput),
				)
				if errcmdImport != nil {
					return errcmdImport
				}
			}
		}
	}
	return nil
}

// WindowStoreCertImporter imports the CA in the Operating System cert store
func WindowStoreCertImporter(logger *zap.Logger, caFile *x509.Certificate, caSerialNumber *big.Int) error {
	switch runtime.GOOS {
	case "windows":
		cert := caFile.Raw

		// if not elevated, relaunch  with runas administrator
		admin, err := isAdmin()
		if err != nil {
			return err
		}
		if !admin {
			logger.Sugar().Debugw("not running as administrator")
			return errors.New("no admin right provided, can't import certificate")
		}
		// Open root store
		store, err := openWindowsRootStore()
		logger.Sugar().Debugw("opening windows trust store")
		if err != nil {
			logger.Sugar().Debugw("failed to open store",
				"err", err.Error())
			return err
		}
		defer store.close()

		// Add cert
		err = store.addCert(cert)
		logger.Sugar().Debugw("adding cert to store")
		if err != nil {
			logger.Sugar().Debugw("failed to add cert to store",
				"err", err.Error())
			return err
		}
		return nil
	default:
		logger.Sugar().Debugw("OS not supported",
			"OS", runtime.GOOS,
		)
		return ErrOSNotSupportedFound
	}
}

// copied from https://github.com/FiloSottile/mkcert/blob/master/truststore_windows.go#L69
type windowsRootStore uintptr

func openWindowsRootStore() (windowsRootStore, error) {
	store, _, err := procCertOpenSystemStoreW.Call(0, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("ROOT"))))
	if store != 0 {
		return windowsRootStore(store), nil
	}
	return 0, fmt.Errorf("Failed to open windows root store: %v", err)
}

func (w windowsRootStore) close() error {
	ret, _, err := procCertCloseStore.Call(uintptr(w), 0)
	if ret != 0 {
		return nil
	}
	return fmt.Errorf("Failed to close windows root store: %v", err)
}

func (w windowsRootStore) addCert(cert []byte) error {
	// TODO: ok to always overwrite?
	ret, _, err := procCertAddEncodedCertificateToStore.Call(
		uintptr(w), // HCERTSTORE hCertStore
		uintptr(syscall.X509_ASN_ENCODING|syscall.PKCS_7_ASN_ENCODING), // DWORD dwCertEncodingType
		uintptr(unsafe.Pointer(&cert[0])),                              // const BYTE *pbCertEncoded
		uintptr(len(cert)),                                             // DWORD cbCertEncoded
		3,                                                              // DWORD dwAddDisposition (CERT_STORE_ADD_REPLACE_EXISTING is 3)
		0,                                                              // PCCERT_CONTEXT *ppCertContext
	)
	if ret != 0 {
		return nil
	}
	return fmt.Errorf("Failed adding cert: %v", err)
}
