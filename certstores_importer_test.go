package certinstall

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func createJAVAValidationPreconditions(logger *zap.Logger) (string, error) {
	//1. Set java home
	javahome, err := ioutil.TempDir("", "Test_isJAVAInstalled")
	if err != nil {
		logger.Sugar().Debugw("Failed to create temp directory",
			"java_home", javahome)
		return "", err
	}

	err = os.Setenv("JAVA_HOME", javahome)
	if err != nil {
		logger.Sugar().Debugw("Failed to set java home env variable",
			"java_home", javahome)
		return "", err
	}

	//2. Create paths for executable
	logger.Sugar().Debugw("using java home path",
		"java_home", javahome)
	keytoolPath := filepath.Join(javahome, "bin")
	err = os.MkdirAll(keytoolPath, os.ModePerm)
	if err != nil {
		logger.Sugar().Debugw("Failed to create keytool path",
			"java_home", javahome,
			"keytoolPath", keytoolPath)
		return "", err
	}

	keytoolPathExe := filepath.Join(keytoolPath, "keytool.exe")
	os.Create(keytoolPathExe)
	logger.Sugar().Debugw("keytool home path",
		"java_home", javahome,
		"keytool", keytoolPathExe)
	cacertsPath := filepath.Join(javahome, "lib", "security")
	err = os.MkdirAll(cacertsPath, os.ModePerm)
	if err != nil {
		logger.Sugar().Debugw("Failed to create cacerts path",
			"java_home", javahome,
			"keytoolPath", cacertsPath)
		return "", err
	}
	cacertsjks := filepath.Join(cacertsPath, "cacerts")
	os.Create(cacertsjks)
	logger.Sugar().Debugw("cacerts home path",
		"java_home", javahome,
		"cacertspath", cacertsjks)
	return javahome, nil
}

func Test_IsJavaInstalled(t *testing.T) {

	logger := zaptest.NewLogger(t)
	//Create Preconditions
	origJavahome := os.Getenv("JAVA_HOME")

	javahome, err := createJAVAValidationPreconditions(logger)
	defer os.RemoveAll(javahome)
	if err != nil {
		t.Logf("Failed to create java preconditions %s", err)
		t.Fail()
	}

	if !IsJavaInstalled(logger) {
		t.Fail()
	}

	//Set java to the way it was
	err = os.Setenv("JAVA_HOME", origJavahome)
	if err != nil {
		logger.Sugar().Debugw("Failed to set java home env variable",
			"java_home", javahome)
	}

}
