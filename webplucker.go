package certinstall

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// ErrNoCAFound results from iterating a list of certificates but not founding any cert which has the BasicConstraints CA set.
/* https://tools.ietf.org/html/rfc5280#section-6.1.4 section K states:
(k)  If certificate i is a version 3 certificate, verify that the
basicConstraints extension is present and that cA is set to
TRUE.  (If certificate i is a version 1 or version 2
certificate, then the application MUST either verify that
certificate i is a CA certificate through out-of-band means
or reject the certificate.  Conforming implementations may
choose to reject all version 1 and version 2 intermediate
certificates.)
*/
var ErrNoCAFound = errors.New("No CA certificate found")

//WebPlucker returns a CA certificate from an URL if the TLS url has the full cert chain in it.
func WebPlucker(logger *zap.Logger, url string) (*x509.Certificate, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	logger.Sugar().Debugw("discovered certs",
		"url", url,
		"number", len(resp.TLS.PeerCertificates),
	)
	for _, cert := range resp.TLS.PeerCertificates {
		logger.Sugar().Debugw("cert info",
			"url", url,
			"issuer", cert.Issuer,
			"expiration", cert.NotAfter.Format(time.RFC3339),
			"DNSNames", cert.DNSNames,
			"cn", cert.Subject.CommonName,
			"serialNumber", cert.SerialNumber,
		)
		if cert.IsCA {
			return cert, nil
		}
	}
	return nil, ErrNoCAFound
}
