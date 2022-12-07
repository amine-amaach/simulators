package services

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/amine-amaach/simulators/ioTSensorsOPCUA/utils"

	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
	"golang.org/x/crypto/bcrypt"
)

type UaSrvService struct {
	server *server.Server
}

func (uaServer UaSrvService) GetServer() *server.Server {
	return uaServer.server
}

func NewUaSrvService(host string, port int, userIds []ua.UserNameIdentity, certificateAdditions *utils.Certificate) *UaSrvService {
	srv, err := createUaServer(host, port, userIds, certificateAdditions)
	if err != nil {
		// log
		os.Exit(1)
	}
	nsu := "http://github.com/amine-amaach/simulators/ioTSensorsOPCUA"
	// add 'SimulatorsProject' object.
	ioTSensors := server.NewObjectNode(
		ua.NodeIDString{NamespaceIndex: srv.NamespaceManager().Add(nsu), ID: "IoTSensors"},
		ua.QualifiedName{NamespaceIndex: srv.NamespaceManager().Add(nsu), Name: "IoTSensors"},
		ua.LocalizedText{Text: "IoT Sensors"},
		ua.LocalizedText{Text: "A parent object for the IoT sensors."},
		nil,
		[]ua.Reference{ // add property to 'SimulatorsProject' object
			{
				ReferenceTypeID: ua.ReferenceTypeIDOrganizes,
				IsInverse:       true,
				TargetID:        ua.ExpandedNodeID{NodeID: ua.ObjectIDObjectsFolder},
			},
		},
		0,
	)
	srv.NamespaceManager().AddNode(ioTSensors)
	return &UaSrvService{server: srv}
}

func createUaServer(host string, port int, userIds []ua.UserNameIdentity, certificateAdditions *utils.Certificate) (*server.Server, error) {
	if err := ensurePKI(certificateAdditions, host); err != nil {
		log.Println(err)
	}
	// create the endpoint url from hostname and port
	endpointURL := fmt.Sprintf("opc.tcp://%s:%d", host, port)
	// create and return an opcua server
	return server.New(
		ua.ApplicationDescription{
			ApplicationURI: fmt.Sprintf("urn:%s:IoTSensorsUaServer", host),
			ProductURI:     "http://github.com/awcullen/opcua",
			ApplicationName: ua.LocalizedText{
				Text:   fmt.Sprintf("IoTSensorsUaServer@%s", host),
				Locale: "en",
			},
			ApplicationType:     ua.ApplicationTypeServer,
			GatewayServerURI:    "",
			DiscoveryProfileURI: "",
			DiscoveryURLs:       []string{endpointURL},
		},
		"./uaServerCerts/pki/server.crt",
		"./uaServerCerts/pki/server.key",
		endpointURL,
		server.WithBuildInfo(
			ua.BuildInfo{
				ProductURI:       "http://github.com/awcullen/opcua",
				ManufacturerName: "awcullen",
				ProductName:      "IoTSensorsUaServer",
				SoftwareVersion:  "latest",
			}),
		server.WithAnonymousIdentity(true),
		server.WithAuthenticateUserNameIdentityFunc(func(userIdentity ua.UserNameIdentity, applicationURI string, endpointURL string) error {
			encryptPasswords(userIds)
			valid := false
			for _, user := range userIds {
				if user.UserName == userIdentity.UserName {
					if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userIdentity.Password)); err == nil {
						valid = true
						break
					}
				}
			}
			if !valid {
				return ua.BadUserAccessDenied
			}
			// log.Printf("Login user: %s from %s\n", userIdentity.UserName, applicationURI)
			return nil
		}),
		server.WithAnonymousIdentity(true),
		server.WithSecurityPolicyNone(true),
		server.WithInsecureSkipVerify(),
		// server.WithTrace(),
		server.WithServerDiagnostics(true),
	)
}

func encryptPasswords(userIds []ua.UserNameIdentity) {
	for i := range userIds {
		hash, _ := bcrypt.GenerateFromPassword([]byte(userIds[i].Password), 8)
		userIds[i].Password = string(hash)
	}
}

func ensurePKI(certificateAdditions *utils.Certificate, host string) error {

	// check if ../uaServerCerts/pki already exists
	if _, err := os.Stat("./uaServerCerts/pki"); !os.IsNotExist(err) {
		return nil
	}

	// make a pki directory, if not exist
	if err := os.MkdirAll("./uaServerCerts/pki", os.ModeDir|0755); err != nil {
		return err
	}

	// create a server certificate
	if err := createNewCertificate("IoTSensorsUaServer", certificateAdditions, host); err != nil {
		return err
	}

	return nil
}

func createNewCertificate(appName string, certificateAdditions *utils.Certificate, host string) error {
	// create a key pair.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return ua.BadCertificateInvalid
	}

	// get certificates path
	certFile := "./uaServerCerts/pki/server.crt"
	keyFile := "./uaServerCerts/pki/server.key"

	// get local ip address.
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return ua.BadCertificateInvalid
	}
	conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)

	// create a certificate.
	applicationURI, _ := url.Parse(fmt.Sprintf("urn:%s:%s", host, appName))
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	subjectKeyHash := sha1.New()
	subjectKeyHash.Write(key.PublicKey.N.Bytes())
	subjectKeyId := subjectKeyHash.Sum(nil)

	var dnsNames = make([]string, 0, len(certificateAdditions.AdditionalHosts)+1)
	dnsNames = append(dnsNames, host)
	for _, h := range certificateAdditions.AdditionalHosts {
		dnsNames = append(dnsNames, h)
	}

	var ipAddresses = make([]net.IP, 0, len(certificateAdditions.AdditionalIPs)+1)
	ipAddresses = append(ipAddresses, localAddr.IP)
	for _, ipString := range certificateAdditions.AdditionalIPs {
		ip := net.ParseIP(ipString)
		if ip == nil {
			fmt.Println(utils.Colorize(fmt.Sprintf("Invalid IP %s", ipString), utils.Red))
			continue
		}
		ipAddresses = append(ipAddresses, ip)
	}

	uris := []*url.URL{applicationURI}
	for _, h := range certificateAdditions.AdditionalHosts {
		u, e := url.Parse(fmt.Sprintf("urn:%s:%s", h, appName))
		if e != nil {
			continue
		}
		uris = append(uris, u)
		// Commented out because some OPC-UA clients don't like this
		// u, e = url.Parse(fmt.Sprintf("urn:%s", h))
		// if e != nil {
		// 	continue
		// }
		// uris = append(uris, u)
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: appName},
		SubjectKeyId:          subjectKeyId,
		AuthorityKeyId:        subjectKeyId,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
		URIs:                  uris,
	}

	rawcrt, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return ua.BadCertificateInvalid
	}

	if f, err := os.Create(certFile); err == nil {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: rawcrt}
		if err := pem.Encode(f, block); err != nil {
			f.Close()
			return err
		}
		f.Close()
	} else {
		return err
	}

	if f, err := os.Create(keyFile); err == nil {
		block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
		if err := pem.Encode(f, block); err != nil {
			f.Close()
			return err
		}
		f.Close()
	} else {
		return err
	}

	return nil
}
