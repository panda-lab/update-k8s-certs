package main

import (
	"crypto/x509"
	"fmt"
	"github.com/pkg/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeadmapi "k8s.io/kubernetes/cmd/kubeadm/app/apis/kubeadm"
	kubeadmconstants "k8s.io/kubernetes/cmd/kubeadm/app/constants"
	certsphase "k8s.io/kubernetes/cmd/kubeadm/app/phases/certs"
	"k8s.io/kubernetes/cmd/kubeadm/app/util/pkiutil"
)

const CertificatesDir = "/tmp/pki"

var (
	csrOnly bool
	csrDir  string
)

func main() {

	newCertSubPhases()

	cfg := &kubeadmapi.InitConfiguration{
		TypeMeta: v1.TypeMeta{},

		ClusterConfiguration: kubeadmapi.ClusterConfiguration{
			CertificatesDir: CertificatesDir,
			ClusterName:     "kubernetes",
		},
		BootstrapTokens:  nil,
		NodeRegistration: kubeadmapi.NodeRegistrationOptions{Name: "kubesphere-1"},
		LocalAPIEndpoint: kubeadmapi.APIEndpoint{
			AdvertiseAddress: "10.127.253.248",
			BindPort:         6443,
		},
	}
	err := createKubeConfigFiles("/tmp/pki", cfg, kubeadmconstants.KubeletKubeConfigFileName)
	if err != nil {
		fmt.Println(err)
	}
}

func newCertSubPhases() {

	// certificate that is preceded by the CAs that sign them.
	var lastCACert *certsphase.KubeadmCert
	for _, cert := range certsphase.GetDefaultCertList() {
		if cert.CAName == "" {
			runCAPhase(cert)

			lastCACert = cert
		} else {
			err := runCertPhase(cert, lastCACert)
			if err != nil {
				fmt.Println(err)
			}
		}
	}
	certsphase.CreateServiceAccountKeyAndPublicKeyFiles(CertificatesDir, x509.RSA)
}

func runCAPhase(ca *certsphase.KubeadmCert) error {

	if cert, err := pkiutil.TryLoadCertFromDisk(CertificatesDir, ca.BaseName); err == nil {
		certsphase.CheckCertificatePeriodValidity(ca.BaseName, cert)

		if _, err := pkiutil.TryLoadKeyFromDisk(CertificatesDir, ca.BaseName); err == nil {
			fmt.Printf("[certs] Using existing %s certificate authority\n", ca.BaseName)
			return nil
		}
		fmt.Printf("[certs] Using existing %s keyless certificate authority\n", ca.BaseName)
		return nil
	}

	return CreateCACertAndKeyFiles(ca, &kubeadmapi.InitConfiguration{
		TypeMeta:             v1.TypeMeta{},
		ClusterConfiguration: kubeadmapi.ClusterConfiguration{CertificatesDir: CertificatesDir},
		BootstrapTokens:      nil,
		NodeRegistration:     kubeadmapi.NodeRegistrationOptions{},
		LocalAPIEndpoint:     kubeadmapi.APIEndpoint{},
		CertificateKey:       "",
	})
}

func runCertPhase(cert *certsphase.KubeadmCert, caCert *certsphase.KubeadmCert) error {

	if certData, _, err := pkiutil.TryLoadCertAndKeyFromDisk(CertificatesDir, cert.BaseName); err == nil {
		certsphase.CheckCertificatePeriodValidity(cert.BaseName, certData)

		caCertData, err := pkiutil.TryLoadCertFromDisk(CertificatesDir, caCert.BaseName)
		if err != nil {
			return errors.Wrapf(err, "couldn't load CA certificate %s", caCert.Name)
		}

		certsphase.CheckCertificatePeriodValidity(caCert.BaseName, caCertData)

		if err := certData.CheckSignatureFrom(caCertData); err != nil {
			return errors.Wrapf(err, "[certs] certificate %s not signed by CA certificate %s", cert.BaseName, caCert.BaseName)
		}

		fmt.Printf("[certs] Using existing %s certificate and key on disk\n", cert.BaseName)
		return nil
	}

	if csrOnly {
		fmt.Printf("[certs] Generating CSR for %s instead of certificate\n", cert.BaseName)
		if csrDir == "" {
			csrDir = CertificatesDir
		}

		return certsphase.CreateCSR(cert, &kubeadmapi.InitConfiguration{
			TypeMeta:             v1.TypeMeta{},
			ClusterConfiguration: kubeadmapi.ClusterConfiguration{CertificatesDir: CertificatesDir},
			BootstrapTokens:      nil,
			NodeRegistration:     kubeadmapi.NodeRegistrationOptions{},
			LocalAPIEndpoint:     kubeadmapi.APIEndpoint{},
			CertificateKey:       "",
		}, csrDir)
	}

	// create the new certificate (or use existing)
	return CreateCertAndKeyFilesWithCA(cert, caCert, &kubeadmapi.InitConfiguration{
		TypeMeta: v1.TypeMeta{},
		NodeRegistration: kubeadmapi.NodeRegistrationOptions{
			Name: "etcd1.bonc.local",
		},
		ClusterConfiguration: kubeadmapi.ClusterConfiguration{
			CertificatesDir: CertificatesDir,
			Networking: kubeadmapi.Networking{
				ServiceSubnet: "10.96.0.0/16",
				PodSubnet:     "172.16.0.0/16",
				DNSDomain:     "cluster.local",
			},
			ControlPlaneEndpoint: "10.127.253.100",
			APIServer: kubeadmapi.APIServer{
				ControlPlaneComponent: kubeadmapi.ControlPlaneComponent{},
				CertSANs:              []string{"10.127.253.248", "10.127.253.245", "10.127.253.246", "10.127.253.100"},
			},
			Etcd: kubeadmapi.Etcd{
				Local: &kubeadmapi.LocalEtcd{
					ServerCertSANs: []string{"10.127.253.248", "10.127.253.245", "10.127.253.246", "10.127.253.100"},
					PeerCertSANs:   []string{"10.127.253.248", "10.127.253.245", "10.127.253.246", "10.127.253.100"},
				},
			},
		},
		LocalAPIEndpoint: kubeadmapi.APIEndpoint{AdvertiseAddress: "1.1.1.1"},
	})
}
