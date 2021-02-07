package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/pkg/errors"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/klog/v2"
	kubeadmapi "k8s.io/kubernetes/cmd/kubeadm/app/apis/kubeadm"
	kubeadmconstants "k8s.io/kubernetes/cmd/kubeadm/app/constants"
	certsphase "k8s.io/kubernetes/cmd/kubeadm/app/phases/certs"
	kubeadmutil "k8s.io/kubernetes/cmd/kubeadm/app/util"
	kubeconfigutil "k8s.io/kubernetes/cmd/kubeadm/app/util/kubeconfig"
	"k8s.io/kubernetes/cmd/kubeadm/app/util/pkiutil"
	"os"
	"path/filepath"
)

// clientCertAuth struct holds info required to build a client certificate to provide authentication info in a kubeconfig object
type clientCertAuth struct {
	CAKey         crypto.Signer
	Organizations []string
}

// tokenAuth struct holds info required to use a token to provide authentication info in a kubeconfig object
type tokenAuth struct {
	Token string `datapolicy:"token"`
}
type kubeConfigSpec struct {
	CACert         *x509.Certificate
	APIServer      string
	ClientName     string
	TokenAuth      *tokenAuth      `datapolicy:"token"`
	ClientCertAuth *clientCertAuth `datapolicy:"security-key"`
}

func getKubeConfigSpecsBase(cfg *kubeadmapi.InitConfiguration) (map[string]*kubeConfigSpec, error) {
	controlPlaneEndpoint, err := kubeadmutil.GetControlPlaneEndpoint(cfg.ControlPlaneEndpoint, &cfg.LocalAPIEndpoint)
	if err != nil {
		return nil, err
	}
	localAPIEndpoint, err := kubeadmutil.GetLocalAPIEndpoint(&cfg.LocalAPIEndpoint)
	if err != nil {
		return nil, err
	}

	return map[string]*kubeConfigSpec{
		kubeadmconstants.AdminKubeConfigFileName: {
			APIServer:  controlPlaneEndpoint,
			ClientName: "kubernetes-admin",
			ClientCertAuth: &clientCertAuth{
				Organizations: []string{kubeadmconstants.SystemPrivilegedGroup},
			},
		},
		kubeadmconstants.KubeletKubeConfigFileName: {
			APIServer:  controlPlaneEndpoint,
			ClientName: fmt.Sprintf("%s%s", kubeadmconstants.NodesUserPrefix, cfg.NodeRegistration.Name),
			ClientCertAuth: &clientCertAuth{
				Organizations: []string{kubeadmconstants.NodesGroup},
			},
		},
		kubeadmconstants.ControllerManagerKubeConfigFileName: {
			APIServer:      localAPIEndpoint,
			ClientName:     kubeadmconstants.ControllerManagerUser,
			ClientCertAuth: &clientCertAuth{},
		},
		kubeadmconstants.SchedulerKubeConfigFileName: {
			APIServer:      localAPIEndpoint,
			ClientName:     kubeadmconstants.SchedulerUser,
			ClientCertAuth: &clientCertAuth{},
		},
	}, nil
}

// getKubeConfigSpecs returns all KubeConfigSpecs actualized to the context of the current InitConfiguration
// NB. this method holds the information about how kubeadm creates kubeconfig files.
func getKubeConfigSpecs(cfg *kubeadmapi.InitConfiguration) (map[string]*kubeConfigSpec, error) {
	caCert, caKey, err := pkiutil.TryLoadCertAndKeyFromDisk(cfg.CertificatesDir, kubeadmconstants.CACertAndKeyBaseName)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't create a kubeconfig; the CA files couldn't be loaded")
	}
	// Validate period
	certsphase.CheckCertificatePeriodValidity(kubeadmconstants.CACertAndKeyBaseName, caCert)

	configs, err := getKubeConfigSpecsBase(cfg)
	if err != nil {
		return nil, err
	}
	for _, spec := range configs {
		spec.CACert = caCert
		spec.ClientCertAuth.CAKey = caKey
	}
	return configs, nil
}

func newClientCertConfigFromKubeConfigSpec(spec *kubeConfigSpec) pkiutil.CertConfig {
	return pkiutil.CertConfig{
		Config: certutil.Config{
			CommonName:   spec.ClientName,
			Organization: spec.ClientCertAuth.Organizations,
			Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
	}
}
func createKubeConfigFileIfNotExists(outDir, filename string, config *clientcmdapi.Config) error {
	kubeConfigFilePath := filepath.Join(outDir, filename)

	err := validateKubeConfig(outDir, filename, config)
	if err != nil {
		// Check if the file exist, and if it doesn't, just write it to disk
		if !os.IsNotExist(err) {
			return err
		}
		fmt.Printf("[kubeconfig] Writing %q kubeconfig file\n", filename)
		err = kubeconfigutil.WriteToDisk(kubeConfigFilePath, config)
		if err != nil {
			return errors.Wrapf(err, "failed to save kubeconfig file %q on disk", kubeConfigFilePath)
		}
		return nil
	}
	// kubeadm doesn't validate the existing kubeconfig file more than this (kubeadm trusts the client certs to be valid)
	// Basically, if we find a kubeconfig file with the same path; the same CA cert and the same server URL;
	// kubeadm thinks those files are equal and doesn't bother writing a new file
	fmt.Printf("[kubeconfig] Using existing kubeconfig file: %q\n", kubeConfigFilePath)

	return nil
}
func validateKubeConfig(outDir, filename string, config *clientcmdapi.Config) error {
	kubeConfigFilePath := filepath.Join(outDir, filename)

	if _, err := os.Stat(kubeConfigFilePath); err != nil {
		return err
	}

	// The kubeconfig already exists, let's check if it has got the same CA and server URL
	currentConfig, err := clientcmd.LoadFromFile(kubeConfigFilePath)
	if err != nil {
		return errors.Wrapf(err, "failed to load kubeconfig file %s that already exists on disk", kubeConfigFilePath)
	}

	expectedCtx, exists := config.Contexts[config.CurrentContext]
	if !exists {
		return errors.Errorf("failed to find expected context %s", config.CurrentContext)
	}
	expectedCluster := expectedCtx.Cluster
	currentCtx, exists := currentConfig.Contexts[currentConfig.CurrentContext]
	if !exists {
		return errors.Errorf("failed to find CurrentContext in Contexts of the kubeconfig file %s", kubeConfigFilePath)
	}
	currentCluster := currentCtx.Cluster
	if currentConfig.Clusters[currentCluster] == nil {
		return errors.Errorf("failed to find the given CurrentContext Cluster in Clusters of the kubeconfig file %s", kubeConfigFilePath)
	}

	// Make sure the compared CAs are whitespace-trimmed. The function clientcmd.LoadFromFile() just decodes
	// the base64 CA and places it raw in the v1.Config object. In case the user has extra whitespace
	// in the CA they used to create a kubeconfig this comparison to a generated v1.Config will otherwise fail.
	caCurrent := bytes.TrimSpace(currentConfig.Clusters[currentCluster].CertificateAuthorityData)
	caExpected := bytes.TrimSpace(config.Clusters[expectedCluster].CertificateAuthorityData)

	// If the current CA cert on disk doesn't match the expected CA cert, error out because we have a file, but it's stale
	if !bytes.Equal(caCurrent, caExpected) {
		return errors.Errorf("a kubeconfig file %q exists already but has got the wrong CA cert", kubeConfigFilePath)
	}
	// If the current API Server location on disk doesn't match the expected API server, show a warning
	if currentConfig.Clusters[currentCluster].Server != config.Clusters[expectedCluster].Server {
		klog.Warningf("a kubeconfig file %q exists already but has an unexpected API Server URL: expected: %s, got: %s",
			kubeConfigFilePath, config.Clusters[expectedCluster].Server, currentConfig.Clusters[currentCluster].Server)
	}

	return nil
}
func buildKubeConfigFromSpec(cfg *kubeadmapi.InitConfiguration, x string) (*clientcmdapi.Config, error) {
	caCert, caKey, err := certsphase.LoadCertificateAuthority(cfg.CertificatesDir, kubeadmconstants.CACertAndKeyBaseName)
	if err != nil {
		fmt.Println(err)
	}
	specs, err := getKubeConfigSpecs(cfg)
	spec := specs[x]
	clientCertConfig := newClientCertConfigFromKubeConfigSpec(spec)

	clientCert, clientKey, err := NewCertAndKey(caCert, caKey, &clientCertConfig)
	if err != nil {
		return nil, errors.Wrapf(err, "failure while creating %s client certificate", spec.ClientName)
	}

	encodedClientKey, err := keyutil.MarshalPrivateKeyToPEM(clientKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal private key to PEM")
	}
	// create a kubeconfig with the client certs
	return kubeconfigutil.CreateWithCerts(
		spec.APIServer,
		cfg.ClusterName,
		spec.ClientName,
		pkiutil.EncodeCertPEM(spec.CACert),
		encodedClientKey,
		pkiutil.EncodeCertPEM(clientCert),
	), nil

}
func createKubeConfigFiles(outDir string, cfg *kubeadmapi.InitConfiguration, kubeConfigFileName string) error {
	config, err := buildKubeConfigFromSpec(cfg, kubeConfigFileName)
	if err != nil {
		return err
	}
	if err = createKubeConfigFileIfNotExists(outDir, kubeConfigFileName, config); err != nil {
		return err
	}
	return nil
}
