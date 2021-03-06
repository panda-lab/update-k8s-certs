module github.com/panda-lab/update-k8s-certs

go 1.15

require (
	github.com/pkg/errors v0.9.1
	k8s.io/apimachinery v0.0.0
	k8s.io/client-go v11.0.0+incompatible
	k8s.io/klog/v2 v2.5.0
	k8s.io/kubernetes v1.20.2-rc.0
)

replace (
	k8s.io/api => ../../../k8s.io/kubernetes/staging/src/k8s.io/api
	k8s.io/apiextensions-apiserver => ../../../k8s.io/kubernetes/staging/src/k8s.io/apiextensions-apiserver
	k8s.io/apimachinery => ../../../k8s.io/kubernetes/staging/src/k8s.io/apimachinery
	k8s.io/apiserver => ../../../k8s.io/kubernetes/staging/src/k8s.io/apiserver
	k8s.io/cli-runtime => ../../../k8s.io/kubernetes/staging/src/k8s.io/cli-runtime
	k8s.io/client-go => ../../../k8s.io/kubernetes/staging/src/k8s.io/client-go
	k8s.io/cloud-provider => ../../../k8s.io/kubernetes/staging/src/k8s.io/cloud-provider
	k8s.io/cluster-bootstrap => ../../../k8s.io/kubernetes/staging/src/k8s.io/cluster-bootstrap
	k8s.io/code-generator => ../../../k8s.io/kubernetes/staging/src/k8s.io/code-generator
	k8s.io/component-base => ../../../k8s.io/kubernetes/staging/src/k8s.io/component-base
	k8s.io/component-helpers => ../../../k8s.io/kubernetes/staging/src/k8s.io/component-helpers
	k8s.io/controller-manager => ../../../k8s.io/kubernetes/staging/src/k8s.io/controller-manager
	k8s.io/cri-api => ../../../k8s.io/kubernetes/staging/src/k8s.io/cri-api
	k8s.io/csi-translation-lib => ../../../k8s.io/kubernetes/staging/src/k8s.io/csi-translation-lib
	k8s.io/kube-aggregator => ../../../k8s.io/kubernetes/staging/src/k8s.io/kube-aggregator
	k8s.io/kube-controller-manager => ../../../k8s.io/kubernetes/staging/src/k8s.io/kube-controller-manager
	k8s.io/kube-proxy => ../../../k8s.io/kubernetes/staging/src/k8s.io/kube-proxy
	k8s.io/kube-scheduler => ../../../k8s.io/kubernetes/staging/src/k8s.io/kube-scheduler
	k8s.io/kubectl => ../../../k8s.io/kubernetes/staging/src/k8s.io/kubectl
	k8s.io/kubelet => ../../../k8s.io/kubernetes/staging/src/k8s.io/kubelet
	k8s.io/legacy-cloud-providers => ../../../k8s.io/kubernetes/staging/src/k8s.io/legacy-cloud-providers
	k8s.io/metrics => ../../../k8s.io/kubernetes/staging/src/k8s.io/metrics
	k8s.io/mount-utils => ../../../k8s.io/kubernetes/staging/src/k8s.io/mount-utils
	k8s.io/sample-apiserver => ../../../k8s.io/kubernetes/staging/src/k8s.io/sample-apiserver
)
