module code.cloudfoundry.org/efsbroker

go 1.22.6

replace code.cloudfoundry.org/efsdriver v0.0.0-20190712220027-6639a67b5d72 => ../efsdriver

require (
	code.cloudfoundry.org/clock v1.2.0
	code.cloudfoundry.org/debugserver v0.0.0-20240808182508-aa80400f8069
	code.cloudfoundry.org/dockerdriver v0.0.0-20240620154825-441e44b5dbb3
	code.cloudfoundry.org/efsdriver v0.0.0-20190712220027-6639a67b5d72
	code.cloudfoundry.org/goshims v0.38.0
	code.cloudfoundry.org/lager/v3 v3.0.3
	code.cloudfoundry.org/service-broker-store v0.87.0
	github.com/aws/aws-sdk-go v1.55.5
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.34.1
	github.com/pivotal-cf/brokerapi v6.4.2+incompatible
	github.com/pivotal-cf/brokerapi/v11 v11.0.0
	github.com/tedsuo/ifrit v0.0.0-20230516164442-7862c310ad26
)

require (
	code.cloudfoundry.org/cfhttp v2.0.0+incompatible // indirect
	code.cloudfoundry.org/cfhttp/v2 v2.1.0 // indirect
	code.cloudfoundry.org/credhub-cli v0.0.0-20240429130629-19663e8d3d05 // indirect
	code.cloudfoundry.org/lager v2.0.0+incompatible // indirect
	code.cloudfoundry.org/tlsconfig v0.0.0-20240522170710-79df114af82a // indirect
	code.cloudfoundry.org/volume-mount-options v0.95.0 // indirect
	code.cloudfoundry.org/volumedriver v0.96.0 // indirect
	github.com/bmizerany/pat v0.0.0-20210406213842-e4b6760bdd6f // indirect
	github.com/cloudfoundry/go-socks5 v0.0.0-20180221174514-54f73bdb8a8e // indirect
	github.com/cloudfoundry/socks5-proxy v0.2.116 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/go-chi/chi/v5 v5.0.12 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/pprof v0.0.0-20240727154555-813a5fbdbec8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/mux v1.8.1 // indirect
	github.com/hashicorp/go-version v1.6.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/nxadm/tail v1.4.11 // indirect
	github.com/onsi/ginkgo/v2 v2.20.0 // indirect
	github.com/openzipkin/zipkin-go v0.4.3 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/tedsuo/rata v1.0.0 // indirect
	golang.org/x/crypto v0.26.0 // indirect
	golang.org/x/exp v0.0.0-20240808152545-0cdaa3abc0fa // indirect
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/sys v0.24.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	golang.org/x/tools v0.24.0 // indirect
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
	gopkg.in/ldap.v2 v2.5.1 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
