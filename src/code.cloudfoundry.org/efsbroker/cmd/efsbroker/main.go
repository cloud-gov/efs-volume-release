package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"code.cloudfoundry.org/clock"
	"code.cloudfoundry.org/debugserver"
	"code.cloudfoundry.org/efsbroker/utils"
	"code.cloudfoundry.org/existingvolumebroker"
	evbutils "code.cloudfoundry.org/existingvolumebroker/utils"
	"code.cloudfoundry.org/goshims/osshim"
	"code.cloudfoundry.org/lager/v3"
	"code.cloudfoundry.org/lager/v3/lagerflags"
	"code.cloudfoundry.org/service-broker-store/brokerstore"
	vmo "code.cloudfoundry.org/volume-mount-options"
	vmou "code.cloudfoundry.org/volume-mount-options/utils"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/efs"
	"github.com/pivotal-cf/brokerapi/v11"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/grouper"
	"github.com/tedsuo/ifrit/http_server"
)

var dataDir = flag.String(
	"dataDir",
	"",
	"[REQUIRED] - Broker's state will be stored here to persist across reboots",
)

var atAddress = flag.String(
	"listenAddr",
	"0.0.0.0:8999",
	"host:port to serve service broker API",
)

var servicesConfig = flag.String(
	"servicesConfig",
	"",
	"[REQUIRED] - Path to services config to register with cloud controller",
)
var efsToolsAddress = flag.String(
	"efsToolsAddress",
	"127.0.0.1:7090",
	"host:port to reach the efsdriver when creating volumes",
)
var serviceName = flag.String(
	"serviceName",
	"efsvolume",
	"name of the service to register with cloud controller",
)
var serviceId = flag.String(
	"serviceId",
	"service-guid",
	"ID of the service to register with cloud controller",
)

var dbDriver = flag.String(
	"dbDriver",
	"",
	"(optional) database driver name when using SQL to store broker state",
)

var dbHostname = flag.String(
	"dbHostname",
	"",
	"(optional) database hostname when using SQL to store broker state",
)
var dbPort = flag.String(
	"dbPort",
	"",
	"(optional) database port when using SQL to store broker state",
)

var dbName = flag.String(
	"dbName",
	"",
	"(optional) database name when using SQL to store broker state",
)

var dbCACertPath = flag.String(
	"dbCACertPath",
	"",
	"(optional) Path to CA Cert for database SSL connection",
)

var cfServiceName = flag.String(
	"cfServiceName",
	"",
	"(optional) For CF pushed apps, the service name in VCAP_SERVICES where we should find database credentials.  dbDriver must be defined if this option is set, but all other db parameters will be extracted from the service binding.",
)

var awsSubnetIds = flag.String(
	"awsSubnetIds",
	"",
	"list of comma-seperated aws subnet ids where mount targets will be created for each efs",
)
var awsAZs = flag.String(
	"awsAZs",
	"",
	"list of comma-seperated aws AZs (one per subnet id)",
)
var awsSecurityGroups = flag.String(
	"awsSecurityGroups",
	"",
	"list of comma separated aws security groups to assign to the mount points (one per subnet id)",
)

var allowedOptions = flag.String(
	"allowedOptions",
	"auto_cache,uid,gid",
	"A comma separated list of parameters allowed to be set in config.",
)

var defaultOptions = flag.String(
	"defaultOptions",
	"auto_cache:true",
	"A comma separated list of defaults specified as param:value. If a parameter has a default value and is not in the allowed list, this default value becomes a fixed value that cannot be overridden",
)

var credhubURL = flag.String(
	"credhubURL",
	"",
	"(optional) CredHub server URL when using CredHub to store broker state",
)

var credhubCACert = flag.String(
	"credhubCACert",
	"",
	"(optional) CA Cert for CredHub",
)

var uaaClientID = flag.String(
	"uaaClientID",
	"",
	"(optional) UAA client ID when using CredHub to store broker state",
)

var uaaClientSecret = flag.String(
	"uaaClientSecret",
	"",
	"(optional) UAA client secret when using CredHub to store broker state",
)

var uaaCACert = flag.String(
	"uaaCACert",
	"",
	"(optional) Path to CA Cert for UAA used for CredHub authorization",
)

var storeID = flag.String(
	"storeID",
	"efsbroker",
	"(optional) Store ID used to namespace instance details and bindings (credhub only)",
)

var (
	username string
	password string
)

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate
//counterfeiter:generate -o fakes/retired_store_fake.go . RetiredStore
type RetiredStore interface {
	IsRetired() (bool, error)
	brokerstore.Store
}

func main() {
	parseCommandLine()
	parseEnvironment()

	checkParams()

	logger, logSink := newLogger()
	logger.Info("starting")
	defer logger.Info("ends")

	verifyCredhubIsReachable(logger)

	server := createServer(logger)

	if dbgAddr := debugserver.DebugAddress(flag.CommandLine); dbgAddr != "" {
		server = utils.ProcessRunnerFor(grouper.Members{
			{Name: "debug-server", Runner: debugserver.Runner(dbgAddr, logSink)},
			{Name: "broker-api", Runner: server},
		})
	}

	process := ifrit.Invoke(server)
	logger.Info("started")
	utils.UntilTerminated(logger, process)
}

func parseCommandLine() {
	lagerflags.AddFlags(flag.CommandLine)
	debugserver.AddFlags(flag.CommandLine)
	flag.Parse()
}

func parseEnvironment() {
	username, _ = os.LookupEnv("USERNAME")
	password, _ = os.LookupEnv("PASSWORD")
	uaaClientSecretString, _ := os.LookupEnv("UAA_CLIENT_SECRET")
	if uaaClientSecretString != "" {
		uaaClientSecret = &uaaClientSecretString
	}
	uaaClientIDString, _ := os.LookupEnv("UAA_CLIENT_ID")
	if uaaClientIDString != "" {
		uaaClientID = &uaaClientIDString
	}

}

func checkParams() {
	if *dataDir == "" && *credhubURL == "" {
		fmt.Fprint(os.Stderr, "\nERROR: Either dataDir or credhubURL parameters must be provided.\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// if *awsSubnetIds == "" {
	// 	fmt.Fprint(os.Stderr, "\nERROR: Required parameter awsSubnetIds not defined.\n\n")
	// 	flag.Usage()
	// 	os.Exit(1)
	// }
}

func newLogger() (lager.Logger, *lager.ReconfigurableSink) {
	lagerConfig := lagerflags.ConfigFromFlags()
	lagerConfig.RedactSecrets = true

	return lagerflags.NewFromConfig("efsbroker", lagerConfig)
}
func verifyCredhubIsReachable(logger lager.Logger) {
	var client = &http.Client{
		Timeout: 30 * time.Second,
	}

	evbutils.IsThereAProxy(&osshim.OsShim{}, logger)

	resp, err := client.Get(*credhubURL + "/info")
	if err != nil {
		logger.Fatal("Unable to connect to credhub", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Fatal(fmt.Sprintf("Attempted to connect to credhub. Expected 200. Got %d", resp.StatusCode), nil, lager.Data{"response_headers": fmt.Sprintf("%v", resp.Header)})
	}
}

func parseVcapServices(logger lager.Logger, os osshim.Os) {
	// populate db parameters from VCAP_SERVICES and pitch a fit if there isn't one.
	services, hasValue := os.LookupEnv("VCAP_SERVICES")
	if !hasValue {
		logger.Fatal("missing-vcap-services-environment", errors.New("missing VCAP_SERVICES environment"))
	}

	stuff := map[string][]interface{}{}
	err := json.Unmarshal([]byte(services), &stuff)
	if err != nil {
		logger.Fatal("json-unmarshal-error", err)
	}

	stuff2, ok := stuff[*cfServiceName]
	if !ok {
		logger.Fatal("missing-service-binding", errors.New("VCAP_SERVICES missing specified db service"), lager.Data{"stuff": stuff})
	}

	stuff3 := stuff2[0].(map[string]interface{})

	credentials := stuff3["credentials"].(map[string]interface{})
	logger.Debug("credentials-parsed", lager.Data{"credentials": credentials})

}

func getByAlias(data map[string]interface{}, keys ...string) interface{} {
	for _, key := range keys {
		value, ok := data[key]
		if ok {
			return value
		}
	}
	return nil
}
func parseSubnets() []existingvolumebroker.Subnet {
	subnetIDs := strings.Split(*awsSubnetIds, ",")
	AZs := strings.Split(*awsAZs, ",")
	securityGroups := strings.Split(*awsSecurityGroups, ",")
	if len(subnetIDs) != len(AZs) || len(AZs) != len(securityGroups) {
		panic("arguments awsSubnetIds, awsAZs, and awsSecurityGroups must have the same number of entries")
	}

	ret := []existingvolumebroker.Subnet{}
	for i, s := range subnetIDs {
		ret = append(ret, existingvolumebroker.Subnet{ID: s, AZ: AZs[i], SecurityGroup: securityGroups[i]})
	}
	return ret
}

func createServer(logger lager.Logger) ifrit.Runner {
	session, err := session.NewSession()
	if isCfPushed() {
		parseVcapServices(logger, &osshim.OsShim{})
	}

	store := brokerstore.NewStore(
		logger,
		*credhubURL,
		*credhubCACert,
		*uaaClientID,
		*uaaClientSecret,
		*uaaCACert,
		*storeID,
	)

	retired, err := IsRetired(store)
	if err != nil {
		logger.Fatal("check-is-retired-failed", err)
	}

	if retired {
		logger.Fatal("retired-store", errors.New("Store is retired"))
	}

	cacheOptsValidator := vmo.UserOptsValidationFunc(validateCache)

	configMask, err := vmo.NewMountOptsMask(
		strings.Split(*allowedOptions, ","),
		vmou.ParseOptionStringToMap(*defaultOptions, ":"),
		map[string]string{
			"share": "source",
		},
		[]string{},
		[]string{"source"},
		cacheOptsValidator,
	)
	if err != nil {
		logger.Fatal("creating-config-mask-error", err)
	}
	logger.Debug("efsbroker-startup-config", lager.Data{"config-mask": configMask})

	config := aws.NewConfig()

	efsClient := efs.New(session, config)

	subnets := parseSubnets()

	services, err := NewServicesFromConfig(*servicesConfig)
	if err != nil {
		logger.Fatal("loading-services-config-error", err)
	}
	serviceBroker := existingvolumebroker.New(
		existingvolumebroker.BrokerTypeEFS,
		logger,
		services,
		&osshim.OsShim{},
		clock.NewClock(),
		store,
		configMask,
		efsClient,
		subnets,
		existingvolumebroker.NewProvisionOperation,
		existingvolumebroker.NewDeprovisionOperation,
	)

	credentials := brokerapi.BrokerCredentials{Username: username, Password: password}
	handler := brokerapi.New(serviceBroker, slog.New(lager.NewHandler(logger.Session("broker-api"))), credentials)

	return http_server.New(*atAddress, handler)
}

func isCfPushed() bool {
	return *cfServiceName != ""
}

func IsRetired(store brokerstore.Store) (bool, error) {
	if retiredStore, ok := store.(RetiredStore); ok {
		return retiredStore.IsRetired()
	}
	return false, nil
}

func validateCache(key string, val string) error {

	if key != "cache" {
		return nil
	}

	_, err := strconv.ParseBool(val)
	if err != nil {
		return errors.New(fmt.Sprintf("%s is not a valid value for cache", val))
	}

	return nil
}
