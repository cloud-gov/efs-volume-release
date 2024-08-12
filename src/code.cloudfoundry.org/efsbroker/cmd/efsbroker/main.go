package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"

	"code.cloudfoundry.org/clock"
	"code.cloudfoundry.org/debugserver"
	"code.cloudfoundry.org/efsbroker/efsbroker"
	"code.cloudfoundry.org/efsbroker/utils"
	"code.cloudfoundry.org/efsdriver/efsvoltools/voltoolshttp"
	"code.cloudfoundry.org/goshims/osshim"
	"code.cloudfoundry.org/lager/v3"
	"code.cloudfoundry.org/lager/v3/lagerflags"
	"code.cloudfoundry.org/service-broker-store/brokerstore"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/efs"
	"github.com/kelseyhightower/envconfig"
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

var username = flag.String(
	"username",
	"admin",
	"basic auth username to verify on incoming requests",
)
var password = flag.String(
	"password",
	"admin",
	"basic auth password to verify on incoming requests",
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

var uaaCACertPath = flag.String(
	"uaaCACertPath",
	"",
	"(optional) Path to CA Cert for UAA used for CredHub authorization",
)

var storeID = flag.String(
	"storeID",
	"nfsbroker",
	"(optional) Store ID used to namespace instance details and bindings (credhub only)",
)

type StoreConfig struct {
	CredHubURL        string `envconfig:"CH_CRED_HUB_URL"`
	UaaURL            string `envconfig:"CH_UAA_URL"`
	UaaClientName     string `envconfig:"CH_UAA_CLIENT_NAME"`
	UaaClientSecret   string `envconfig:"CH_UAA_CLIENT_SECRET"`
	SkipSSLValidation bool   `envconfig:"CH_SKIP_SSL_VALIDATION"`
	CaCertFile        string `envconfig:"CH_CA_CERT_FILE"`
}

var (
	dbUsername string
	dbPassword string
)

func main() {
	parseCommandLine()
	parseEnvironment()

	checkParams()

	logger, logTap := newLogger()
	logger.Info("starting")
	defer logger.Info("ends")

	server := createServer(logger)

	if dbgAddr := debugserver.DebugAddress(flag.CommandLine); dbgAddr != "" {
		server = utils.ProcessRunnerFor(grouper.Members{
			{Name: "debug-server", Runner: debugserver.Runner(dbgAddr, logTap)},
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
	dbUsername, _ = os.LookupEnv("DB_USERNAME")
	dbPassword, _ = os.LookupEnv("DB_PASSWORD")
}

func checkParams() {
	if *dataDir == "" && *dbDriver == "" {
		fmt.Fprint(os.Stderr, "\nERROR: Either dataDir or db parameters must be provided.\n\n")
		flag.Usage()
		os.Exit(1)
	}

	if *awsSubnetIds == "" {
		fmt.Fprint(os.Stderr, "\nERROR: Required parameter awsSubnetIds not defined.\n\n")
		flag.Usage()
		os.Exit(1)
	}
}

func newLogger() (lager.Logger, *lager.ReconfigurableSink) {
	lagerConfig := lagerflags.ConfigFromFlags()
	lagerConfig.RedactSecrets = true

	return lagerflags.NewFromConfig("efsbroker", lagerConfig)
}

func parseVcapServices(logger lager.Logger, os osshim.Os) {
	if *dbDriver == "" {
		logger.Fatal("missing-db-driver-parameter", errors.New("dbDriver parameter is required for cf deployed broker"))
	}

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

	dbUsername = credentials["username"].(string)
	dbPassword = credentials["password"].(string)
	*dbHostname = credentials["hostname"].(string)
	if *dbPort, ok = credentials["port"].(string); !ok {
		*dbPort = fmt.Sprintf("%.0f", credentials["port"].(float64))
	}
	*dbName = credentials["name"].(string)
}

func parseSubnets() []efsbroker.Subnet {
	subnetIDs := strings.Split(*awsSubnetIds, ",")
	AZs := strings.Split(*awsAZs, ",")
	securityGroups := strings.Split(*awsSecurityGroups, ",")
	if len(subnetIDs) != len(AZs) || len(AZs) != len(securityGroups) {
		panic("arguments awsSubnetIds, awsAZs, and awsSecurityGroups must have the same number of entries")
	}

	ret := []efsbroker.Subnet{}
	for i, s := range subnetIDs {
		ret = append(ret, efsbroker.Subnet{ID: s, AZ: AZs[i], SecurityGroup: securityGroups[i]})
	}
	return ret
}

func createServer(logger lager.Logger) ifrit.Runner {
	session, err := session.NewSession()
	if err != nil {
		panic(err)
	}

	if *cfServiceName != "" {
		parseVcapServices(logger, &osshim.OsShim{})
	}

	var store StoreConfig
	errstore := envconfig.Process("", &store)
	if errstore != nil {
		log.Fatal(errstore.Error())
	}
	newstore := brokerstore.NewStore(
		logger,
		store.CredHubURL,
		store.CaCertFile,
		store.UaaClientName,
		store.UaaClientSecret,
		store.CaCertFile,
		*storeID,
	)

	config := aws.NewConfig()

	efsClient := efs.New(session, config)

	efsTools, err := voltoolshttp.NewRemoteClient("http://" + *efsToolsAddress)
	if err != nil {
		panic(err)
	}

	subnets := parseSubnets()

	serviceBroker := efsbroker.New(
		logger,
		*serviceName,
		*serviceId,
		*dataDir,
		&osshim.OsShim{},
		clock.NewClock(),
		newstore,
		efsClient, subnets, efsTools, efsbroker.NewProvisionOperation, efsbroker.NewDeprovisionOperation)

	credentials := brokerapi.BrokerCredentials{Username: *username, Password: *password}
	handler := brokerapi.New(serviceBroker, slog.New(lager.NewHandler(logger.Session("broker-api"))), credentials)

	return http_server.New(*atAddress, handler)
}
