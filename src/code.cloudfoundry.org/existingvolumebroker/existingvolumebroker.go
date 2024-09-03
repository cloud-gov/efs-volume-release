package existingvolumebroker

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"sync"

	"code.cloudfoundry.org/clock"
	"code.cloudfoundry.org/goshims/osshim"
	"code.cloudfoundry.org/lager/v3"
	"code.cloudfoundry.org/service-broker-store/brokerstore"
	vmo "code.cloudfoundry.org/volume-mount-options"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/efs"
	"github.com/pivotal-cf/brokerapi/v11/domain"
	"github.com/pivotal-cf/brokerapi/v11/domain/apiresponses"
)

const (
	DEFAULT_CONTAINER_PATH = "/var/vcap/data"
	SHARE_KEY              = "share"
	SOURCE_KEY             = "source"
	VERSION_KEY            = "version"
	PermissionVolumeMount  = domain.RequiredPermission("volume_mount")
	DefaultContainerPath   = "/var/vcap/data"
	ServiceName            = "efs"
	RootPath               = ":/"
)

var (
	ErrNoMountTargets         = errors.New("no mount targets found")
	ErrMountTargetUnavailable = errors.New("mount target not in available state")
)

type EFSInstance struct {
	domain.ProvisionDetails
	EfsId         string             `json:"EfsId"`
	FsState       string             `json:"FsState"`
	MountId       string             `json:"MountId"`
	MountState    string             `json:"MountState"`
	MountPermsSet bool               `json:"MountPermsSet"`
	MountIp       string             `json:"MountIp"`
	MountIds      []string           `json:"MountIds"`
	MountStates   []string           `json:"MountStates"`
	MountIps      []string           `json:"MountIps"`
	MountAZs      []string           `json:"MountAZs"`
	Err           *OperationStateErr `json:"Err"`
}

type dynamicState struct {
	InstanceMap map[string]EFSInstance
	BindingMap  map[string]domain.BindDetails
}

type lock interface {
	Lock()
	Unlock()
}

type Subnet struct {
	ID            string
	AZ            string
	SecurityGroup string
}

type BrokerType int

const (
	BrokerTypeNFS BrokerType = iota
	BrokerTypeSMB
	BrokerTypeEFS
)

type Broker struct {
	brokerType              BrokerType
	logger                  lager.Logger
	efsService              EFSService
	subnets                 []Subnet
	os                      osshim.Os
	mutex                   lock
	clock                   clock.Clock
	ProvisionOperation      func(logger lager.Logger, instanceID string, details domain.ProvisionDetails, efsService EFSService, subnets []Subnet, clock Clock, updateCb func(*OperationState)) Operation
	DeprovisionOperation    func(logger lager.Logger, efsService EFSService, clock Clock, spec DeprovisionOperationSpec, updateCb func(*OperationState)) Operation
	store                   brokerstore.Store
	services                Services
	configMask              vmo.MountOptsMask
	DisallowedBindOverrides []string
}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate
//counterfeiter:generate -o fakes/fake_services.go . Services
type Services interface {
	List() []domain.Service
}

func New(
	brokerType BrokerType,
	logger lager.Logger,
	services Services,
	os osshim.Os,
	clock clock.Clock,
	store brokerstore.Store,
	configMask vmo.MountOptsMask,
	efsService EFSService, subnets []Subnet,
	provisionOperation func(logger lager.Logger, instanceID string, details domain.ProvisionDetails, efsService EFSService, subnets []Subnet, clock Clock, updateCb func(*OperationState)) Operation,
	deprovisionOperation func(logger lager.Logger, efsService EFSService, clock Clock, spec DeprovisionOperationSpec, updateCb func(*OperationState)) Operation,
) *Broker {
	theBroker := Broker{
		brokerType:              brokerType,
		logger:                  logger,
		os:                      os,
		efsService:              efsService,
		subnets:                 subnets,
		mutex:                   &sync.Mutex{},
		clock:                   clock,
		store:                   store,
		services:                services,
		configMask:              configMask,
		ProvisionOperation:      provisionOperation,
		DeprovisionOperation:    deprovisionOperation,
		DisallowedBindOverrides: []string{SHARE_KEY, SOURCE_KEY},
	}

	return &theBroker
}

func (b *Broker) isNFSBroker() bool {
	return b.brokerType == BrokerTypeNFS
}

func (b *Broker) isSMBBroker() bool {
	return b.brokerType == BrokerTypeSMB
}

func (b *Broker) isEFSBroker() bool {
	return b.brokerType == BrokerTypeEFS
}

func (b *Broker) Services(_ context.Context) ([]domain.Service, error) {
	logger := b.logger.Session("services")
	logger.Info("start")
	defer logger.Info("end")

	return b.services.List(), nil
}

func (b *Broker) Provision(context context.Context, instanceID string, details domain.ProvisionDetails, _ bool) (_ domain.ProvisionedServiceSpec, e error) {
	logger := b.logger.Session("provision").WithData(lager.Data{"instanceID": instanceID, "details": details})
	logger.Info("start")
	defer logger.Info("end")

	// var configuration map[string]interface{}
	// var decoder = json.NewDecoder(bytes.NewBuffer(details.RawParameters))
	// logger.Info("decoder", lager.Data{"decorder": decoder})
	// err := decoder.Decode(&configuration)
	// if err != nil {
	// 	logger.Info("decode error", lager.Data{"error": err})
	// 	return domain.ProvisionedServiceSpec{}, apiresponses.ErrRawParamsInvalid
	// }

	// share := stringifyShare(configuration[SHARE_KEY])
	// if share == "" {
	// 	return domain.ProvisionedServiceSpec{}, errors.New("config requires a \"share\" key")
	// }

	// if _, ok := configuration[SOURCE_KEY]; ok {
	// 	return domain.ProvisionedServiceSpec{}, errors.New("create configuration contains the following invalid option: ['" + SOURCE_KEY + "']")
	// }
	// if b.isNFSBroker() {
	// 	re := regexp.MustCompile("^[^/]+:/")
	// 	match := re.MatchString(share)

	// 	if match {
	// 		return domain.ProvisionedServiceSpec{}, errors.New("syntax error for share: no colon allowed after server")
	// 	}
	// }

	b.mutex.Lock()
	defer b.mutex.Unlock()
	defer func() {
		out := b.store.Save(logger)
		if e == nil {
			e = out
		}
	}()

	//efsInstance := EFSInstance{details, "", "", "", "", false, "", []string{}, []string{}, []string{}, []string{}, nil}
	operation := b.ProvisionOperation(logger, instanceID, details, b.efsService, b.subnets, b.clock, b.ProvisionEvent)
	go operation.Execute()
	instanceDetails := brokerstore.ServiceInstance{
		ServiceID:          details.ServiceID,
		PlanID:             details.PlanID,
		OrganizationGUID:   details.OrganizationGUID,
		SpaceGUID:          details.SpaceGUID,
		ServiceFingerPrint: operation,
	}

	if b.instanceConflicts(instanceDetails, instanceID) {
		return domain.ProvisionedServiceSpec{}, apiresponses.ErrInstanceAlreadyExists
	}

	err := b.store.CreateInstanceDetails(instanceID, instanceDetails)
	if err != nil {
		return domain.ProvisionedServiceSpec{}, fmt.Errorf("failed to store instance details: %s", err.Error())
	}

	logger.Info("service-instance-created", lager.Data{"instanceDetails": instanceDetails})

	return domain.ProvisionedServiceSpec{IsAsync: false}, nil
}

func (b *Broker) Deprovision(context context.Context, instanceID string, details domain.DeprovisionDetails, _ bool) (_ domain.DeprovisionServiceSpec, e error) {
	logger := b.logger.Session("deprovision")
	logger.Info("start")
	defer logger.Info("end")

	b.mutex.Lock()
	defer b.mutex.Unlock()
	defer func() {
		out := b.store.Save(logger)
		if e == nil {
			e = out
		}
	}()

	instance, err := b.store.RetrieveInstanceDetails(instanceID)
	if err != nil {
		return domain.DeprovisionServiceSpec{}, apiresponses.ErrInstanceDoesNotExist
	}

	efsInstance, err := getFingerprint(instance.ServiceFingerPrint)
	if err != nil {
		return domain.DeprovisionServiceSpec{}, err
	}

	if efsInstance.MountIds == nil || len(efsInstance.MountIds) == 0 {
		efsInstance.MountIds = []string{efsInstance.MountId}
	}

	spec := DeprovisionOperationSpec{
		InstanceID:     instanceID,
		FsID:           efsInstance.EfsId,
		MountTargetIDs: efsInstance.MountIds,
	}
	operation := b.DeprovisionOperation(logger, b.efsService, b.clock, spec, b.DeprovisionEvent)

	go operation.Execute()

	return domain.DeprovisionServiceSpec{IsAsync: false, OperationData: "deprovision"}, nil
}

func (b *Broker) Bind(context context.Context, instanceID string, bindingID string, bindDetails domain.BindDetails, _ bool) (_ domain.Binding, e error) {
	logger := b.logger.Session("bind")
	logger.Info("start", lager.Data{"bindingID": bindingID, "details": bindDetails})
	defer logger.Info("end")

	b.mutex.Lock()
	defer b.mutex.Unlock()
	defer func() {
		out := b.store.Save(logger)
		if e == nil {
			e = out
		}
	}()

	logger.Info("starting-broker-bind")
	instanceDetails, err := b.store.RetrieveInstanceDetails(instanceID)
	if err != nil {
		return domain.Binding{}, apiresponses.ErrInstanceDoesNotExist
	}

	if bindDetails.AppGUID == "" {
		return domain.Binding{}, apiresponses.ErrAppGuidNotProvided
	}
	var params map[string]interface{}
	if len(bindDetails.RawParameters) > 0 {
		if err := json.Unmarshal(bindDetails.RawParameters, &params); err != nil {
			return domain.Binding{}, err
		}
	}
	mode := evaluateMode(params)

	opts, err := getFingerprintexisting(instanceDetails.ServiceFingerPrint)
	if err != nil {
		return domain.Binding{}, err
	}

	var bindOpts map[string]interface{}
	if len(bindDetails.RawParameters) > 0 {
		if err = json.Unmarshal(bindDetails.RawParameters, &bindOpts); err != nil {
			return domain.Binding{}, err
		}
	}

	for k, v := range bindOpts {
		for _, disallowed := range b.DisallowedBindOverrides {
			if k == disallowed {
				err := errors.New(fmt.Sprintf("bind configuration contains the following invalid option: ['%s']", k))
				logger.Error("err-override-not-allowed-in-bind", err, lager.Data{"key": k})
				return domain.Binding{}, apiresponses.NewFailureResponse(
					err, http.StatusBadRequest, "invalid-raw-params",
				)

			}
		}
		opts[k] = v
	}
	if err != nil {
		logger.Error("error-evaluating-mode", err)
		return domain.Binding{}, err
	}

	mountOpts, err := vmo.NewMountOpts(opts, b.configMask)
	if err != nil {
		logger.Error("error-generating-mount-options", err)
		return domain.Binding{}, apiresponses.NewFailureResponse(err, http.StatusBadRequest, "invalid-params")
	}

	if b.bindingConflicts(bindingID, bindDetails) {
		return domain.Binding{}, apiresponses.ErrBindingAlreadyExists
	}

	logger.Info("retrieved-instance-details", lager.Data{"instanceDetails": instanceDetails})

	err = b.store.CreateBindingDetails(bindingID, bindDetails)
	if err != nil {
		return domain.Binding{}, err
	}

	driverName := "smbdriver"
	if b.isNFSBroker() {
		driverName = "nfsv3driver"

		// for backwards compatibility the nfs flavor has to issue source strings
		// with nfs:// prefix (otherwise the mapfs-mounter wont construct the correct
		// mount string for the kernel mount
		//
		// see (https://github.com/cloudfoundry/nfsv3driver/blob/ac1e1d26fec9a8551cacfabafa6e035f233c83e0/mapfs_mounter.go#L121)
		mountOpts[SOURCE_KEY] = fmt.Sprintf("nfs://%s", mountOpts[SOURCE_KEY])
	}
	if b.isEFSBroker() {
		driverName = "efsdriver"
		//might need url here
	}

	logger.Debug("volume-service-binding", lager.Data{"driver": driverName, "mountOpts": mountOpts})

	s, err := b.hash(mountOpts)
	if err != nil {
		logger.Error("error-calculating-volume-id", err, lager.Data{"config": mountOpts, "bindingID": bindingID, "instanceID": instanceID})
		return domain.Binding{}, err
	}
	volumeId := fmt.Sprintf("%s-%s", instanceID, s)

	mountConfig := map[string]interface{}{}

	for k, v := range mountOpts {
		mountConfig[k] = v
	}

	ret := domain.Binding{
		Credentials: struct{}{}, // if nil, cloud controller chokes on response
		VolumeMounts: []domain.VolumeMount{{
			ContainerDir: evaluateContainerPath(opts, instanceID),
			Mode:         mode,
			Driver:       driverName,
			DeviceType:   "shared",
			Device: domain.SharedDevice{
				VolumeId:    volumeId,
				MountConfig: mountConfig,
			},
		}},
	}
	return ret, nil
}

func (b *Broker) getMountIp(fsId string) (string, error) {
	// get mount point details from ews to return in bind response
	mtOutput, err := b.efsService.DescribeMountTargets(&efs.DescribeMountTargetsInput{
		FileSystemId: aws.String(fsId),
	})
	if err != nil {
		b.logger.Error("err-getting-mount-target-status", err)
		return "", err
	}
	if len(mtOutput.MountTargets) < 1 {
		b.logger.Error("found-no-mount-targets", ErrNoMountTargets)
		return "", ErrNoMountTargets
	}

	if mtOutput.MountTargets[0].LifeCycleState == nil ||
		*mtOutput.MountTargets[0].LifeCycleState != efs.LifeCycleStateAvailable {
		b.logger.Error("mount-point-unavailable", ErrMountTargetUnavailable)
		return "", ErrMountTargetUnavailable
	}

	mountConfig := *mtOutput.MountTargets[0].IpAddress

	return mountConfig, nil
}

func (b *Broker) hash(mountOpts map[string]interface{}) (string, error) {
	var (
		bytes []byte
		err   error
	)
	if bytes, err = json.Marshal(mountOpts); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", md5.Sum(bytes)), nil
}

func (b *Broker) Unbind(context context.Context, instanceID string, bindingID string, details domain.UnbindDetails, _ bool) (_ domain.UnbindSpec, e error) {
	logger := b.logger.Session("unbind")
	logger.Info("start")
	defer logger.Info("end")

	b.mutex.Lock()
	defer b.mutex.Unlock()
	defer func() {
		out := b.store.Save(logger)
		if e == nil {
			e = out
		}
	}()

	if _, err := b.store.RetrieveInstanceDetails(instanceID); err != nil {
		return domain.UnbindSpec{}, apiresponses.ErrInstanceDoesNotExist
	}

	if _, err := b.store.RetrieveBindingDetails(bindingID); err != nil {
		return domain.UnbindSpec{}, apiresponses.ErrBindingDoesNotExist
	}

	if err := b.store.DeleteBindingDetails(bindingID); err != nil {
		return domain.UnbindSpec{}, err
	}
	return domain.UnbindSpec{}, nil
}

func (b *Broker) Update(context context.Context, instanceID string, details domain.UpdateDetails, _ bool) (domain.UpdateServiceSpec, error) {
	return domain.UpdateServiceSpec{},
		apiresponses.NewFailureResponse(
			errors.New("This service does not support instance updates. Please delete your service instance and create a new one with updated configuration."),
			422,
			"",
		)
}

func (b *Broker) LastOperation(_ context.Context, instanceID string, operationData domain.PollDetails) (domain.LastOperation, error) {
	logger := b.logger.Session("last-operation").WithData(lager.Data{"instanceID": instanceID})
	logger.Info("start")
	defer logger.Info("end")

	b.mutex.Lock()
	defer b.mutex.Unlock()
	switch operationData.OperationData {
	case "provision":
		logger.Info("Provisioning")
		instance, err := b.store.RetrieveInstanceDetails(instanceID)
		if err != nil {
			logger.Info("instance-not-found")
			return domain.LastOperation{}, errors.New(fmt.Sprintf("failed to make instance%s", instanceID))
		}
		logger.Debug("service-instance", lager.Data{"instance": instance})

		efsInstance, err := getFingerprint(instance.ServiceFingerPrint)
		if err != nil {
			return domain.LastOperation{}, errors.New(fmt.Sprintf("failed to deserialize details for instance %s", instanceID))
		}
		logger.Debug("efs-instance", lager.Data{"efs-instance": efsInstance})

		if efsInstance.Err != nil {
			logger.Info(fmt.Sprintf("last-operation-error %#v", efsInstance.Err))
			return domain.LastOperation{State: domain.Failed, Description: efsInstance.Err.Error()}, nil
		}

		return stateToLastOperation(efsInstance), nil
	case "deprovision":
		instance, err := b.store.RetrieveInstanceDetails(instanceID)

		if err != nil {
			return domain.LastOperation{State: domain.Succeeded}, nil
		} else {
			efsInstance, err := getFingerprint(instance.ServiceFingerPrint)
			if err != nil {
				return domain.LastOperation{}, errors.New(fmt.Sprintf("failed to deserialize details for instance %s", instanceID))
			}
			if efsInstance.Err != nil {
				return domain.LastOperation{State: domain.Failed}, nil
			} else {
				return domain.LastOperation{State: domain.InProgress}, nil
			}
		}
	default:
		return domain.LastOperation{}, errors.New("unrecognized operationData")
	}

}

// callbacks
func (b *Broker) ProvisionEvent(opState *OperationState) {
	logger := b.logger.Session("provision-event").WithData(lager.Data{"state": opState})
	logger.Info("start")
	defer logger.Info("end")
	b.mutex.Lock()
	defer b.mutex.Unlock()
	defer func() {
		out := b.store.Save(logger)
		if out != nil {
			logger.Error("store save failed", out)
		}
	}()

	if opState.Err != nil {
		logger.Error("Last provision failed", opState.Err)
	}

	instance, err := b.store.RetrieveInstanceDetails(opState.InstanceID)
	if err != nil {
		logger.Error("instance-not-found", err)
	}

	logger.Debug("updated-operation-state", lager.Data{"id": opState.InstanceID, "state": opState})

	var efsInstance EFSInstance

	efsInstance.EfsId = opState.FsID
	efsInstance.FsState = opState.FsState

	efsInstance.MountId = opState.MountTargetIDs[0]
	efsInstance.MountIp = opState.MountTargetIps[0]
	efsInstance.MountState = opState.MountTargetStates[0]

	efsInstance.MountIds = opState.MountTargetIDs
	efsInstance.MountIps = opState.MountTargetIps
	efsInstance.MountAZs = opState.MountTargetAZs
	efsInstance.MountStates = opState.MountTargetStates
	efsInstance.MountPermsSet = opState.MountPermsSet
	efsInstance.Err = opState.Err

	instance.ServiceFingerPrint = efsInstance

	err = b.store.DeleteInstanceDetails(opState.InstanceID)
	if err != nil {
		logger.Error("failed to delete instance", err)
		return
	}

	err = b.store.CreateInstanceDetails(opState.InstanceID, instance)
	if err != nil {
		logger.Error("failed to store instance details", err)
		return
	}

	logger.Debug("updated-store", lager.Data{"id": opState.InstanceID, "details": instance})
}

func (b *Broker) DeprovisionEvent(opState *OperationState) {
	logger := b.logger.Session("deprovision-event").WithData(lager.Data{"state": opState})
	logger.Info("start")
	defer logger.Info("end")
	b.mutex.Lock()
	defer b.mutex.Unlock()
	defer func() {
		out := b.store.Save(logger)
		if out != nil {
			logger.Error("store save failed", out)
		}
	}()

	var err error

	if opState.Err == nil {
		err = b.store.DeleteInstanceDetails(opState.InstanceID)
		if err != nil {
			logger.Error("failed to delete instance", err)
			return
		}
	} else {
		instance, err := b.store.RetrieveInstanceDetails(opState.InstanceID)
		if err != nil {
			logger.Error("instance-not-found", err)
			return
		}

		efsInstance, err := getFingerprint(instance.ServiceFingerPrint)
		if err != nil {
			return
		}

		efsInstance.Err = opState.Err

		instance.ServiceFingerPrint = efsInstance

		err = b.store.DeleteInstanceDetails(opState.InstanceID)
		if err != nil {
			logger.Error("failed to delete instance", err)
			return
		}

		err = b.store.CreateInstanceDetails(opState.InstanceID, instance)
		if err != nil {
			logger.Error("failed to store instance details", err)
			return
		}
	}
}

func stateToLastOperation(instance EFSInstance) domain.LastOperation {
	desc := stateToDescription(instance)

	if instance.Err != nil {
		return domain.LastOperation{State: domain.Failed, Description: desc}
	}

	switch instance.FsState {
	case "":
		return domain.LastOperation{State: domain.InProgress, Description: desc}
	case efs.LifeCycleStateCreating:
		return domain.LastOperation{State: domain.InProgress, Description: desc}
	case efs.LifeCycleStateAvailable:

		switch instance.MountState {
		case "":
			return domain.LastOperation{State: domain.InProgress, Description: desc}
		case efs.LifeCycleStateCreating:
			return domain.LastOperation{State: domain.InProgress, Description: desc}
		case efs.LifeCycleStateAvailable:
			if instance.MountPermsSet {
				return domain.LastOperation{State: domain.Succeeded, Description: desc}
			} else {
				return domain.LastOperation{State: domain.InProgress, Description: desc}
			}
		default:
			return domain.LastOperation{State: domain.Failed, Description: desc}
		}

	default:
		return domain.LastOperation{State: domain.Failed, Description: desc}
	}
}

func stateToDescription(instance EFSInstance) string {
	desc := fmt.Sprintf("FsID: %s, FsState: %s, MountID: %s, MountState: %s, MountAddress: %s", instance.EfsId, instance.FsState, instance.MountId, instance.MountState, instance.MountIp)
	if instance.Err != nil {
		desc = fmt.Sprintf("%s, Error: %s", desc, instance.Err.Error())
	}
	return desc
}

func (b *Broker) instanceConflicts(details brokerstore.ServiceInstance, instanceID string) bool {
	return b.store.IsInstanceConflict(instanceID, brokerstore.ServiceInstance(details))
}

func (b *Broker) bindingConflicts(bindingID string, details domain.BindDetails) bool {
	return b.store.IsBindingConflict(bindingID, details)
}

func planIDToPerformanceMode(planID string) *string {
	if planID == "maxIO" {
		return aws.String(efs.PerformanceModeMaxIo)
	}
	return aws.String(efs.PerformanceModeGeneralPurpose)
}

func evaluateContainerPath(parameters map[string]interface{}, volId string) string {
	if containerPath, ok := parameters["mount"]; ok && containerPath != "" {
		return containerPath.(string)
	}

	return path.Join(DefaultContainerPath, volId)
}

func evaluateMode(parameters map[string]interface{}) string {
	if ro, ok := parameters["readonly"]; ok {
		switch ro := ro.(type) {
		case bool:
			return readOnlyToMode(ro)
		default:
			return ""
		}
	}
	return "rw"
}

func readOnlyToMode(ro bool) string {
	if ro {
		return "r"
	}
	return "rw"
}

func getFingerprint(rawObject interface{}) (EFSInstance, error) {

	fingerprint, ok := rawObject.(EFSInstance)
	if ok {
		return fingerprint, nil
	}

	// casting didn't work--try marshalling and unmarshalling as the correct type
	rawJson, err := json.Marshal(rawObject)
	if err != nil {
		return EFSInstance{}, err
	}

	efsInstance := EFSInstance{}
	err = json.Unmarshal(rawJson, &efsInstance)
	if err != nil {
		return EFSInstance{}, err
	}

	return efsInstance, nil
}

func (b *Broker) GetInstance(ctx context.Context, instanceID string, details domain.FetchInstanceDetails) (domain.GetInstanceDetailsSpec, error) {
	panic("implement me")
}

func (b *Broker) LastBindingOperation(ctx context.Context, instanceID, bindingID string, details domain.PollDetails) (domain.LastOperation, error) {
	panic("implement me")
}

func (b *Broker) GetBinding(ctx context.Context, instanceID, bindingID string, details domain.FetchBindingDetails) (domain.GetBindingSpec, error) {
	panic("implement me")
}

func stringifyShare(data interface{}) string {
	if val, ok := data.(string); ok {
		return val
	}

	return ""
}

func getFingerprintexisting(rawObject interface{}) (map[string]interface{}, error) {
	fingerprint, ok := rawObject.(map[string]interface{})
	if ok {
		return fingerprint, nil
	} else {
		// legacy service instances only store the "share" key in the service fingerprint.
		share, ok := rawObject.(string)
		if ok {
			return map[string]interface{}{SHARE_KEY: share}, nil
		}
		return nil, errors.New("unable to deserialize service fingerprint")
	}
}
