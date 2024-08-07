// Code generated by counterfeiter. DO NOT EDIT.
package brokerstorefakes

import (
	"sync"

	"code.cloudfoundry.org/goshims/sqlshim"
	"code.cloudfoundry.org/lager"
	"code.cloudfoundry.org/service-broker-store/brokerstore"
)

type FakeSqlVariant struct {
	ConnectStub        func(logger lager.Logger) (sqlshim.SqlDB, error)
	connectMutex       sync.RWMutex
	connectArgsForCall []struct {
		logger lager.Logger
	}
	connectReturns struct {
		result1 sqlshim.SqlDB
		result2 error
	}
	connectReturnsOnCall map[int]struct {
		result1 sqlshim.SqlDB
		result2 error
	}
	FlavorifyStub        func(query string) string
	flavorifyMutex       sync.RWMutex
	flavorifyArgsForCall []struct {
		query string
	}
	flavorifyReturns struct {
		result1 string
	}
	flavorifyReturnsOnCall map[int]struct {
		result1 string
	}
	CloseStub        func() error
	closeMutex       sync.RWMutex
	closeArgsForCall []struct{}
	closeReturns     struct {
		result1 error
	}
	closeReturnsOnCall map[int]struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeSqlVariant) Connect(logger lager.Logger) (sqlshim.SqlDB, error) {
	fake.connectMutex.Lock()
	ret, specificReturn := fake.connectReturnsOnCall[len(fake.connectArgsForCall)]
	fake.connectArgsForCall = append(fake.connectArgsForCall, struct {
		logger lager.Logger
	}{logger})
	fake.recordInvocation("Connect", []interface{}{logger})
	fake.connectMutex.Unlock()
	if fake.ConnectStub != nil {
		return fake.ConnectStub(logger)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.connectReturns.result1, fake.connectReturns.result2
}

func (fake *FakeSqlVariant) ConnectCallCount() int {
	fake.connectMutex.RLock()
	defer fake.connectMutex.RUnlock()
	return len(fake.connectArgsForCall)
}

func (fake *FakeSqlVariant) ConnectArgsForCall(i int) lager.Logger {
	fake.connectMutex.RLock()
	defer fake.connectMutex.RUnlock()
	return fake.connectArgsForCall[i].logger
}

func (fake *FakeSqlVariant) ConnectReturns(result1 sqlshim.SqlDB, result2 error) {
	fake.ConnectStub = nil
	fake.connectReturns = struct {
		result1 sqlshim.SqlDB
		result2 error
	}{result1, result2}
}

func (fake *FakeSqlVariant) ConnectReturnsOnCall(i int, result1 sqlshim.SqlDB, result2 error) {
	fake.ConnectStub = nil
	if fake.connectReturnsOnCall == nil {
		fake.connectReturnsOnCall = make(map[int]struct {
			result1 sqlshim.SqlDB
			result2 error
		})
	}
	fake.connectReturnsOnCall[i] = struct {
		result1 sqlshim.SqlDB
		result2 error
	}{result1, result2}
}

func (fake *FakeSqlVariant) Flavorify(query string) string {
	fake.flavorifyMutex.Lock()
	ret, specificReturn := fake.flavorifyReturnsOnCall[len(fake.flavorifyArgsForCall)]
	fake.flavorifyArgsForCall = append(fake.flavorifyArgsForCall, struct {
		query string
	}{query})
	fake.recordInvocation("Flavorify", []interface{}{query})
	fake.flavorifyMutex.Unlock()
	if fake.FlavorifyStub != nil {
		return fake.FlavorifyStub(query)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.flavorifyReturns.result1
}

func (fake *FakeSqlVariant) FlavorifyCallCount() int {
	fake.flavorifyMutex.RLock()
	defer fake.flavorifyMutex.RUnlock()
	return len(fake.flavorifyArgsForCall)
}

func (fake *FakeSqlVariant) FlavorifyArgsForCall(i int) string {
	fake.flavorifyMutex.RLock()
	defer fake.flavorifyMutex.RUnlock()
	return fake.flavorifyArgsForCall[i].query
}

func (fake *FakeSqlVariant) FlavorifyReturns(result1 string) {
	fake.FlavorifyStub = nil
	fake.flavorifyReturns = struct {
		result1 string
	}{result1}
}

func (fake *FakeSqlVariant) FlavorifyReturnsOnCall(i int, result1 string) {
	fake.FlavorifyStub = nil
	if fake.flavorifyReturnsOnCall == nil {
		fake.flavorifyReturnsOnCall = make(map[int]struct {
			result1 string
		})
	}
	fake.flavorifyReturnsOnCall[i] = struct {
		result1 string
	}{result1}
}

func (fake *FakeSqlVariant) Close() error {
	fake.closeMutex.Lock()
	ret, specificReturn := fake.closeReturnsOnCall[len(fake.closeArgsForCall)]
	fake.closeArgsForCall = append(fake.closeArgsForCall, struct{}{})
	fake.recordInvocation("Close", []interface{}{})
	fake.closeMutex.Unlock()
	if fake.CloseStub != nil {
		return fake.CloseStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.closeReturns.result1
}

func (fake *FakeSqlVariant) CloseCallCount() int {
	fake.closeMutex.RLock()
	defer fake.closeMutex.RUnlock()
	return len(fake.closeArgsForCall)
}

func (fake *FakeSqlVariant) CloseReturns(result1 error) {
	fake.CloseStub = nil
	fake.closeReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeSqlVariant) CloseReturnsOnCall(i int, result1 error) {
	fake.CloseStub = nil
	if fake.closeReturnsOnCall == nil {
		fake.closeReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.closeReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeSqlVariant) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.connectMutex.RLock()
	defer fake.connectMutex.RUnlock()
	fake.flavorifyMutex.RLock()
	defer fake.flavorifyMutex.RUnlock()
	fake.closeMutex.RLock()
	defer fake.closeMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakeSqlVariant) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ brokerstore.SqlVariant = new(FakeSqlVariant)
