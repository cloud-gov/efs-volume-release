package brokerstorefakes

import (
	"code.cloudfoundry.org/goshims/sqlshim"
	"code.cloudfoundry.org/lager/v3"
)

type FakeSQLMockConnection struct {
	sqlshim.SqlDB
}

func (fake FakeSQLMockConnection) Connect(logger lager.Logger) error {
	return nil
}
