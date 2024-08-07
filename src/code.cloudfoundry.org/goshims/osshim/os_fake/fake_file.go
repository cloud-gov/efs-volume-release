// This file was generated by counterfeiter
package os_fake

import (
	"os"
	"sync"

	"code.cloudfoundry.org/goshims/osshim"
)

type FakeFile struct {
	NameStub        func() string
	nameMutex       sync.RWMutex
	nameArgsForCall []struct{}
	nameReturns     struct {
		result1 string
	}
	FdStub        func() uintptr
	fdMutex       sync.RWMutex
	fdArgsForCall []struct{}
	fdReturns     struct {
		result1 uintptr
	}
	CloseStub        func() error
	closeMutex       sync.RWMutex
	closeArgsForCall []struct{}
	closeReturns     struct {
		result1 error
	}
	StatStub        func() (os.FileInfo, error)
	statMutex       sync.RWMutex
	statArgsForCall []struct{}
	statReturns     struct {
		result1 os.FileInfo
		result2 error
	}
	ReadStub        func(b []byte) (n int, err error)
	readMutex       sync.RWMutex
	readArgsForCall []struct {
		b []byte
	}
	readReturns struct {
		result1 int
		result2 error
	}
	ReadAtStub        func(b []byte, off int64) (n int, err error)
	readAtMutex       sync.RWMutex
	readAtArgsForCall []struct {
		b   []byte
		off int64
	}
	readAtReturns struct {
		result1 int
		result2 error
	}
	WriteStub        func(b []byte) (n int, err error)
	writeMutex       sync.RWMutex
	writeArgsForCall []struct {
		b []byte
	}
	writeReturns struct {
		result1 int
		result2 error
	}
	WriteAtStub        func(b []byte, off int64) (n int, err error)
	writeAtMutex       sync.RWMutex
	writeAtArgsForCall []struct {
		b   []byte
		off int64
	}
	writeAtReturns struct {
		result1 int
		result2 error
	}
	SeekStub        func(offset int64, whence int) (ret int64, err error)
	seekMutex       sync.RWMutex
	seekArgsForCall []struct {
		offset int64
		whence int
	}
	seekReturns struct {
		result1 int64
		result2 error
	}
	WriteStringStub        func(s string) (n int, err error)
	writeStringMutex       sync.RWMutex
	writeStringArgsForCall []struct {
		s string
	}
	writeStringReturns struct {
		result1 int
		result2 error
	}
	ChdirStub        func() error
	chdirMutex       sync.RWMutex
	chdirArgsForCall []struct{}
	chdirReturns     struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeFile) Name() string {
	fake.nameMutex.Lock()
	fake.nameArgsForCall = append(fake.nameArgsForCall, struct{}{})
	fake.recordInvocation("Name", []interface{}{})
	fake.nameMutex.Unlock()
	if fake.NameStub != nil {
		return fake.NameStub()
	}
	return fake.nameReturns.result1
}

func (fake *FakeFile) NameCallCount() int {
	fake.nameMutex.RLock()
	defer fake.nameMutex.RUnlock()
	return len(fake.nameArgsForCall)
}

func (fake *FakeFile) NameReturns(result1 string) {
	fake.NameStub = nil
	fake.nameReturns = struct {
		result1 string
	}{result1}
}

func (fake *FakeFile) Fd() uintptr {
	fake.fdMutex.Lock()
	fake.fdArgsForCall = append(fake.fdArgsForCall, struct{}{})
	fake.recordInvocation("Fd", []interface{}{})
	fake.fdMutex.Unlock()
	if fake.FdStub != nil {
		return fake.FdStub()
	}
	return fake.fdReturns.result1
}

func (fake *FakeFile) FdCallCount() int {
	fake.fdMutex.RLock()
	defer fake.fdMutex.RUnlock()
	return len(fake.fdArgsForCall)
}

func (fake *FakeFile) FdReturns(result1 uintptr) {
	fake.FdStub = nil
	fake.fdReturns = struct {
		result1 uintptr
	}{result1}
}

func (fake *FakeFile) Close() error {
	fake.closeMutex.Lock()
	fake.closeArgsForCall = append(fake.closeArgsForCall, struct{}{})
	fake.recordInvocation("Close", []interface{}{})
	fake.closeMutex.Unlock()
	if fake.CloseStub != nil {
		return fake.CloseStub()
	}
	return fake.closeReturns.result1
}

func (fake *FakeFile) CloseCallCount() int {
	fake.closeMutex.RLock()
	defer fake.closeMutex.RUnlock()
	return len(fake.closeArgsForCall)
}

func (fake *FakeFile) CloseReturns(result1 error) {
	fake.CloseStub = nil
	fake.closeReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeFile) Stat() (os.FileInfo, error) {
	fake.statMutex.Lock()
	fake.statArgsForCall = append(fake.statArgsForCall, struct{}{})
	fake.recordInvocation("Stat", []interface{}{})
	fake.statMutex.Unlock()
	if fake.StatStub != nil {
		return fake.StatStub()
	}
	return fake.statReturns.result1, fake.statReturns.result2
}

func (fake *FakeFile) StatCallCount() int {
	fake.statMutex.RLock()
	defer fake.statMutex.RUnlock()
	return len(fake.statArgsForCall)
}

func (fake *FakeFile) StatReturns(result1 os.FileInfo, result2 error) {
	fake.StatStub = nil
	fake.statReturns = struct {
		result1 os.FileInfo
		result2 error
	}{result1, result2}
}

func (fake *FakeFile) Read(b []byte) (n int, err error) {
	var bCopy []byte
	if b != nil {
		bCopy = make([]byte, len(b))
		copy(bCopy, b)
	}
	fake.readMutex.Lock()
	fake.readArgsForCall = append(fake.readArgsForCall, struct {
		b []byte
	}{bCopy})
	fake.recordInvocation("Read", []interface{}{bCopy})
	fake.readMutex.Unlock()
	if fake.ReadStub != nil {
		return fake.ReadStub(b)
	}
	return fake.readReturns.result1, fake.readReturns.result2
}

func (fake *FakeFile) ReadCallCount() int {
	fake.readMutex.RLock()
	defer fake.readMutex.RUnlock()
	return len(fake.readArgsForCall)
}

func (fake *FakeFile) ReadArgsForCall(i int) []byte {
	fake.readMutex.RLock()
	defer fake.readMutex.RUnlock()
	return fake.readArgsForCall[i].b
}

func (fake *FakeFile) ReadReturns(result1 int, result2 error) {
	fake.ReadStub = nil
	fake.readReturns = struct {
		result1 int
		result2 error
	}{result1, result2}
}

func (fake *FakeFile) ReadAt(b []byte, off int64) (n int, err error) {
	var bCopy []byte
	if b != nil {
		bCopy = make([]byte, len(b))
		copy(bCopy, b)
	}
	fake.readAtMutex.Lock()
	fake.readAtArgsForCall = append(fake.readAtArgsForCall, struct {
		b   []byte
		off int64
	}{bCopy, off})
	fake.recordInvocation("ReadAt", []interface{}{bCopy, off})
	fake.readAtMutex.Unlock()
	if fake.ReadAtStub != nil {
		return fake.ReadAtStub(b, off)
	}
	return fake.readAtReturns.result1, fake.readAtReturns.result2
}

func (fake *FakeFile) ReadAtCallCount() int {
	fake.readAtMutex.RLock()
	defer fake.readAtMutex.RUnlock()
	return len(fake.readAtArgsForCall)
}

func (fake *FakeFile) ReadAtArgsForCall(i int) ([]byte, int64) {
	fake.readAtMutex.RLock()
	defer fake.readAtMutex.RUnlock()
	return fake.readAtArgsForCall[i].b, fake.readAtArgsForCall[i].off
}

func (fake *FakeFile) ReadAtReturns(result1 int, result2 error) {
	fake.ReadAtStub = nil
	fake.readAtReturns = struct {
		result1 int
		result2 error
	}{result1, result2}
}

func (fake *FakeFile) Write(b []byte) (n int, err error) {
	var bCopy []byte
	if b != nil {
		bCopy = make([]byte, len(b))
		copy(bCopy, b)
	}
	fake.writeMutex.Lock()
	fake.writeArgsForCall = append(fake.writeArgsForCall, struct {
		b []byte
	}{bCopy})
	fake.recordInvocation("Write", []interface{}{bCopy})
	fake.writeMutex.Unlock()
	if fake.WriteStub != nil {
		return fake.WriteStub(b)
	}
	return fake.writeReturns.result1, fake.writeReturns.result2
}

func (fake *FakeFile) WriteCallCount() int {
	fake.writeMutex.RLock()
	defer fake.writeMutex.RUnlock()
	return len(fake.writeArgsForCall)
}

func (fake *FakeFile) WriteArgsForCall(i int) []byte {
	fake.writeMutex.RLock()
	defer fake.writeMutex.RUnlock()
	return fake.writeArgsForCall[i].b
}

func (fake *FakeFile) WriteReturns(result1 int, result2 error) {
	fake.WriteStub = nil
	fake.writeReturns = struct {
		result1 int
		result2 error
	}{result1, result2}
}

func (fake *FakeFile) WriteAt(b []byte, off int64) (n int, err error) {
	var bCopy []byte
	if b != nil {
		bCopy = make([]byte, len(b))
		copy(bCopy, b)
	}
	fake.writeAtMutex.Lock()
	fake.writeAtArgsForCall = append(fake.writeAtArgsForCall, struct {
		b   []byte
		off int64
	}{bCopy, off})
	fake.recordInvocation("WriteAt", []interface{}{bCopy, off})
	fake.writeAtMutex.Unlock()
	if fake.WriteAtStub != nil {
		return fake.WriteAtStub(b, off)
	}
	return fake.writeAtReturns.result1, fake.writeAtReturns.result2
}

func (fake *FakeFile) WriteAtCallCount() int {
	fake.writeAtMutex.RLock()
	defer fake.writeAtMutex.RUnlock()
	return len(fake.writeAtArgsForCall)
}

func (fake *FakeFile) WriteAtArgsForCall(i int) ([]byte, int64) {
	fake.writeAtMutex.RLock()
	defer fake.writeAtMutex.RUnlock()
	return fake.writeAtArgsForCall[i].b, fake.writeAtArgsForCall[i].off
}

func (fake *FakeFile) WriteAtReturns(result1 int, result2 error) {
	fake.WriteAtStub = nil
	fake.writeAtReturns = struct {
		result1 int
		result2 error
	}{result1, result2}
}

func (fake *FakeFile) Seek(offset int64, whence int) (ret int64, err error) {
	fake.seekMutex.Lock()
	fake.seekArgsForCall = append(fake.seekArgsForCall, struct {
		offset int64
		whence int
	}{offset, whence})
	fake.recordInvocation("Seek", []interface{}{offset, whence})
	fake.seekMutex.Unlock()
	if fake.SeekStub != nil {
		return fake.SeekStub(offset, whence)
	}
	return fake.seekReturns.result1, fake.seekReturns.result2
}

func (fake *FakeFile) SeekCallCount() int {
	fake.seekMutex.RLock()
	defer fake.seekMutex.RUnlock()
	return len(fake.seekArgsForCall)
}

func (fake *FakeFile) SeekArgsForCall(i int) (int64, int) {
	fake.seekMutex.RLock()
	defer fake.seekMutex.RUnlock()
	return fake.seekArgsForCall[i].offset, fake.seekArgsForCall[i].whence
}

func (fake *FakeFile) SeekReturns(result1 int64, result2 error) {
	fake.SeekStub = nil
	fake.seekReturns = struct {
		result1 int64
		result2 error
	}{result1, result2}
}

func (fake *FakeFile) WriteString(s string) (n int, err error) {
	fake.writeStringMutex.Lock()
	fake.writeStringArgsForCall = append(fake.writeStringArgsForCall, struct {
		s string
	}{s})
	fake.recordInvocation("WriteString", []interface{}{s})
	fake.writeStringMutex.Unlock()
	if fake.WriteStringStub != nil {
		return fake.WriteStringStub(s)
	}
	return fake.writeStringReturns.result1, fake.writeStringReturns.result2
}

func (fake *FakeFile) WriteStringCallCount() int {
	fake.writeStringMutex.RLock()
	defer fake.writeStringMutex.RUnlock()
	return len(fake.writeStringArgsForCall)
}

func (fake *FakeFile) WriteStringArgsForCall(i int) string {
	fake.writeStringMutex.RLock()
	defer fake.writeStringMutex.RUnlock()
	return fake.writeStringArgsForCall[i].s
}

func (fake *FakeFile) WriteStringReturns(result1 int, result2 error) {
	fake.WriteStringStub = nil
	fake.writeStringReturns = struct {
		result1 int
		result2 error
	}{result1, result2}
}

func (fake *FakeFile) Chdir() error {
	fake.chdirMutex.Lock()
	fake.chdirArgsForCall = append(fake.chdirArgsForCall, struct{}{})
	fake.recordInvocation("Chdir", []interface{}{})
	fake.chdirMutex.Unlock()
	if fake.ChdirStub != nil {
		return fake.ChdirStub()
	}
	return fake.chdirReturns.result1
}

func (fake *FakeFile) ChdirCallCount() int {
	fake.chdirMutex.RLock()
	defer fake.chdirMutex.RUnlock()
	return len(fake.chdirArgsForCall)
}

func (fake *FakeFile) ChdirReturns(result1 error) {
	fake.ChdirStub = nil
	fake.chdirReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeFile) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.nameMutex.RLock()
	defer fake.nameMutex.RUnlock()
	fake.fdMutex.RLock()
	defer fake.fdMutex.RUnlock()
	fake.closeMutex.RLock()
	defer fake.closeMutex.RUnlock()
	fake.statMutex.RLock()
	defer fake.statMutex.RUnlock()
	fake.readMutex.RLock()
	defer fake.readMutex.RUnlock()
	fake.readAtMutex.RLock()
	defer fake.readAtMutex.RUnlock()
	fake.writeMutex.RLock()
	defer fake.writeMutex.RUnlock()
	fake.writeAtMutex.RLock()
	defer fake.writeAtMutex.RUnlock()
	fake.seekMutex.RLock()
	defer fake.seekMutex.RUnlock()
	fake.writeStringMutex.RLock()
	defer fake.writeStringMutex.RUnlock()
	fake.chdirMutex.RLock()
	defer fake.chdirMutex.RUnlock()
	return fake.invocations
}

func (fake *FakeFile) recordInvocation(key string, args []interface{}) {
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

var _ osshim.File = new(FakeFile)
