package core

import (
	"net"
	"sync"
)

type Cache interface {
	Put(key uint64, value net.Conn)

	Get(key uint64) net.Conn

	Delete(key uint64)
}

type ConnMapCache struct {
	cacheConnMap map[uint64]net.Conn
	lock         sync.RWMutex
}

func NewMapCache() *ConnMapCache {
	return &ConnMapCache{
		cacheConnMap: make(map[uint64]net.Conn),
	}
}

func (mc *ConnMapCache) Put(key uint64, value net.Conn) () {
	mc.lock.Lock()
	defer mc.lock.Unlock()
	mc.cacheConnMap[key] = value
}

func (mc *ConnMapCache) Get(key uint64) net.Conn {
	return mc.cacheConnMap[key]
}

func (mc *ConnMapCache) Delete(key uint64) {
	mc.lock.Lock()
	defer mc.lock.Unlock()
	delete(mc.cacheConnMap, key)
}
