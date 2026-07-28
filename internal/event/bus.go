package event

import (
	"errors"
	"log"
	"sync"
)

// Bus 事件总线
type Bus struct {
	mu        sync.RWMutex
	listeners map[EventType][]Listener
}

var globalBus *Bus
var once sync.Once

// 获取全局事件总线单例
func GetBus() *Bus {
	once.Do(func() {
		globalBus = &Bus{
			listeners: make(map[EventType][]Listener),
		}
	})
	return globalBus
}

// 订阅事件
func (b *Bus) Subscribe(eventType EventType, listener Listener) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.listeners[eventType] = append(b.listeners[eventType], listener)
}

// 发布事件
func (b *Bus) Publish(event InboundEvent) error {
	b.mu.RLock()
	listeners := append([]Listener(nil), b.listeners[event.Type]...)
	b.mu.RUnlock()

	var publishErrors []error
	for _, listener := range listeners {
		if err := listener.Handle(event); err != nil {
			publishErrors = append(publishErrors, err)
		}
	}
	return errors.Join(publishErrors...)
}

// 异步发布事件
func (b *Bus) PublishAsync(event InboundEvent) {
	go func() {
		if err := b.Publish(event); err != nil {
			log.Printf("[Event] asynchronous %s listener failed: %v", event.Type, err)
		}
	}()
}
