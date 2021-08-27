package main

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"

	manager "github.com/DataDog/ebpf-manager"
)

func demoMapEditor() error {
	logrus.Println("MAP EDITOR DEMO")
	// Select the shared map to give it to m2
	sharedCache1, found, err := m1.GetMap("shared_cache1")
	if err != nil || !found {
		return fmt.Errorf("couldn't find shared_cache1 in m1: %w", err)
	}
	if err = dumpSharedMap(sharedCache1); err != nil {
		return err
	}

	// Give shared_cache1 to m2 through a map editor
	options := manager.Options{
		MapEditors: map[string]*ebpf.Map{
			"shared_cache1": sharedCache1,
		},
		// The following parameter is NOT used by the MapEditor demo, but is required to load m2 since m2 has a
		// BPF_MAP_TYPE_HASH_OF_MAPS map.
		InnerOuterMapSpecs: []manager.InnerOuterMapSpec{
			{
				OuterMapName: "maps_router",
				InnerMapName: "routed_cache",
			},
		},
	}
	// Initialize m2, edit shared_cache1 and start it
	if err = m2.InitWithOptions(recoverAsset("/prog2.o"), options); err != nil {
		return fmt.Errorf("couldn't init m2: %w", err)
	}
	if err = m2.Start(); err != nil {
		return err
	}
	if err = trigger(); err != nil {
		return err
	}
	return dumpSharedMap(sharedCache1)
}

func demoMapRouter() error {
	logrus.Println("MAP ROUTER DEMO")
	// Select the shared map to give it to m2
	sharedCache2, found, err := m1.GetMap("shared_cache2")
	if err != nil || !found {
		return fmt.Errorf("couldn't find shared_cache2 in m1: %w", err)
	}
	if err = dumpSharedMap(sharedCache2); err != nil {
		return err
	}

	// Give shared_cache2 to m2 through a map router
	router := manager.MapRoute{
		RoutingMapName: "maps_router",
		Key:            uint32(1),
		Map:            sharedCache2,
	}
	if err := m2.UpdateMapRoutes(router); err != nil {
		return err
	}

	if err = trigger(); err != nil {
		return err
	}
	return dumpSharedMap(sharedCache2)
}
