//go:build linux

package gvisor

import (
	"context"
	"sync"
	"testing"
)

func TestMeasuredNetworkOwnerRefusesMissingInputs(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		if child, err := StartMeasuredNetworkProcess(ctx, MeasuredNetworkLaunchConfig{}); child != nil || err == nil {
			t.Fatal("missing trusted launch inputs accepted")
		}
	}
	var absent *MeasuredNetworkProcess
	if absent.Child() != nil || absent.Close(context.Background()) != nil || absent.Release(context.Background()) == nil || absent.Wait(context.Background()) == nil {
		t.Fatal("nil owner semantics")
	}
	owner := &MeasuredNetworkProcess{}
	var group sync.WaitGroup
	for i := 0; i < 16; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for n := 0; n < 10; n++ {
				if owner.Release(context.Background()) == nil {
					t.Error("zero owner released")
				}
				if owner.Wait(context.Background()) == nil {
					t.Error("zero owner completed")
				}
				if owner.Close(context.Background()) != nil {
					t.Error("zero owner cleanup")
				}
			}
		}()
	}
	group.Wait()
}
