// Copyright 2019 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package parser

import (
	"io/ioutil"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/parser/errors"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var log *logrus.Logger

func init() {
	log = logrus.New()
	log.SetOutput(ioutil.Discard)
}

func Test_InvalidPayloads(t *testing.T) {
	p, err := New(log, nil, nil, nil, nil, nil)
	assert.NoError(t, err)

	_, err = p.Decode(nil)
	assert.Equal(t, err, errors.ErrEmptyData)

	_, err = p.Decode(&flowpb.Payload{
		Type: flowpb.EventType_EventSample,
		Data: nil,
	})
	assert.Equal(t, err, errors.ErrEmptyData)

	_, err = p.Decode(&flowpb.Payload{
		Type: flowpb.EventType_EventSample,
		Data: []byte{100},
	})
	assert.Equal(t, err, errors.NewErrInvalidType(100))

	_, err = p.Decode(&flowpb.Payload{
		Type: flowpb.EventType_UNKNOWN,
	})
	assert.Equal(t, err, errors.ErrUnknownPerfEvent)
}

func Test_EventType_RecordLost(t *testing.T) {
	p, err := New(log, nil, nil, nil, nil, nil)
	assert.NoError(t, err)

	ts := ptypes.TimestampNow()
	ev, err := p.Decode(&flowpb.Payload{
		Type: flowpb.EventType_RecordLost,
		CPU:  3,
		Lost: 1001,
		Time: ts,
	})
	assert.NoError(t, err)
	assert.Equal(t, &v1.Event{
		Timestamp: ts,
		Event: &flowpb.LostEvent{
			NumEventsLost: 1001,
			Cpu:           &wrappers.Int32Value{Value: 3},
			Source:        flowpb.LostEventSource_PERF_EVENT_RING_BUFFER,
		},
	}, ev)
}
