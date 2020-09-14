/*
Copyright 2020 The Knative Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
	messagingv1 "knative.dev/eventing/pkg/apis/messaging/v1"
)

// FakeChannels implements ChannelInterface
type FakeChannels struct {
	Fake *FakeMessagingV1
	ns   string
}

var channelsResource = schema.GroupVersionResource{Group: "messaging.knative.dev", Version: "v1", Resource: "channels"}

var channelsKind = schema.GroupVersionKind{Group: "messaging.knative.dev", Version: "v1", Kind: "Channel"}

// Get takes name of the channel, and returns the corresponding channel object, and an error if there is any.
func (c *FakeChannels) Get(ctx context.Context, name string, options v1.GetOptions) (result *messagingv1.Channel, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(channelsResource, c.ns, name), &messagingv1.Channel{})

	if obj == nil {
		return nil, err
	}
	return obj.(*messagingv1.Channel), err
}

// List takes label and field selectors, and returns the list of Channels that match those selectors.
func (c *FakeChannels) List(ctx context.Context, opts v1.ListOptions) (result *messagingv1.ChannelList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(channelsResource, channelsKind, c.ns, opts), &messagingv1.ChannelList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &messagingv1.ChannelList{ListMeta: obj.(*messagingv1.ChannelList).ListMeta}
	for _, item := range obj.(*messagingv1.ChannelList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested channels.
func (c *FakeChannels) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(channelsResource, c.ns, opts))

}

// Create takes the representation of a channel and creates it.  Returns the server's representation of the channel, and an error, if there is any.
func (c *FakeChannels) Create(ctx context.Context, channel *messagingv1.Channel, opts v1.CreateOptions) (result *messagingv1.Channel, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(channelsResource, c.ns, channel), &messagingv1.Channel{})

	if obj == nil {
		return nil, err
	}
	return obj.(*messagingv1.Channel), err
}

// Update takes the representation of a channel and updates it. Returns the server's representation of the channel, and an error, if there is any.
func (c *FakeChannels) Update(ctx context.Context, channel *messagingv1.Channel, opts v1.UpdateOptions) (result *messagingv1.Channel, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(channelsResource, c.ns, channel), &messagingv1.Channel{})

	if obj == nil {
		return nil, err
	}
	return obj.(*messagingv1.Channel), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeChannels) UpdateStatus(ctx context.Context, channel *messagingv1.Channel, opts v1.UpdateOptions) (*messagingv1.Channel, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(channelsResource, "status", c.ns, channel), &messagingv1.Channel{})

	if obj == nil {
		return nil, err
	}
	return obj.(*messagingv1.Channel), err
}

// Delete takes name of the channel and deletes it. Returns an error if one occurs.
func (c *FakeChannels) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(channelsResource, c.ns, name), &messagingv1.Channel{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeChannels) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(channelsResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &messagingv1.ChannelList{})
	return err
}

// Patch applies the patch and returns the patched channel.
func (c *FakeChannels) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *messagingv1.Channel, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(channelsResource, c.ns, name, pt, data, subresources...), &messagingv1.Channel{})

	if obj == nil {
		return nil, err
	}
	return obj.(*messagingv1.Channel), err
}
