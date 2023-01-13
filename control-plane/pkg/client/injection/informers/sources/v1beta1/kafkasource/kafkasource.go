/*
 * Copyright 2021 The Knative Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Code generated by injection-gen. DO NOT EDIT.

package kafkasource

import (
	context "context"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	cache "k8s.io/client-go/tools/cache"
	apissourcesv1beta1 "knative.dev/eventing-kafka-broker/control-plane/pkg/apis/sources/v1beta1"
	versioned "knative.dev/eventing-kafka-broker/control-plane/pkg/client/clientset/versioned"
	v1beta1 "knative.dev/eventing-kafka-broker/control-plane/pkg/client/informers/externalversions/sources/v1beta1"
	client "knative.dev/eventing-kafka-broker/control-plane/pkg/client/injection/client"
	factory "knative.dev/eventing-kafka-broker/control-plane/pkg/client/injection/informers/factory"
	sourcesv1beta1 "knative.dev/eventing-kafka-broker/control-plane/pkg/client/listers/sources/v1beta1"
	controller "knative.dev/pkg/controller"
	injection "knative.dev/pkg/injection"
	logging "knative.dev/pkg/logging"
)

func init() {
	injection.Default.RegisterInformer(withInformer)
	injection.Dynamic.RegisterDynamicInformer(withDynamicInformer)
}

// Key is used for associating the Informer inside the context.Context.
type Key struct{}

func withInformer(ctx context.Context) (context.Context, controller.Informer) {
	f := factory.Get(ctx)
	inf := f.Sources().V1beta1().KafkaSources()
	return context.WithValue(ctx, Key{}, inf), inf.Informer()
}

func withDynamicInformer(ctx context.Context) context.Context {
	inf := &wrapper{client: client.Get(ctx), resourceVersion: injection.GetResourceVersion(ctx)}
	return context.WithValue(ctx, Key{}, inf)
}

// Get extracts the typed informer from the context.
func Get(ctx context.Context) v1beta1.KafkaSourceInformer {
	untyped := ctx.Value(Key{})
	if untyped == nil {
		logging.FromContext(ctx).Panic(
			"Unable to fetch knative.dev/eventing-kafka-broker/control-plane/pkg/client/informers/externalversions/sources/v1beta1.KafkaSourceInformer from context.")
	}
	return untyped.(v1beta1.KafkaSourceInformer)
}

type wrapper struct {
	client versioned.Interface

	namespace string

	resourceVersion string
}

var _ v1beta1.KafkaSourceInformer = (*wrapper)(nil)
var _ sourcesv1beta1.KafkaSourceLister = (*wrapper)(nil)

func (w *wrapper) Informer() cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(nil, &apissourcesv1beta1.KafkaSource{}, 0, nil)
}

func (w *wrapper) Lister() sourcesv1beta1.KafkaSourceLister {
	return w
}

func (w *wrapper) KafkaSources(namespace string) sourcesv1beta1.KafkaSourceNamespaceLister {
	return &wrapper{client: w.client, namespace: namespace, resourceVersion: w.resourceVersion}
}

// SetResourceVersion allows consumers to adjust the minimum resourceVersion
// used by the underlying client.  It is not accessible via the standard
// lister interface, but can be accessed through a user-defined interface and
// an implementation check e.g. rvs, ok := foo.(ResourceVersionSetter)
func (w *wrapper) SetResourceVersion(resourceVersion string) {
	w.resourceVersion = resourceVersion
}

func (w *wrapper) List(selector labels.Selector) (ret []*apissourcesv1beta1.KafkaSource, err error) {
	lo, err := w.client.SourcesV1beta1().KafkaSources(w.namespace).List(context.TODO(), v1.ListOptions{
		LabelSelector:   selector.String(),
		ResourceVersion: w.resourceVersion,
	})
	if err != nil {
		return nil, err
	}
	for idx := range lo.Items {
		ret = append(ret, &lo.Items[idx])
	}
	return ret, nil
}

func (w *wrapper) Get(name string) (*apissourcesv1beta1.KafkaSource, error) {
	return w.client.SourcesV1beta1().KafkaSources(w.namespace).Get(context.TODO(), name, v1.GetOptions{
		ResourceVersion: w.resourceVersion,
	})
}
