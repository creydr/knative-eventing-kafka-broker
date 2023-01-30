/*
Copyright 2021 The Knative Authors

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

package kafkatopic

import (
	"context"
	"embed"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"knative.dev/pkg/injection/clients/dynamicclient"
	"knative.dev/reconciler-test/pkg/feature"
	"knative.dev/reconciler-test/pkg/k8s"
	"knative.dev/reconciler-test/pkg/manifest"
)

const (
	// kafkaNamespace is the namespace where kafka is installed
	kafkaNamespace = "kafka"
)

//go:embed *.yaml
var yaml embed.FS

func GVR() schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: "kafka.strimzi.io", Version: "v1beta2", Resource: "kafkatopics"}
}

// Install will create a Kafka Topic via the Strimzi topic CRD,, augmented with the config fn options.
func Install(name string, opts ...manifest.CfgFn) feature.StepFn {
	cfg := map[string]interface{}{
		"name":             name,
		"clusterNamespace": "kafka",
		"partitions":       10,
		"clusterName":      "my-cluster",
	}
	for _, fn := range opts {
		fn(cfg)
	}

	return func(ctx context.Context, t feature.T) {
		if _, err := manifest.InstallYamlFS(ctx, yaml, cfg); err != nil {
			t.Fatal(err, cfg)
		}
	}
}

// IsReady tests to see if a KafkaTopic becomes ready within the time given.
func IsReady(name string, timings ...time.Duration) feature.StepFn {
	return func(ctx context.Context, t feature.T) {
		interval, timeout := k8s.PollTimings(ctx, timings)
		if err := k8s.WaitForResourceReady(ctx, t, kafkaNamespace, name, GVR(), interval, timeout); err != nil {
			t.Error(GVR(), "did not become ready,", err)
		}
	}
}

// HasReplicationFactor asserts that the Topic has the given replication factor.
func HasReplicationFactor(name string, replicationFactor int) feature.StepFn {
	return func(ctx context.Context, t feature.T) {
		ut, err := dynamicclient.Get(ctx).
			Resource(GVR()).
			Namespace(kafkaNamespace).
			Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("failed to get topic %s/%s: %v", kafkaNamespace, name, err)
		}

		topicObj := &topic{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(ut.UnstructuredContent(), topicObj); err != nil {
			t.Fatal(err)
		}

		if topicObj.Spec.Replicas != replicationFactor {
			t.Fatalf("Kafkatopic %s/%s does not have the expected replication factor of %d. Has %d instead.", name, kafkaNamespace, topicObj.Spec.Replicas, replicationFactor)
		}
	}
}

// HasReplicationFactor asserts that the Topic has the given replication factor.
func HasNumPartitions(name string, numPartitions int) feature.StepFn {
	return func(ctx context.Context, t feature.T) {
		ut, err := dynamicclient.Get(ctx).
			Resource(GVR()).
			Namespace(kafkaNamespace).
			Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("failed to get topic %s/%s: %v", kafkaNamespace, name, err)
		}

		topicObj := &topic{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(ut.UnstructuredContent(), topicObj); err != nil {
			t.Fatal(err)
		}

		if topicObj.Spec.Partitions != numPartitions {
			t.Fatalf("Kafkatopic %s/%s does not have the expected number of partitions of %d. Has %d instead.", name, kafkaNamespace, topicObj.Spec.Partitions, numPartitions)
		}
	}
}

// WithPartitions overrides the number of partitions (default: 10).
func WithPartitions(partitions string) manifest.CfgFn {
	return func(cfg map[string]interface{}) {
		cfg["partitions"] = partitions
	}
}

// WithClusterName overrides the Kafka cluster names where to create the topic (default: my-cluster)
func WithClusterName(name string) manifest.CfgFn {
	return func(cfg map[string]interface{}) {
		cfg["clusterName"] = name
	}
}

// WithClusterNamespace overrides the Kafka cluster namespace where to create the topic (default: kafka)
func WithClusterNamespace(namespace string) manifest.CfgFn {
	return func(cfg map[string]interface{}) {
		cfg["clusterNamespace"] = namespace
	}
}
