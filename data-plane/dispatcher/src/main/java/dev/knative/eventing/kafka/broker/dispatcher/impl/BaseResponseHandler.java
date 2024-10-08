/*
 * Copyright © 2018 Knative Authors (knative-dev@googlegroups.com)
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
package dev.knative.eventing.kafka.broker.dispatcher.impl;

import static dev.knative.eventing.kafka.broker.core.utils.Logging.keyValue;

import dev.knative.eventing.kafka.broker.contract.DataPlaneContract;
import dev.knative.eventing.kafka.broker.core.eventtype.EventType;
import dev.knative.eventing.kafka.broker.core.eventtype.EventTypeCreator;
import dev.knative.eventing.kafka.broker.core.tracing.TracingSpan;
import dev.knative.eventing.kafka.broker.dispatcher.ResponseHandler;
import io.cloudevents.CloudEvent;
import io.cloudevents.http.vertx.VertxMessageFactory;
import io.fabric8.kubernetes.client.informers.cache.Lister;
import io.vertx.core.Future;
import io.vertx.core.buffer.Buffer;
import io.vertx.ext.web.client.HttpResponse;
import org.slf4j.Logger;

public abstract class BaseResponseHandler implements ResponseHandler {

    protected final Logger logger;

    private boolean isEventTypeAutocreateEnabled;
    private EventTypeCreator eventTypeCreator;
    private Lister<EventType> eventTypeLister;
    private DataPlaneContract.Reference reference;

    public BaseResponseHandler(Logger logger) {
        this.logger = logger;
        this.isEventTypeAutocreateEnabled = false;
    }

    public BaseResponseHandler withEventTypeAutocreate(
            EventTypeCreator eventTypeCreator,
            Lister<EventType> eventTypeLister,
            DataPlaneContract.Reference reference) {
        logger.info("cali0707: enabling eventtype autocreate");
        this.eventTypeCreator = eventTypeCreator;
        this.eventTypeLister = eventTypeLister;
        this.reference = reference;
        this.isEventTypeAutocreateEnabled = true;
        return this;
    }

    /**
     * The {@link BaseResponseHandler} will convert the response from the sink into a CloudEvent. Implementations should
     * handle the CloudEvent.
     *
     * @param event CloudEvent parsed from the sink response
     * @return future for handling
     */
    protected abstract Future<Void> doHandleEvent(CloudEvent event);

    @Override
    public Future<Void> handle(HttpResponse<Buffer> response) {
        CloudEvent event;

        try {
            event = VertxMessageFactory.createReader(response).toEvent();
        } catch (final Exception ex) {
            if (maybeIsNotEvent(response)) {
                if (logger.isDebugEnabled()) {
                    logger.debug(
                            "Response is not recognized as event, discarding it {} {} {}",
                            keyValue("response", response),
                            keyValue(
                                    "response.body",
                                    response == null || response.body() == null ? "null" : response.body()),
                            keyValue(
                                    "response.body.len",
                                    response == null || response.body() == null
                                            ? "null"
                                            : response.body().length()));
                }
                return Future.succeededFuture();
            }

            // When the sink returns a malformed event we return a failed future to avoid committing the message to
            // Kafka.
            return Future.failedFuture(new IllegalStateException(
                    "Unable to decode response: unknown encoding and non empty response", ex));
        }

        if (event == null) {
            return Future.failedFuture(new IllegalArgumentException("event cannot be null"));
        }

        TracingSpan.decorateCurrentWithEvent(event);

        if (this.isEventTypeAutocreateEnabled) {
            return this.doHandleEvent(event).compose((ignored) -> this.eventTypeCreator
                    .create(event, this.eventTypeLister, this.reference)
                    .compose(
                            eventType -> {
                                logger.debug("successfully created eventtype {}", eventType);
                                return Future.succeededFuture();
                            },
                            cause -> {
                                logger.warn("failed to create eventtype", cause);
                                return Future.failedFuture(cause);
                            }));
        }
        return this.doHandleEvent(event);
    }

    private static boolean maybeIsNotEvent(final HttpResponse<Buffer> response) {
        // This checks whether there is something in the body or not, though binary events can contain only headers and
        // they
        // are valid Cloud Events.
        return response == null || response.body() == null || response.body().length() <= 0;
    }
}
