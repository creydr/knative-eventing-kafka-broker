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
package dev.knative.eventing.kafka.broker.receiver.impl.handler;

import static dev.knative.eventing.kafka.broker.core.utils.Logging.keyValue;

import dev.knative.eventing.kafka.broker.receiver.IngressProducer;
import dev.knative.eventing.kafka.broker.receiver.IngressRequestHandler;
import dev.knative.eventing.kafka.broker.receiver.RequestContext;
import dev.knative.eventing.kafka.broker.receiver.impl.auth.*;
import io.cloudevents.core.message.MessageReader;
import io.cloudevents.http.vertx.VertxMessageFactory;
import io.netty.handler.codec.http.HttpResponseStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handler checking that the provided request is authenticated and authorized.
 */
public class AuthHandler {

    private static final Logger logger = LoggerFactory.getLogger(AuthHandler.class);

    private final AuthVerifier authVerifier;

    public AuthHandler(AuthVerifier authVerifier) {
        this.authVerifier = authVerifier;
    }

    public void handle(
            final RequestContext requestContext, final IngressProducer ingressInfo, final IngressRequestHandler next) {

        if (ingressInfo.getAudience().isEmpty()) {
            logger.debug("No audience for ingress set. Continue without authentication check...");

            // get CloudEvent from request and pass to ingress handler
            VertxMessageFactory.createReader(requestContext.getRequest())
                    .map(MessageReader::toEvent)
                    .onComplete(event -> {
                        next.handle(requestContext, event.result(), ingressInfo);
                    });
            return;
        }

        authVerifier
                .verify(requestContext.getRequest(), ingressInfo)
                .onFailure(e -> {
                    if (e instanceof AuthenticationException) {
                        logger.debug(
                                "Failed to verify authentication of request: {}", keyValue("error", e.getMessage()));
                        requestContext
                                .getRequest()
                                .response()
                                .setStatusCode(HttpResponseStatus.UNAUTHORIZED.code())
                                .end();
                    } else if (e instanceof AuthorizationException) {
                        logger.debug(
                                "Failed to verify authorization of request: {}", keyValue("error", e.getMessage()));
                        requestContext
                                .getRequest()
                                .response()
                                .setStatusCode(HttpResponseStatus.FORBIDDEN.code())
                                .end();
                    } else {
                        logger.debug(
                                "Got unexpected exception on verifying auth of request: {}",
                                keyValue("error", e.getMessage()));
                        requestContext
                                .getRequest()
                                .response()
                                .setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code())
                                .end();
                    }
                })
                .onSuccess(cloudEvent -> {
                    logger.debug("Request was authenticated and authorized. Continuing...");

                    next.handle(requestContext, cloudEvent, ingressInfo);
                });
    }
}
