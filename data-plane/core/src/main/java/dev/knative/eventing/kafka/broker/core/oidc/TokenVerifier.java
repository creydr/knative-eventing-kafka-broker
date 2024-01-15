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
package dev.knative.eventing.kafka.broker.core.oidc;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.fabric8.kubernetes.client.Config;
import io.fabric8.kubernetes.client.ConfigBuilder;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.net.PemTrustOptions;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class TokenVerifier {

  private static final Logger logger = LoggerFactory.getLogger(TokenVerifier.class);

  private final Vertx vertx;

  private OIDCInfo oidcInfo;

  private JwksVerificationKeyResolver jwksVerificationKeyResolver;

  public TokenVerifier(Vertx vertx) throws ExecutionException, InterruptedException, TimeoutException {
    this.vertx = vertx;

    oidcDiscovery()
      .onFailure(t -> {
        logger.error("could not do OIDC discovery", t);
        throw new RuntimeException(t);
      })
      .toCompletionStage()
      .toCompletableFuture()
      .get();
  }

  public Future<JwtClaims> verify(String token, String expectedAudience) {
    return this.vertx.<JwtClaims>executeBlocking(promise -> {
      // execute blocking, as jose .process() is blocking

      JwtConsumer jwtConsumer = new JwtConsumerBuilder()
        .setVerificationKeyResolver(this.jwksVerificationKeyResolver)
        .setExpectedAudience(expectedAudience)
        .setExpectedIssuer(this.oidcInfo.getIssuer())
        .build();

      try {
        JwtContext jwtContext = jwtConsumer.process(token);

        promise.complete(jwtContext.getJwtClaims());
      } catch (InvalidJwtException e) {
        promise.fail(e);
      }
    });
  }

  public Future<JwtClaims> verify(HttpServerRequest request, String expectedAudience) {
    String authHeader = request.getHeader("Authorization");
    if (authHeader.length() == 0) {
      return Future.failedFuture("Request didn't contain auth header"); // change to exception
    }

    if (!authHeader.startsWith("Bearer ")) {
      return Future.failedFuture("Authorization header didn't contain Bearer token"); // change to exception
    }

    String token = authHeader.substring("Bearer ".length() -1);

    return verify(token, expectedAudience);
  }

  private Future<Void> oidcDiscovery() {
    Config kubeConfig = new ConfigBuilder().build();

    WebClientOptions webClientOptions = new WebClientOptions()
      .setPemTrustOptions(new PemTrustOptions().addCertPath(kubeConfig.getCaCertFile()));
    WebClient webClient = WebClient.create(vertx, webClientOptions);

    return webClient.getAbs("https://kubernetes.default.svc/.well-known/openid-configuration").bearerTokenAuthentication(kubeConfig.getAutoOAuthToken()).send().compose(res -> {
      logger.debug("Got raw OIDC discovery info: " + res.bodyAsString());

      ObjectMapper mapper = new ObjectMapper();
      try {
        OIDCInfo oidcInfo = mapper.readValue(res.bodyAsString(), OIDCInfo.class);

        return Future.succeededFuture(oidcInfo);
      } catch (JsonProcessingException e) {
        logger.error("Failed to parse OIDC discovery info", e);

        return Future.failedFuture(e);
      }
    }).compose(oidcInfo -> {
      this.oidcInfo = oidcInfo;

      logger.debug("Got OIDC discovery info: " + oidcInfo);

      return webClient.getAbs(oidcInfo.getJwks().toString()).bearerTokenAuthentication(kubeConfig.getAutoOAuthToken()).send();
    }).compose(res -> {
      if (res.statusCode() >= 200 && res.statusCode() < 300) {
        try {
          JsonWebKeySet jwks = new JsonWebKeySet(res.bodyAsString());
          this.jwksVerificationKeyResolver = new JwksVerificationKeyResolver(jwks.getJsonWebKeys());

          logger.debug("Got JWKeys: " + jwks.toJson());

          return Future.succeededFuture();
        } catch (Throwable t) {
          logger.error("Failed to parse JWKeys", t);

          return Future.failedFuture(t);
        }
      }

      logger.error("Got unexpected response code for JWKey URL: " + res.statusCode());

      return Future.failedFuture("unexpected response code on JWKeys URL: " + res.statusCode());
    });
  }
}
