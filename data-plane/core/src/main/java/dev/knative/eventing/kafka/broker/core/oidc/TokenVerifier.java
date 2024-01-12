package dev.knative.eventing.kafka.broker.core.oidc;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.fabric8.kubernetes.client.Config;
import io.fabric8.kubernetes.client.ConfigBuilder;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
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

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class TokenVerifier {

  private final Vertx vertx;

  private OIDCInfo oidcInfo;

  private JwksVerificationKeyResolver jwksVerificationKeyResolver;

  public TokenVerifier(Vertx vertx) throws ExecutionException, InterruptedException, TimeoutException {
    this.vertx = vertx;

    oidcDiscovery().wait();

    oidcDiscovery()
      .toCompletionStage()
      .toCompletableFuture()
      .get(10, TimeUnit.SECONDS);
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

  private Future<Void> oidcDiscovery() {
    Config kubeConfig = new ConfigBuilder().build();

    WebClientOptions webClientOptions = new WebClientOptions()
      .setPemTrustOptions(new PemTrustOptions().addCertPath(kubeConfig.getCaCertFile()));
    WebClient webClient = WebClient.create(vertx, webClientOptions);

    return webClient.getAbs("https://kubernetes.default.svc/.well-known/openid-configuration").bearerTokenAuthentication(kubeConfig.getAutoOAuthToken()).send().compose(res -> {
      ObjectMapper mapper = new ObjectMapper();
      try {
        OIDCInfo oidcInfo = mapper.readValue(res.bodyAsString(), OIDCInfo.class);

        return Future.succeededFuture(oidcInfo);
      } catch (JsonProcessingException e) {
        return Future.failedFuture(e);
      }
    }).compose(oidcInfo -> {
      this.oidcInfo = oidcInfo;

      return webClient.getAbs(oidcInfo.getJwks().toString()).bearerTokenAuthentication(kubeConfig.getAutoOAuthToken()).send();
    }).compose(res -> {
      if (res.statusCode() >= 200 && res.statusCode() < 300) {
        try {
          JsonWebKeySet jwks = new JsonWebKeySet(res.bodyAsString());
          this.jwksVerificationKeyResolver = new JwksVerificationKeyResolver(jwks.getJsonWebKeys());

          return Future.succeededFuture();
        } catch (Throwable t) {
          return Future.failedFuture(t);
        }
      }

      return Future.failedFuture("unexpected response code on JWKeys URL: " + res.statusCode());
    });
  }
}
