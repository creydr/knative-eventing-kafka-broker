package dev.knative.eventing.kafka.broker.core.oidc;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.fabric8.kubernetes.client.Config;
import io.fabric8.kubernetes.client.ConfigBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.net.PemTrustOptions;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;

public class TokenVerifier {

  private final Vertx vertx;

  private OIDCInfo oidcInfo;

  private JwksVerificationKeyResolver jwksVerificationKeyResolver;

  public TokenVerifier(Vertx vertx) {
    this.vertx = vertx;
  }

  public Future<Boolean> verify(String token, String expectedAudience) {
    if (this.jwksVerificationKeyResolver == null) {
      return oidcDiscovery().compose(unused -> this.directVerify(token, expectedAudience));
    }

    return this.directVerify(token, expectedAudience);
  }

  private Future<Boolean> directVerify(String token, String expectedAudience) {
    Promise<Boolean> r = Promise.promise();
    return r.future().compose(booleanPromise -> {
      JwtConsumer jwtConsumer = new JwtConsumerBuilder()
        .setVerificationKeyResolver(jwksVerificationKeyResolver)
        .setExpectedAudience(expectedAudience)
        .setExpectedIssuer(this.oidcInfo.getIssuer())
        .build();

      try {
        JwtContext jwtContext = jwtConsumer.process(token);

        return Future.succeededFuture(true);
      } catch (InvalidJwtException e) {
        return Future.succeededFuture(false);
      }
    });
  }

  private Future<Void> oidcDiscovery() {
    Config c = new ConfigBuilder().build();
    KubernetesClient kClient = new KubernetesClientBuilder().withConfig(c).build();

    WebClientOptions webClientOptions = new WebClientOptions()
      .setPemTrustOptions(new PemTrustOptions().addCertPath(c.getCaCertFile()));
    WebClient webClient = WebClient.create(vertx, webClientOptions);

    return this.vertx.<OIDCInfo>executeBlocking(p -> {
      try {
        String out = kClient.raw("/.well-known/openid-configuration");

        ObjectMapper mapper = new ObjectMapper();
        OIDCInfo oidcInfo = mapper.readValue(out, OIDCInfo.class);

        p.complete(oidcInfo);
      } catch (final Exception ex) {
        p.fail(ex);
      }
    }).compose(oidcInfo -> {
      this.oidcInfo = oidcInfo;

      return webClient.getAbs(oidcInfo.getJwks().toString()).bearerTokenAuthentication(c.getAutoOAuthToken()).send();
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

      return Future.failedFuture("unexpected response code: " + res.statusCode());
    });
  }
}
