package dev.knative.eventing.kafka.broker.core.oidc;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.net.URL;

class OIDCInfo {

  private String issuer;

  @JsonProperty("jwks_uri")
  private URL jwks;

  public String getIssuer() {
    return issuer;
  }

  public void setIssuer(String issuer) {
    this.issuer = issuer;
  }

  public URL getJwks() {
    return jwks;
  }

  public void setJwks(URL jwks) {
    this.jwks = jwks;
  }
}

