# OIDF conformance suite, self-hosted (C3/C4)

The OpenID Foundation conformance suite, run from its prebuilt images in OrbStack, for the
lab Verifier's conformance mode (`docs/interop/oidf-conformance-plan.md` stages C3 and C4).

**Policy.** Run it on this machine only, against lab endpoints on this machine only. Never use
the hosted certification or demo servers, never point the suite at another system, and never
post issues, MRs or comments. Synthetic keys and credentials only. Exports contain the test
configuration, including the synthetic issuer private key: they are synthetic, but treat them as
lab evidence, not as anything to publish.

**Egress.** The suite container's outbound traffic is not restricted: it fetches whatever
`request_uri` it is handed, with a client that trusts every certificate (section 3). Section 2
explains why that matters and how to keep it limited to lab endpoints.

Tags used below: **[run]** = observed on 2026-11-25 by running this compose file with the
stand-in in `standin/` (section 5); **[read]** = read from the suite source at the pinned
commit, not exercised. Source paths are relative to
`src/main/java/net/openid/conformance/` in <https://gitlab.com/openid/conformance-suite> unless
they start with `src/`, `scripts/` or `nginx/`.

## 1. Pins

| What | Value |
| --- | --- |
| Suite release | tag `release-v5.3.5` = commit `246b2c14b8562012b02d0ac462d667fe49e1a937` (2026-11-24), the commit `oidf-conformance-plan.md` was written against. `application.properties` says `fintechlabs.version=5.3.5`. |
| `docker-compose-prebuilt.yml` | taken from that tag, then changed as listed at the top of `docker-compose.yml` |
| Server image | `registry.gitlab.com/openid/conformance-suite:release-v5.3.5@sha256:576ad9d6ea4230a6d58623a03c17c74e2ae1438cceec252f8721daa53a705961` (index; linux/arm64 manifest `sha256:8a6b788bd81e1a16550331f7867aa8f8cae4c181beeb02a60008d5aa678b0c73`, created 2026-11-24T10:49Z) |
| nginx image | `registry.gitlab.com/openid/conformance-suite/nginx:release-v5.3.5@sha256:fd5ae05bf2a8f246f600b16a198dd670051bbad44f0b59d903da6e294e02707d` (index; arm64 `sha256:8225f080426c77ee4cbbfc3c52c542d6defeb64a2a4e3f5da8f9e926514bae41`) |
| MongoDB | `mongo:6.0.28@sha256:8b6d8f5bbedb25cb73517b65cf99f13aeb75ad5b157a56c479287a840bbad3ac` (index; arm64 `sha256:3ed30e2875f51747c16be3807301f5595ea44a29ab339be3668c3eecd115cd89`). **Diverges from upstream**, whose default `mongo:6.0.13` is affected by CVE-2025-14847 ("MongoBleed": unauthenticated memory disclosure; MongoDB SERVER-115508 lists 6.0.0–6.0.26 as affected, fixed in 6.0.27). 6.0.28 is the newest 6.0 patch on 2026-11-25 and still matches the suite's `featureCompatibilityVersion` 6.0. [run] The suite starts and both plans run unchanged on it. |

On 2026-11-25 `:latest` resolved to the same two suite digests as `:release-v5.3.5`.

The server container also runs with `no-new-privileges` and `cap_drop: [ALL]` (not upstream);
[run] it starts and both plans run unchanged.

To move the pins: pick a new `release-v*` tag, diff its `docker-compose-prebuilt.yml`, resolve
the digests with `docker buildx imagetools inspect <image>:<tag>`, and re-check sections 4 and 5
against the new source (every condition cited there can change between releases).

## 2. Runbook

```sh
cd tools/oidf-suite
docker --context orbstack compose up -d          # pulls the pinned digests on first use
curl -sk https://localhost:8443/api/currentuser  # [run] 200 {"sub":"developer",…,"isAdmin":true} once booted (10–25 s observed)
cd ../..                                         # the driver builds the lab itself (--features conformance --locked)
RUN="evidence/oidf/$(date -u +%Y%m%dT%H%M%SZ)-$(git rev-parse --short HEAD)"
python3 -I tools/oidf-suite/driver/run_plan.py run --plan c3 --out "$RUN/c3"   # starts and stops the lab itself
python3 -I tools/oidf-suite/driver/run_plan.py run --plan c4 --out "$RUN/c4"   # export zip -> tools/oidf-suite/ (git-ignored)
python3 -I tools/oidf-suite/driver/run_plan.py summarize "$RUN"
docker --context orbstack compose -f tools/oidf-suite/docker-compose.yml down   # removes containers and network; nothing persists
```

- **No login.** The server runs the `dev` Spring profile, which sets `fintechlabs.devmode=true`
  (`src/main/resources/application-dev.properties`). `DummyUserFilter` then authenticates every
  request as the admin `DEVMODE@developer.com` (`security/DummyUserFilter.java:62-83`), and
  `WebSecurityResourceServerConfig` adds that filter to the API chain (`:132-134`). [run] The API
  answers without a token; `scripts/run-test-plan.py` would need `CONFORMANCE_DEV_MODE` set.
  This admin access is granted to **any local process**, not only a browser. While the stack is
  up, any program on this machine, and any OrbStack container (they reach host 127.0.0.1, see
  section 3), can list, read, export, rerun or delete plans and logs, and start tests. So export
  results as soon as a run ends, and keep the stack up only for the duration of a run.
- **Browser risk: SSRF and an unauthenticated admin API.** [read] CSRF protection is off
  (`security/WebSecurityResourceServerConfig.java:60`, also `WebSecurityConfig.java:107`), and
  `/test/**` carries a permissive CORS policy for any origin (`security/TestDispatcherCorsConfiguration.java`,
  `applyPermitDefaultValues`; the `authorize` path itself is excluded from that mapping, but a
  cross-site GET needs no CORS to be *sent*). So any web page open in a browser that has
  accepted the `localhost:8443` certificate can make the suite request
  `https://localhost:8443/test/a/<alias>/authorize?request_uri=<any URL>` while a test waits.
  The suite then fetches that URL with its trust-all client: server-side request forgery into
  host loopback (`host.docker.internal`), the LAN, or the internet. Therefore:
  - drive runs with `curl` or the driver (section 5e), not a browser;
  - if the UI is needed, use a throwaway browser profile, and close it before any other browsing;
  - keep the stack up only for the duration of a run (`compose down` straight after export);
  - use a fresh random alias per run (`oid4vp-lab-c3-<16 hex>`), so a guessed alias from an
    earlier run reaches nothing.
- **Loopback only.** nginx publishes `127.0.0.1:8443` only. The mTLS listener 8444, mongo 27017
  and the server's 8080 are not published.
- **No hosts-file edit.** `BASE_URL=https://localhost:8443`, so every URL the suite hands out
  (authorization endpoint, issuer, status list) starts with `https://localhost:8443/test/a/<alias>/`
  [run]. The upstream default `localhost.emobix.co.uk` is not needed (it resolved to 127.0.0.1 in
  public DNS on 2026-11-25 [run, one `dig` lookup]). [read] None of the verifier modules makes
  the suite call its own `BASE_URL`; the status-list and Entity Configuration URLs it serves
  are for the verifier to fetch (`vp1finalverifier/AbstractVP1FinalVerifierTest.java:328-342`).
- **The placeholder OIDC client ids are required.** Without `OIDC_*_CLIENTID` the server does
  not start ("Client id of registration 'gitlab' must not be empty") [run]. They are never used.
- **Ephemeral state.** Mongo keeps its data on tmpfs, so `compose down` (or `stop`) loses all
  plans and logs. Export first. `-v` is not needed; no volume is created.
- **Alias.** Tests in one plan share the configured `alias`. Starting a test while another test
  with the same alias is still running stops the older one (`runner/TestRunner.java:478-527`), so
  run modules one at a time.
- **Configs.** `config/*.config.json` are templates with `LAB:` placeholders. A run renders its
  own `config/<name>.local.json` (git-ignored), or writes under `evidence/local/`; it never edits
  the committed files.
- **Export signatures are not provenance.** The `.sig` files in an export are made with
  `fintechlabs.signingKey`, which in the dev profile is upstream's published development key
  (`src/main/resources/application-dev.properties:31`): anyone can produce them. Provenance for
  lab evidence is the SHA-256 recorded in the lab's evidence manifest
  (`scripts/evidence_manifest.sh`).

## 3. Reachability (task 2) [run]

`scripts/oidf_suite_probe.sh` starts a throwaway HTTPS server (fresh self-signed P-256 cert)
bound to **host 127.0.0.1 only**, then fetches it from inside `oidf-suite-server-1` with
`curl -k`. Result on OrbStack (Docker 29.8.2, arm64):

```
probe server listening on 127.0.0.1:18443 only
host.docker.internal reachable
host.orb.internal reachable
```

- Both names work. `host.docker.internal` resolves to `0.250.250.254`, `host.orb.internal` to an
  IPv6 ULA; OrbStack forwards both to the host loopback, and the host server sees the client as
  127.0.0.1. **Binding the lab to 127.0.0.1 is enough**; no wider bind, no host networking.
  This is OrbStack behaviour; Docker Desktop was not tested.
- **The flip side: on OrbStack, host 127.0.0.1 is not isolated from local containers.** Every
  container on this machine can reach every service bound to host loopback the same way, not only
  the suite. A loopback bind keeps the lab off the LAN, not away from other local containers. The
  lab's conformance-mode ADR therefore treats the mode as time-boxed and off by default.
- Use `host.docker.internal` in `request_uri` and `response_uri` (it is also the name the
  example configs and certificate SANs below assume).
- The suite's outbound client accepts any TLS certificate and host name (trust-all
  `X509TrustManager`, `NoopHostnameVerifier`: `condition/AbstractCondition.java` ~L677-702), so
  the lab's TLS certificate can be self-signed. Its HTTP timeouts are 60 s
  (`condition/AbstractCondition.java:746-747`).
- The probe stops its server on exit (verified: no listener left on 18443). It exits 0 when every
  alias is reachable, 1 when one is not (with curl's error), 2 when it cannot run.

## 4. Plan configuration (task 3)

The plans are created with `POST /api/plan?planName=<name>&variant=<json>` and the config JSON
as body (`info/TestPlanApi.java:93-110`). [run] for both plans.

| | C3 plain | C4 HAIP |
| --- | --- | --- |
| `planName` | `oid4vp-1final-verifier-test-plan` (alpha, not certifiable) | `oid4vp-1final-verifier-haip-test-plan` (certifiable) |
| variant | `config/c3-plain.variant.json` | `config/c4-haip.variant.json`; the plan itself pins `vp_profile=haip`, `client_id_prefix=x509_hash`, `request_method=request_uri_signed` (`vp1finalverifier/VP1FinalVerifierTestPlanHaip.java:30-32`) |
| config | `config/c3-plain.config.json` | `config/c4-haip.config.json` |

`vp_profile` must be set to `plain_vp` for C3: its default is `haip` (`variant/VPProfile.java:3-9`).

Config fields the verifier modules read (everything else in the JSON is ignored):

| Field | Plan | Meaning |
| --- | --- | --- |
| `alias` | both | Path segment of every suite URL: `https://localhost:8443/test/a/<alias>/…` (`runner/TestRunner.java:384-406`). URL-safe, unique. |
| `description` | both | Free text. |
| `client.client_id` | C3 only, **required** | The bare DNS name, e.g. `host.docker.internal`. The suite prefixes it with `x509_san_dns:` (`condition/as/OID4VPSetClientIdToIncludeClientIdScheme.java:14-22`) and requires the request's `client_id` to equal the result (`condition/as/EnsureMatchingClientId.java:15-24`). The UI tooltip says it may be left blank; the code would then expect `x509_san_dns:null`. |
| `client.request_object_trust_anchor_pem` | C4 required, C3 optional | PEM of the CA the request-object leaf chains to; with it the x5c chain gets strict PKIX validation (section 5b). HAIP fails setup without it or a RICAL (`condition/client/EnsureClientRequestObjectTrustAnchorConfigured.java:24-26`). |
| `client.rical` / `client.rical_url` | optional | ISO 18013-5 reader CA list; replaces the trust anchor; setting both is an error (`condition/client/RegisterClientRequestObjectTrustAnchor.java:14-21`). Not needed. |
| `credential.signing_jwk` | both, required | Private JWK of the synthetic SD-JWT VC issuer (section 5a). `alg` optional for EC (defaults to ES256), required otherwise (`condition/as/AbstractCredentialSigningJwkCondition.java:32-40`). `x5c` optional in code; if present it is copied into the issuer JWT header. |
| `waitTimeoutSeconds`, `skip_test`, `browser` | — | Not needed (`vp1finalverifier/AbstractVP1FinalVerifierTest.java:200-212`; `browser` is CI screenshot automation). |

[run] With configs of exactly this shape (synthetic CA, leaf with SAN `host.docker.internal`,
issuer key with `x5c`) and the request object of section 5b, every module of both plans ran to
completion; see section 5d for the results.

## 5. Facts for the lab side (task 4)

How the [run] facts were observed: `standin/standin.py`, a suite-observation stand-in. It is
**not a verifier and not the lab**. It served a signed request object on
`https://host.docker.internal:18443` (bound to 127.0.0.1), decrypted the suite's response to
record its shape, and answered by module name: 200 for positive modules, 400 for negative ones.
It verified nothing. Three switches make it wrong on purpose, to see how the suite reacts:
`--san-mismatch`, `--reuse-enc-key`, `--no-redirect-uri`. It uses fresh synthetic keys only.

```sh
uv run --with cryptography==46.0.3 python -I tools/oidf-suite/standin/standin.py \
    --plan haip --out "evidence/local/standin/$(date -u +%Y%m%dT%H%M%SZ)" oid4vp-1final-verifier-happy-flow
```

`--out` must be a new (or empty) directory; the stand-in refuses to overwrite an earlier run.
Its TLS handshakes run per connection under a 10 s deadline, so a stalled peer cannot block
the suite's requests.

### 5a. The SD-JWT VC the mock wallet presents

Built by `condition/as/CreateSdJwtKbCredential.java:20-27` and
`condition/as/AbstractCreateSdJwtCredential.java:124-243`. [run] shapes below are from a
happy-flow capture.

- **Issuer JWT header**: `{"alg":"ES256","typ":"dc+sd-jwt"}` plus `x5c` if and only if
  `signing_jwk` has `x5c` (`:199-205`). **No `kid`.** `alg` is the JWK's `alg`, or ES256 for EC.
  The lab must trust the configured issuer key directly (or via x5c to a synthetic CA).
- **Issuer JWT payload** (always disclosed, not selectively disclosable):
  `vct` = `"urn:eudi:pid:1"` (`CreateSdJwtKbCredential.java:21`); `iss` = the test's base URL
  without trailing slash, e.g. `https://localhost:8443/test/a/oid4vp-lab-c3` (`:186-187`);
  `iat` = now; `exp` = `iat` + 14 days, or + 23 h for the module without status
  (`:119-122`, [run] 1209600 s / 82800 s); `cnf` = `{"jwk":{kty,crv,x,y}}` (P-256, no `kid`)
  (`:177-181`); `status` = `{"status_list":{"idx":N,"uri":"https://localhost:8443/test/a/<alias>/statuslists/<id>"}}`
  except in `…-present-credential-without-status`; `_sd` with 3 decoy digests (`:196`).
  **There is no `_sd_alg`** [run]: the lab must default to `sha-256` when it is absent.
- **Selectively disclosable claims**, in this order (`:154-171`): `given_name` "Jean",
  `family_name` "Dupont", `birthdate` "1980-05-23", `nationalities` `[ {…: "FR"} ]` (an array whose
  one element is itself an array-element disclosure), `place_of_birth` `{ country: "FR" }`
  (`country` a nested SD claim), `issuing_authority` "Test Issuing Authority",
  `issuing_country` "FR", `picture` (a small JPEG data URL).
- **It honours the DCQL claims, by name.** Disclosures are filtered to the claim names that
  appear anywhere in any `claims[].path` (`:224-225`, `:256-313`, `condition/client/DcqlQueryUtils.java:391-400`),
  plus everything a kept disclosure references (so `["place_of_birth"]` also brings `country`).
  Path segments are flattened: `["place_of_birth","country"]` keeps both. `claim_sets` is ignored
  (upstream comment at `:264-265`). No `claims` at all ⇒ no disclosures (`:268-272`); that would also break
  `…-invalid-credential-signature`, which needs at least one disclosure
  (`condition/as/InvalidateSdJwtCredentialSignature.java:42-46`). [run] DCQL
  `given_name`/`family_name`/`birthdate` ⇒ exactly those three disclosures.
- **KB-JWT**: header `{"typ":"kb+jwt","alg":"ES256"}` (`:77`); claims `iat` (now), `aud`,
  `nonce`, `sd_hash` (`:79-83`). `aud` = the full client id **with prefix**
  (`:230`), i.e. `x509_san_dns:host.docker.internal` (C3) or `x509_hash:<b64url sha256>` (C4)
  [run]. `nonce` = the request's nonce. `sd_hash` = base64url SHA-256 over the issuer JWT and
  the *presented* disclosures, each followed by `~` (`:233`).
- **vp_token** = `{"<credential id from DCQL>": ["<issuer-jwt>~<disclosure>~…~<kb-jwt>"]}`
  (`condition/as/AddVP1FinalDCQLVPTokenToAuthorizationEndpointResponseParams.java:27-37`).
  Exactly one credential: several `credentials` need an unambiguous `credential_sets` (`:45-102`).
- **Negative mutations**: aud + `"INVALID"`, nonce + `"INVALID"`, sd_hash + `"INVALID"`, KB-JWT
  signature corrupted, issuer signature corrupted with `sd_hash` recomputed so only the signature
  is wrong, KB `iat` ±365 days, `vct` = `urn:conformance-suite:unrequested:credential:1`,
  `MinimalCnfJwk` (the happy flow's `cnf` is already minimal [run]), revoked status index.

### 5b. How the Request Object is validated

Order: `vp1finalverifier/AbstractVP1FinalVerifierTest.java:487-524` (fetch, prefix), `:650-686`
(object), `:576-648` (parameters), `:715-721` (DCQL). FAILURE unless marked WARNING.

- **Fetch**: plain GET of `request_uri` (`condition/as/FetchRequestUriAndExtractRequestObject.java:42-44`;
  [run] `Accept: text/plain, application/json, …`, so no content negotiation is needed);
  `request_uri` must be `https` and have no fragment. `request_uri_method=post` is only used by
  `…-request-uri-method-post`, which is SKIPPED without it [run]. The URL parameters may only be
  `client_id`, `request_uri`, `request_uri_method` (WARNING otherwise).
- **Header**: `typ` = `oauth-authz-req+jwt` (case-insensitive) (`condition/as/ValidateRequestObjectTypIsOAuthQauthReqJwt.java:9-26`);
  `x5c` required (`condition/as/ValidateRequestObjectSignatureAgainstX5cHeader.java:27-31`);
  signature verified with the x5c **leaf** (`:50`, `condition/AbstractValidateX5cCertificateChain.java:102-122`).
- **x5c chain** (`util/X509CertificateUtil.java:243-313`): leaf first; leaf within validity and
  **not self-signed**; the trust anchor must **not** be in x5c. With a trust anchor configured:
  full PKIX path validation to it (CA needs basicConstraints CA:true, keyUsage keyCertSign;
  revocation off). Without one (allowed in C3): only a signature walk, and the last cert may not
  be self-signed. So `x5c = [leaf]` (or `[leaf, intermediate]`), CA only in the config PEM.
- **`x509_san_dns`**: the suite does **not** check the certificate's SAN at all, nor the
  `response_uri` host. Its only check is `client_id` == `x509_san_dns:` + `client.client_id`.
  (A SAN check, `CheckIfClientIdInX509CertSanDns`, exists only in the wallet-test families.)
  [read, run] With `--san-mismatch` (leaf SAN only `DNS:san-mismatch.invalid`, `client_id`
  `x509_san_dns:host.docker.internal`) the C3 happy flow still ended in REVIEW with no new
  finding.
  Put `DNS:host.docker.internal` in the leaf SAN anyway, as OpenID4VP §5.9.3 requires, and use
  that host in `response_uri`.
- **`x509_hash`**: `client_id` must equal `x509_hash:` + base64url (no padding) SHA-256 of the
  DER of `x5c[0]` (`condition/as/ExtractAndValidateX509HashClientId.java:37-50`). [run] The KB-JWT
  `aud` then carries that value.
- **`client_id`** in the URL must equal the request object's `client_id`
  (`condition/as/EnsureClientIdInAuthorizationRequestParametersMatchRequestObject.java:12-20`).
- **Claims**: `aud` must be `https://self-issued.me/v2` or the suite issuer
  `https://localhost:8443/test/a/<alias>/` (WARNING) (`condition/as/ValidateRequestObjectAudForVP.java:22-47`);
  `iat` optional, not > 5 min in future or > 1 day old (WARNING); `exp` optional, not expired
  beyond 5 min skew; `iss` optional, WARNING if ≠ client_id; `response_type` = `vp_token`;
  `response_mode` = `direct_post.jwt`; `nonce` required (see below); `response_uri` https, no
  fragment (`condition/as/EnsureValidResponseUriForAuthorizationEndpointRequest.java:24-45`);
  no `redirect_uri`, `scope`, `client_id_scheme`, `transaction_data`, `wallet_nonce`; no
  `presentation_definition` (WARNING). `state` is allowed and echoed back. Any claim outside
  `presentation_definition dcql_query client_id client_id_scheme response_uri client_metadata
  nonce state response_type response_mode verifier_info scope request_uri_method wallet_nonce
  aud iss iat nbf exp jti` is a WARNING (`condition/as/CheckForUnexpectedParametersInVpAuthorizationRequest.java:12-38`).
- **nonce** (happy flow): URL-safe characters `[A-Za-z0-9-_.~]` (FAILURE); 16–43 characters
  (WARNING; `condition/as/CheckNonceMinimumLength.java:17`, `CheckNonceMaximumLength.java:18`);
  Shannon estimate > 64 bits (WARNING). 22-char base64url of 16 random bytes passes [run].
- **`client_metadata`** — only `jwks`, `vp_formats_supported`,
  `encrypted_response_enc_values_supported` (anything else WARNING;
  `condition/as/VP1FinalCheckForUnexpectedParametersInVpClientMetadata.java:12-16`):
  - `vp_formats_supported` must be an object with `dc+sd-jwt` an object; `sd-jwt_alg_values` /
    `kb-jwt_alg_values` optional, but if present non-empty arrays of known JWS algs
    (`condition/as/VP1FinalValidateVpFormatsSupportedInClientMetadata.java:95-130`). [run]
    `{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256"],"kb-jwt_alg_values":["ES256"]}}` passes.
  - `jwks.keys` non-empty; **every key has a unique, non-blank `kid`**
    (`condition/as/VP1FinalCheckForKeyIdInClientMetadataJWKs.java:34-56`); **every key has `alg`**;
    at least one has `use":"enc"` or no `use`
    (`condition/as/VP1FinalValidateClientMetadataJwksForEncryptedResponse.java:40-66`); public
    keys only (`sequence/ValidateJwksSequence.java:66-72`).
  - **Encryption key reuse**: the JWK thumbprint of each encryption key is remembered per suite
    user for 3 h; a key seen in an earlier Authorization Request is a **FAILURE under HAIP**, a
    WARNING in plain (`condition/as/VP1FinalCheckEncryptionKeyNotReused.java:62-79`,
    `AbstractVP1FinalVerifierTest.java:636-641`, `condition/as/RecentValueHistory.java:34`).
    [run] With `--reuse-enc-key` over happy-flow then minimal-cnf-jwk: HAIP minimal-cnf-jwk
    FAILED on `VP1FinalCheckEncryptionKeyNotReused`; in plain the same check was a WARNING and
    the module still reached REVIEW. The lab's
    research route (`crates/lab-server/src/ecdh_es.rs`: one shared key) would fail C4 from the
    second module on: the conformance mode needs a **fresh ECDH-ES key per session**. The
    history is in server memory, so a suite restart clears it; that is not a fix.
- **DCQL**: JSON-schema valid (`src/main/resources/json-schemas/oid4vp/dcql_request.json`:
  `id` `[A-Za-z0-9_-]+`, `format`, `meta` required); unique credential ids and claim paths;
  `format` = `dc+sd-jwt`; requesting `iss nbf exp cnf vct vct#integrity status aka_vcts` as a
  claim is a WARNING (`condition/client/CheckForNonSelectivelyDisclosableClaimsInDcqlQuery.java:20-21`).
  `meta.vct_values` should contain `urn:eudi:pid:1` (the `…-wrong-vct` module relies on it).

### 5c. The response

- `enc` = the **first** entry of `encrypted_response_enc_values_supported`, or A128GCM if absent
  (`condition/as/VP1FinalEncryptVPResponse.java:59-66`). `alg` = the selected key's `alg`. The key
  is the first JWK not restricted to `use":"sig"` (`util/JWEUtil.java:61-80`).
- Protected header [run]: `alg` `ECDH-ES`, `enc`, `epk` `{kty,crv,x,y}` only, `kid` (the lab's
  `kid`, when the key has one; `condition/as/AbstractJWEEncryptString.java:108-118`), `cty`
  `"json"`, `apu` and `apv` = base64url of two *different* random 16-character alphanumeric
  strings (`VP1FinalEncryptVPResponse.java:70-74`). Direct key agreement: empty encrypted key.
  This passes the lab codec's header policy as written (`crates/jose-ecdh-es/src/header.rs`
  `ACCEPTED`, `EPK_ACCEPTED`, apu ≠ apv).
- Plaintext: `{"state":"<state>","vp_token":{…}}` (`state` only if the request had one;
  `condition/as/CreateAuthorizationEndpointResponseParams.java:20-36`).
- POST [run]: `Content-Type: application/x-www-form-urlencoded`, `Accept: application/json`,
  body **only** `response=<compact JWE>` (`VP1FinalEncryptVPResponse.java:88-90`), to the
  request's `response_uri` (`condition/client/CallDirectPostEndpoint.java:34`).

### 5d. What the suite expects back, and how modules finish

Response checks (`AbstractVP1FinalVerifierTest.java:878-886`): HTTP 200 (exactly, not any 2xx),
`Content-Type: application/json`, body `{}` or `{"redirect_uri":"…"}` and nothing else
(WARNING otherwise), `redirect_uri` a non-empty string if present. **HAIP: `redirect_uri` is
required** (`condition/as/VP1FinalEnsureDirectPostResponseHasRedirectUriForHaip.java:34-38`);
[run] with `--no-redirect-uri` (`200 {}`) the HAIP happy flow FAILED on that condition. Plain
accepts `{}` [run]. The suite does not follow `redirect_uri`; it lists it as a URL to visit
(`AbstractVP1FinalVerifierTest.java:739-758`), which does not block the result.

- **Positive** modules (happy flow, minimal-cnf, fetched-twice, without-status, method-post when
  applicable): after a 2xx the test creates a screenshot placeholder and waits
  (`:764-773`). Uploading an image to it finishes the test as **REVIEW**
  (`logging/ImageAPI.java:129-170`, `testmodule/AbstractTestModule.java:1460-1490`). REVIEW is
  the best result a positive module can reach; there is no API to turn it into PASSED. [run]
- **Negative** modules: a 4xx ends the test as **PASSED** (`AbstractVP1FinalVerifierNegativeTest.java:26-30`);
  a 2xx must be a valid §8.2 response and ends in REVIEW after a screenshot of the rejection;
  3xx/5xx fail. The lab's generic 400 takes the PASSED path. [run]
- [run] Both plans, stand-in answering 200/400 (HAIP with `redirect_uri`):

  | Module | Result | Note |
  | --- | --- | --- |
  | happy-flow, minimal-cnf-jwk, request-uri-fetched-twice | REVIEW | 1 WARNING: status list not fetched; fetched-twice fetched `request_uri` twice |
  | present-credential-without-status | REVIEW | |
  | request-uri-method-post | SKIPPED | no `request_uri_method=post` |
  | invalid-kb-jwt-signature, invalid-credential-signature, invalid-sd-hash, invalid-kb-jwt-nonce, invalid-kb-jwt-aud, kb-jwt-iat-in-past, kb-jwt-iat-in-future, wrong-vct | PASSED | 400 |
  | present-revoked-credential | **FAILED** | 400 is not enough: the stand-in never fetched the status list, and that is a FAILURE in this module. [read] The rule holds for any verifier that does not fetch it (`VP1FinalVerifierPresentRevokedCredential.java:52-55`). The lab now checks status lists (ADR 0003) and passes it; see §7. |
  | invalid-session-transcript, present-credential-on-identifier-list | not in the plan | mdoc only |

- **Screenshots via API**: the placeholder id is the `upload` field of a log entry
  (`condition/AbstractCondition.java:641-648`); `POST /api/log/<testId>/images/<placeholder>`
  with a `text/plain` body `data:image/png;base64,…` (≤ 500 KB, ≤ 2 per test;
  `logging/ImageAPI.java:48-49`). [run] For lab evidence, upload a real rendering of the lab's
  verdict for that session, not a placeholder image.

### 5e. Driving a verifier test

- Each module exposes `authorization_endpoint` =
  `https://localhost:8443/test/a/<alias>/authorize` (`condition/as/GenerateServerConfiguration.java:43-44`,
  `AbstractVP1FinalVerifierTest.java:226-228`) in `GET /api/runner/<testId>` → `exposed`. [run]
- The UI's "paste the openid4vp:// URL" box only does
  `GET <authorization_endpoint>?<query string>` (`frontchannel/BrowserControl.java:255-268`,
  `src/main/resources/static/js/log-detail.js` ~L1146). A driver does the same:
  `GET https://localhost:8443/test/a/<alias>/authorize?client_id=<urlenc>&request_uri=<urlenc>`.
  [run] The call is synchronous: inside it the suite fetches `request_uri`, validates, POSTs to
  `response_uri`, and only then answers 200 with an HTML page (0.1–1.3 s observed). So the
  lab must already be serving the session when the driver calls it, and must handle the
  suite's two requests while the driver's GET is open.
- Timeouts [read]: suite HTTP client 60 s per request (`condition/AbstractCondition.java:746-747`);
  nginx proxy 120 s (`nginx/nginx.conf`, `proxy_read_timeout`/`proxy_send_timeout`); a WAITING
  test is stopped after 6 h idle (`runner/InMemoryTestRunnerSupport.java:21`).
- `scripts/run-test-plan.py` cannot drive this: it has no way to make the lab start a session,
  and relies on `browser` automation in the config. Use the REST API directly:

  | Step | Call |
  | --- | --- |
  | create plan | `POST /api/plan?planName=…&variant=<json>`, body = config → `{"id":…,"modules":[…]}` |
  | start module | `POST /api/runner?test=<module>&plan=<planId>` (no body) → `{"id":<testId>,"url":…}`; the test goes to WAITING by itself |
  | wait | `GET /api/runner/<testId>/wait-state?states=WAITING,FINISHED,INTERRUPTED&timeoutMs=30000` (long poll, ≤ 30 s; repeat) |
  | endpoint | `GET /api/runner/<testId>` → `exposed.authorization_endpoint`, `browser.uploadsRequired` |
  | deliver | `GET <authorization_endpoint>?client_id=…&request_uri=…` |
  | screenshot | `GET /api/log/<testId>` → entry with `upload`; `POST /api/log/<testId>/images/<upload>` |
  | result | `GET /api/info/<testId>` → `status`, `result` (PASSED, FAILED, WARNING, REVIEW, SKIPPED) |
  | evidence | `GET /api/log/<testId>`, `GET /api/plan/export/<planId>` (zip of signed JSON logs) [run] |
  | clean up | `DELETE /api/runner/<testId>` (stop), `DELETE /api/plan/<planId>` |

**Driver design**, implemented by `driver/run_plan.py` (section 7; its docstring lists exactly
what it does, including the lab command line it starts):

1. Preconditions: suite up and `/api/currentuser` 200; lab conformance mode up on
   `127.0.0.1:<port>` with TLS; the committed synthetic reader CA, leaf and issuer key (ADR 0002;
   the driver adds a throwaway self-signed `x5c` certificate for the issuer key per run).
   Render the plan config from the committed template into `config/<name>.local.json` or
   `evidence/local/` (both git-ignored), never editing the template. Fill the `LAB:`
   placeholders, including a fresh random alias such as `oid4vp-lab-c3-<16 hex>` per run
   (section 2), and pass the same keys to the lab config.
2. Create the plan; record `planId`, the alias, the suite tag and digests, the lab commit.
3. For each module in plan order, one at a time: start it; wait for WAITING; read
   `authorization_endpoint`; ask the lab for a new session (`POST /lab/v1/sessions`, fresh nonce,
   state and ECDH-ES key) and build `client_id` + `request_uri`; GET the authorization endpoint;
   wait; if `uploadsRequired` > 0, render the lab's verdict for that session to PNG and upload
   it; wait for FINISHED; fetch `/api/info` and `/api/log`.
4. Write `evidence/<run>/`: per-module result and sanitized log, and a manifest with all pins
   and the SHA-256 of every file (the export's own signatures are not provenance, section 2).
   The plan export holds the issuer private key: it stays in `tools/oidf-suite/` (git-ignored),
   only its SHA-256 goes into the manifest. Map REVIEW (positive) and PASSED (negative) to "as expected"; FAILED and any
   WARNING to triage.
5. Stop the stack (`compose down`) straight away.

All of this runs over HTTP from the driver; no browser is involved (section 2).

### 5f. HAIP extras (C4)

- Plan pins `x509_hash` + `request_uri_signed` + `vp_profile=haip`; only `direct_post.jwt` is
  allowed (`AbstractVP1FinalVerifierTest.java:141-146`).
- Trust anchor (or RICAL) **required** at setup; strict PKIX of `x5c` to it (5b).
- `client_id` = `x509_hash:` + base64url SHA-256 of the DER leaf (5b). The KB-JWT `aud` is that
  string.
- `encrypted_response_enc_values_supported` must contain **both** `A128GCM` and `A256GCM`, and
  `jwks` must contain a P-256 key with `alg":"ECDH-ES"`
  (`condition/as/ValidateVpClientMetadataEncryptionForHaip.java:28-85`). The suite then encrypts
  with whichever is listed first [run: A128GCM].
- Fresh encryption key per request (5b; reuse is a FAILURE [run]).
- `redirect_uri` in the 200 response body (5d; missing is a FAILURE [run]).
- No other HAIP-only condition runs in these modules: signed request, `typ`, x5c and the
  metadata checks are the same as in plain. Issuer `x5c` in the SD-JWT is whatever
  `signing_jwk.x5c` holds; the suite does not require it, but HAIP-style issuers carry it, so
  the C4 config includes it.

## 6. Still UNKNOWN

- Docker Desktop's behaviour for `host.docker.internal` → host 127.0.0.1 (only OrbStack was run).
- Whether the hosted demo server runs code newer than `release-v5.3.5` (deliberately not checked).
- Nothing in this plan's modules was observed to depend on `client.client_id` being blank,
  `iss` in the request object, or `verifier_info`; those paths were read only.

## 7. Results: the lab against both plans

### 7.1 With Token Status List checking (run `evidence/oidf/20261126T022001Z-8e487fa/`)

Its `summary.md` is the source of truth. Lab commit `8e487fa` (clean tree, built by the driver),
both plans driven by `driver/run_plan.py` only, suite stack freshly started and taken down
after the run. The lab ran as in §7.2 plus a status policy (ADR 0003): only
`https://localhost:8443/test/a/<alias>/statuslists/` URIs of that run, the list signing key
pinned explicitly (`--status-list-key crates/lab-server/tests/fixtures/lab_issuer.pub.jwk`, the
public half of the key the suite signs its lists with), and the suite nginx certificate pinned
(`--status-list-tls-cert`). That certificate is read from `localhost:8443` when the run starts
(trust on first use, over host loopback); it is stored as `suite-tls.pem` in each plan
directory and its SHA-256 is in the manifest. The HAIP `x5c` trust mode is not exercised by the
suite (its `x5c` is the driver's self-signed certificate); the lab tests cover it
(`x509_trust_accepts_only_a_signer_certified_by_the_status_ca`).

| Module | C3 plain | C4 HAIP | Lab evidence (both plans) |
| --- | --- | --- | --- |
| happy-flow, minimal-cnf-jwk, request-uri-fetched-twice | REVIEW, **no WARNING** | same | status `Valid`, committed; suite logged one list fetch (`GET`, `Accept` ok, no query, no body) |
| present-credential-without-status | REVIEW | REVIEW | `NotReferenced`, committed, nothing fetched |
| present-revoked-credential | **PASSED** (was FAILED) | **PASSED** | list fetched, then `Status(Revoked)`; nothing committed, the session stays `pending` |
| the eight negative modules | PASSED | same | refused while validating (`KbSignature`, `IssuerSignature`, ...); status not reached, nothing fetched |
| request-uri-method-post | SKIPPED | SKIPPED | no response |

- 28 of 28 modules ended as expected, with the lab-side checks (same result as the first
  status run `20261125T113627Z-e91431d`, at `e91431d`, before the review fixes): the driver requires the suite
  result, the lab's own evidence line (status outcome, commit, rejection), the suite's
  "The verifier fetched the status list ..." log entry and the session state on the lab's
  result endpoint to agree (`LAB_EXPECTED`), exactly one list fetch where one is expected,
  each negative module refused with its own `ValidationError`, and no WARNING or FAILURE in any
  module (none appeared).
- The flip of one credential from accepted to refused when only the list entry changes from
  `0x00` to `0x01` cannot be driven through the suite (it mints a new credential per module);
  the lab test `same_credential_flips_from_accepted_to_revoked_when_only_the_list_changes`
  shows it, with a real HTTPS fetch each time.
- Driver change for this run: the suite answers the authorize GET of a module it skips with a
  redirect of its own; the driver now records it (`authorize_redirect_not_followed`) instead of
  failing, and still never follows it.

### 7.2 Before status checking (run `evidence/oidf/20261125T044623Z-61dbb05/`)

Run `evidence/oidf/20261125T044623Z-61dbb05/`. Its `summary.md` is the source of truth for
the results (per-module table with reasons and the lab test covering each module); the table
below condenses it. Later driver hardening commits (leak guard, self-build, deadline,
no-redirect authorize GET) do not alter that run: its manifests record the SHA-256 of the
driver that produced it (commit `61dbb05`; the summary by `def69f4`). `manifest.json` per
plan has the lab commit, `Cargo.lock` hash, image digests, alias, Docker / OrbStack / Java
versions. That run predates the self-build: its binary was built by hand with the same command
from the same lab sources (at `5d8d14b`; `61dbb05` only adds the driver), and its dirty flag
covered tracked files only (`git status` showed no untracked files under `crates/` then). One
run per plan,
both at lab commit `61dbb05` (clean tree), suite stack freshly started, driven by
`driver/run_plan.py` only, with no browser. Lab in conformance mode with the committed synthetic
fixtures, time box 3600 s, bound to 127.0.0.1:18444, public origin
`https://host.docker.internal:18444`; DCQL `urn:eudi:pid:1` with `given_name`, `family_name`,
`birthdate`; issuer key `lab_issuer.jwk` (public half to the lab, private JWK to the suite).

| Module | C3 plain (`x509_san_dns`) | C4 HAIP (`x509_hash`, `redirect_uri`) |
| --- | --- | --- |
| happy-flow, minimal-cnf-jwk, request-uri-fetched-twice | REVIEW, 1 WARNING (status list not fetched) | same |
| present-credential-without-status | REVIEW | REVIEW |
| invalid-kb-jwt-signature, invalid-credential-signature, invalid-sd-hash, invalid-kb-jwt-nonce, invalid-kb-jwt-aud, kb-jwt-iat-in-past, kb-jwt-iat-in-future, wrong-vct | PASSED (lab answered the generic 400) | same |
| request-uri-method-post | SKIPPED (no `request_uri_method=post`) | same |
| present-revoked-credential | FAILED, expected (`EnsureVerifierFetchedRevocationList`: the lab has no status-list support) | same |

- **Every module ended as expected; no lab bug was found**, so no lab code changed. No other
  WARNING or FAILURE appeared: the request object, `x5c` chain (strict PKIX to the trust anchor
  in C4), `client_metadata`, DCQL, nonce and the 200 / 400 answers met every condition the
  modules run, and under HAIP `ValidateVpClientMetadataEncryptionForHaip` passed, the
  per-session ECDH-ES keys passed `VP1FinalCheckEncryptionKeyNotReused` and the `redirect_uri` (with a fresh `response_code`)
  passed `VP1FinalEnsureDirectPostResponseHasRedirectUriForHaip`.
- **REVIEW is not PASSED.** It is the best result a positive module can reach (section 5d); the
  uploaded image is a rendering of the lab's own result endpoint JSON for that session
  (`consumed`, the three claims, `vct`, holder key thumbprint), made by the driver, not a
  browser screenshot. Each one is in the run's `screenshots/`.
- **TLS:** the suite's JVM (Temurin 21.0.13) completed every `request_uri` GET and
  `response_uri` POST against the lab's TLS 1.3-only rustls listener; the driver's own
  connections negotiated TLS 1.3 (`TLS_AES_256_GCM_SHA384`).
- **`enc`:** the suite encrypted every response with ECDH-ES + `A128GCM`, the first value the lab
  lists (section 5c). `A256GCM` is therefore not exercised by the suite; the lab test
  `conformance_round_trip_with_x509_hash_a256gcm_and_redirect_uri` covers it.
- **Not a certification.** Nothing was submitted to the OpenID Foundation, and the hosted
  servers were not used. The suite has no OpenID4VP 1.1 or HPKE plan, so the lab's primary
  HPKE-0 path, `session_info` and the #792 shared-route scenarios are not covered by these
  results.
- **Evidence hygiene:** logs are the suite's `/api/log` entries with every private JWK member
  and the issuer private scalar replaced by `REDACTED` (the driver refuses to write a file that
  still contains the scalar). The raw exports (`*.zip`, git-ignored) were not committed.
  The suite stack was taken down and the lab stopped after the run.
