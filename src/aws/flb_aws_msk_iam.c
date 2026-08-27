/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_hmac.h>
#include <fluent-bit/flb_kafka.h>
#include <fluent-bit/flb_random.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/aws/flb_aws_msk_iam.h>
#include <fluent-bit/tls/flb_tls.h>

#include <fluent-bit/flb_signv4.h>
#include <rdkafka.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * Seconds of headroom required before a credential's expiry. We refuse to sign
 * with credentials inside this window, and cap the advertised token lifetime so
 * librdkafka refreshes before the signing credentials die.
 */
#define FLB_MSK_IAM_CRED_MARGIN 60

/*
 * Proactive credential refresh window (seconds before expiry). When cached
 * credentials get inside this window we ask the provider for fresher ones
 * BEFORE signing, instead of riding them down to the refuse-to-sign margin.
 * Mirrors aws-msk-iam-auth's asyncCredentialUpdateEnabled prefetch: the
 * signer should never see dying credentials while the supply is healthy.
 * Sized to exceed the 540s advertised token lifetime so a signing normally
 * has full-token-life credentials in hand. A failed refresh retains the
 * previous (still valid) credentials, so this can only help.
 */
#define FLB_MSK_IAM_CRED_PREFETCH 600

/*
 * Bounded retry with full-jitter backoff around credential fetch / payload
 * signing, mirroring aws-msk-iam-auth's MSKCredentialProvider defaults
 * (3 attempts, 500ms base, capped backoff). Rides through momentary
 * credential-endpoint hiccups inside one token refresh instead of failing
 * it and waiting for librdkafka's ~10s retry cadence. The jitter matters
 * fleet-wide: it de-synchronizes retries from pods that share a failing
 * node-local credential agent.
 */
#define FLB_MSK_IAM_FETCH_ATTEMPTS 3
#define FLB_MSK_IAM_RETRY_BASE_MS  500
#define FLB_MSK_IAM_RETRY_MAX_MS   5000

/*
 * Config plus a persistent credential provider. The provider is created
 * lazily on first use inside the token-refresh callback and reused across
 * refreshes. Persistence is what buys us the standard chain's cache
 * semantics: credentials are served from cache, auto-refreshed ahead of
 * expiry, and - critically - RETAINED when a refresh attempt fails, so a
 * transient credential-endpoint outage no longer means "no credentials at
 * all" while the previous ones are still valid.
 *
 * Thread-safety: the refresh callback normally runs on librdkafka's background
 * thread, but it is not guaranteed to be the only caller - the initial token
 * for a consumer is fetched from a poll before the background queue is in
 * place, and an output configured with several workers polls from each of
 * them if the background queue could not be enabled. provider_lock therefore
 * guards both the lazy creation and every use of the provider. Plugins
 * destroy the rd_kafka handle (stopping the callbacks) before calling
 * flb_aws_msk_iam_destroy(), so teardown cannot race a callback.
 */
struct flb_aws_msk_iam {
    struct flb_config *flb_config;  /* For creating the AWS provider */
    flb_sds_t region;
    flb_sds_t cluster_arn;
    struct flb_aws_provider *provider;
    struct flb_tls *provider_tls;
    pthread_mutex_t provider_lock;
};

/* Utility functions - same as before */
static int to_encode(char c)
{
    if ((c >= '0' && c <= '9') ||
        (c >= 'A' && c <= 'Z') ||
        (c >= 'a' && c <= 'z') ||
        c == '_' || c == '-' || c == '~' || c == '.') {
        return FLB_FALSE;
    }
    return FLB_TRUE;
}

static flb_sds_t uri_encode_params(const char *uri, size_t len)
{
    int i;
    flb_sds_t buf = NULL;
    flb_sds_t tmp = NULL;

    buf = flb_sds_create_size(len * 3 + 1);
    if (!buf) {
        return NULL;
    }

    for (i = 0; i < len; i++) {
        if (to_encode(uri[i]) == FLB_TRUE || uri[i] == '/') {
            tmp = flb_sds_printf(&buf, "%%%02X", (unsigned char) uri[i]);
            if (!tmp) {
                flb_sds_destroy(buf);
                return NULL;
            }
            buf = tmp;
            continue;
        }
        tmp = flb_sds_cat(buf, uri + i, 1);
        if (!tmp) {
            flb_sds_destroy(buf);
            return NULL;
        }
        buf = tmp;
    }
    return buf;
}

static flb_sds_t sha256_to_hex(unsigned char *sha256)
{
    int i;
    flb_sds_t hex;
    flb_sds_t tmp;

    hex = flb_sds_create_size(65);
    if (!hex) {
        return NULL;
    }

    for (i = 0; i < 32; i++) {
        tmp = flb_sds_printf(&hex, "%02x", sha256[i]);
        if (!tmp) {
            flb_sds_destroy(hex);
            return NULL;
        }
        hex = tmp;
    }
    return hex;
}

static int hmac_sha256_sign(unsigned char out[32],
                            unsigned char *key, size_t key_len,
                            unsigned char *msg, size_t msg_len)
{
    int result;

    result = flb_hmac_simple(FLB_HASH_SHA256,
                             key, key_len,
                             msg, msg_len,
                             out, 32);
    if (result != FLB_CRYPTO_SUCCESS) {
        return -1;
    }
    return 0;
}

static char *extract_region(const char *arn)
{
    const char *p;
    const char *r;
    size_t len;
    char *out;

    /* arn:partition:service:region:... */
    p = strchr(arn, ':');
    if (!p) {
        return NULL;
    }
    p = strchr(p + 1, ':');
    if (!p) {
        return NULL;
    }
    p = strchr(p + 1, ':');
    if (!p) {
        return NULL;
    }

    r = p + 1;
    p = strchr(r, ':');
    if (!p) {
        return NULL;
    }
    len = p - r;
    out = flb_malloc(len + 1);
    if (!out) {
        return NULL;
    }
    memcpy(out, r, len);
    out[len] = '\0';

    return out;
}

/*
 * The credential provider chain reaches AWS endpoints over HTTPS — in
 * particular the STS AssumeRoleWithWebIdentity call that EKS IRSA depends
 * on. Passing a NULL TLS context silently disables that sub-provider and
 * the chain falls back to less specific credential sources, so every
 * provider gets a dedicated TLS instance verifying against the system trust
 * store (TLS instances cannot be shared between providers, see
 * flb_aws_credentials.h). Destroy the provider before its TLS instance.
 */
static struct flb_aws_provider *msk_iam_provider_create(struct flb_aws_msk_iam *config,
                                                        struct flb_tls **out_tls)
{
    struct flb_aws_provider *provider;
    struct flb_tls *tls;

    tls = flb_tls_create(FLB_TLS_CLIENT_MODE, FLB_TRUE, FLB_FALSE,
                         NULL, NULL, NULL, NULL, NULL, NULL);
    if (!tls) {
        flb_error("[aws_msk_iam] failed to create TLS context for credentials provider");
        return NULL;
    }

    provider = flb_standard_chain_provider_create(config->flb_config, tls,
                                                  config->region, NULL, NULL,
                                                  flb_aws_client_generator(),
                                                  NULL);
    if (!provider) {
        flb_tls_destroy(tls);
        return NULL;
    }

    /*
     * The token-refresh callback may run on librdkafka's background thread
     * (rd_kafka_sasl_background_callbacks_enable), outside the Fluent Bit
     * event loop — force blocking (sync) network I/O so the credential
     * fetch doesn't try to yield to a coroutine that doesn't exist there.
     */
    provider->provider_vtable->sync(provider);

    *out_tls = tls;
    return provider;
}

static void msk_iam_provider_destroy(struct flb_aws_provider *provider,
                                     struct flb_tls *tls)
{
    if (provider) {
        flb_aws_provider_destroy(provider);
    }
    if (tls) {
        flb_tls_destroy(tls);
    }
}

/*
 * Return the persistent provider, creating and initializing it on first use.
 * The caller must hold provider_lock. A failed init destroys the half-built
 * provider so the next refresh attempt starts clean.
 */
static struct flb_aws_provider *msk_iam_get_provider(struct flb_aws_msk_iam *config)
{
    struct flb_aws_provider *provider;
    struct flb_tls *tls = NULL;

    if (config->provider) {
        return config->provider;
    }

    provider = msk_iam_provider_create(config, &tls);
    if (!provider) {
        flb_error("[aws_msk_iam] failed to create AWS credentials provider");
        return NULL;
    }

    if (provider->provider_vtable->init(provider) != 0) {
        flb_error("[aws_msk_iam] failed to initialize AWS credentials provider");
        msk_iam_provider_destroy(provider, tls);
        return NULL;
    }

    config->provider = provider;
    config->provider_tls = tls;
    return provider;
}

/*
 * Fetch credentials from the persistent provider, proactively refreshing
 * when the cached ones are inside the prefetch window. The provider retains
 * its previous credentials if the refresh fails, so the fallback re-get can
 * only return the same-or-fresher credentials; the caller's margin check
 * (refuse-to-sign) remains the final gate.
 *
 * Holds provider_lock across the whole operation, so concurrent callers
 * serialize on one fetch instead of racing the lazy provider creation. The
 * returned credentials are a private copy owned by the caller.
 */
static struct flb_aws_credentials *msk_iam_get_credentials(struct flb_aws_msk_iam *config)
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    struct flb_aws_credentials *fresh;

    pthread_mutex_lock(&config->provider_lock);

    provider = msk_iam_get_provider(config);
    if (!provider) {
        pthread_mutex_unlock(&config->provider_lock);
        return NULL;
    }

    creds = provider->provider_vtable->get_credentials(provider);

    if (creds && creds->expiration != 0 &&
        time(NULL) >= creds->expiration - FLB_MSK_IAM_CRED_PREFETCH) {
        flb_debug("[aws_msk_iam] credentials expire at %ld (< %ds away), "
                  "refreshing ahead of need",
                  (long) creds->expiration, FLB_MSK_IAM_CRED_PREFETCH);
        /*
         * Refresh only the selected sub-provider: a full-chain refresh
         * re-probes every provider ahead of it (error-level "Shared
         * credentials file does not exist" from the profile provider on
         * every prefetch) and can silently switch the chain to another
         * credential source (e.g. IMDS node role) on a transient hiccup.
         */
        flb_standard_chain_provider_refresh_current(provider);
        fresh = provider->provider_vtable->get_credentials(provider);
        if (fresh) {
            flb_aws_credentials_destroy(creds);
            creds = fresh;
        }
    }

    pthread_mutex_unlock(&config->provider_lock);

    return creds;
}

/*
 * Payload generator. The caller owns 'creds' and keeps them alive for the
 * duration of the call: signing and the token metadata (principal name,
 * advertised lifetime) must all derive from the same credentials, so the
 * fetch deliberately lives in the caller rather than here.
 */
static flb_sds_t build_msk_iam_payload(struct flb_aws_msk_iam *config,
                                       const char *host,
                                       struct flb_aws_credentials *creds)
{
    flb_sds_t payload = NULL;
    int encode_result;
    char *p;
    size_t len;
    size_t url_len;
    size_t encoded_len;
    size_t actual_encoded_len;
    size_t final_len;
    flb_sds_t credential = NULL;
    flb_sds_t credential_enc = NULL;
    flb_sds_t query = NULL;
    flb_sds_t canonical = NULL;
    flb_sds_t hexhash = NULL;
    flb_sds_t string_to_sign = NULL;
    flb_sds_t hexsig = NULL;
    flb_sds_t key = NULL;
    flb_sds_t tmp = NULL;
    flb_sds_t session_token_enc = NULL;
    flb_sds_t action_enc = NULL;
    flb_sds_t presigned_url = NULL;
    flb_sds_t empty_payload_hex = NULL;
    char amzdate[32];
    char datestamp[16];
    unsigned char sha256_buf[32];
    unsigned char key_date[32];
    unsigned char key_region[32];
    unsigned char key_service[32];
    unsigned char key_signing[32];
    unsigned char sig[32];
    unsigned char empty_payload_hash[32];
    struct tm gm;
    time_t now;

    now = time(NULL);

    /* Validate inputs */
    if (!config || !config->region || flb_sds_len(config->region) == 0) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: region is not set or invalid");
        return NULL;
    }

    if (!host || strlen(host) == 0) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: host is required");
        return NULL;
    }

    flb_info("[aws_msk_iam] build_msk_iam_payload: generating payload for host: %s, region: %s",
             host, config->region);

    if (!creds || !creds->access_key_id || !creds->secret_access_key) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: invalid or incomplete "
                  "credentials");
        return NULL;
    }

    /*
     * Refuse to sign with credentials that are already expired (or within the
     * safety margin of expiring). The EKS Pod Identity agent can return HTTP
     * 200 carrying STS credentials whose Expiration is already in the past;
     * signing the presigned URL with them produces a token MSK rejects with
     * "Access denied", which manifests as an all-broker auth burst until a
     * fresh fetch succeeds. Failing here makes the refresh callback report a
     * token failure so librdkafka retries with a fresh fetch instead of
     * presenting a doomed token. expiration == 0 means the provider could not
     * determine an expiry (e.g. static credentials), so we do not gate on it.
     */
    if (creds->expiration != 0 && now >= creds->expiration - FLB_MSK_IAM_CRED_MARGIN) {
        flb_warn("[aws_msk_iam] refusing to sign: credentials expired at %ld "
                 "(now %ld, margin %ds) - failing token refresh so a fresh "
                 "fetch is attempted instead of presenting a rejected token",
                 (long) creds->expiration, (long) now, FLB_MSK_IAM_CRED_MARGIN);
        return NULL;
    }

    gmtime_r(&now, &gm);
    strftime(amzdate, sizeof(amzdate) - 1, "%Y%m%dT%H%M%SZ", &gm);
    strftime(datestamp, sizeof(datestamp) - 1, "%Y%m%d", &gm);

    /* Build credential string */
    credential = flb_sds_create_size(256);
    if (!credential) {
        goto error;
    }

    credential = flb_sds_printf(&credential, "%s/%s/%s/kafka-cluster/aws4_request",
                               creds->access_key_id, datestamp, config->region);
    if (!credential) {
        goto error;
    }

    credential_enc = uri_encode_params(credential, flb_sds_len(credential));
    if (!credential_enc) {
        goto error;
    }

    /* CRITICAL: Encode the action parameter */
    action_enc = uri_encode_params("kafka-cluster:Connect", 21);
    if (!action_enc) {
        goto error;
    }

    /* Build canonical query string with ACTION parameter first (alphabetical order) */
    query = flb_sds_create_size(8192);
    if (!query) {
        goto error;
    }

    /* note: Action must be FIRST in alphabetical order */
    query = flb_sds_printf(&query,
                          "Action=%s&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=%s"
                          "&X-Amz-Date=%s&X-Amz-Expires=900",
                          action_enc, credential_enc, amzdate);
    if (!query) {
        goto error;
    }

    /* Add session token if present (before SignedHeaders alphabetically) */
    if (creds->session_token && flb_sds_len(creds->session_token) > 0) {
        session_token_enc = uri_encode_params(creds->session_token,
                                              flb_sds_len(creds->session_token));
        if (!session_token_enc) {
            flb_error("[aws_msk_iam] build_msk_iam_payload: failed to encode session token");
            goto error;
        }

        tmp = flb_sds_printf(&query, "&X-Amz-Security-Token=%s", session_token_enc);
        if (!tmp) {
            flb_error("[aws_msk_iam] build_msk_iam_payload: failed to append session token to query");
            goto error;
        }
        query = tmp;
    }

    /* Add SignedHeaders LAST (alphabetically after Security-Token) */
    tmp = flb_sds_printf(&query, "&X-Amz-SignedHeaders=host");
    if (!tmp) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: failed to append SignedHeaders");
        goto error;
    }
    query = tmp;

    /* Build canonical request */
    canonical = flb_sds_create_size(16384);
    if (!canonical) {
        goto error;
    }

    /* CRITICAL: MSK IAM canonical request format - use SHA256 of empty string, not UNSIGNED-PAYLOAD */
    if (flb_hash_simple(FLB_HASH_SHA256, (unsigned char *) "", 0, empty_payload_hash,
                       sizeof(empty_payload_hash)) != FLB_CRYPTO_SUCCESS) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: failed to hash empty payload");
        goto error;
    }

    empty_payload_hex = sha256_to_hex(empty_payload_hash);
    if (!empty_payload_hex) {
        goto error;
    }

    canonical = flb_sds_printf(&canonical,
                              "GET\n/\n%s\nhost:%s\n\nhost\n%s",
                              query, host, empty_payload_hex);

    flb_sds_destroy(empty_payload_hex);
    empty_payload_hex = NULL;  /* Prevent double-free */
    if (!canonical) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: failed to build canonical request");
        goto error;
    }

    /* Hash canonical request immediately */
    if (flb_hash_simple(FLB_HASH_SHA256, (unsigned char *) canonical,
                       flb_sds_len(canonical), sha256_buf,
                       sizeof(sha256_buf)) != FLB_CRYPTO_SUCCESS) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: failed to hash canonical request");
        goto error;
    }

    hexhash = sha256_to_hex(sha256_buf);
    if (!hexhash) {
        goto error;
    }

    /* Build string to sign */
    string_to_sign = flb_sds_create_size(2048);
    if (!string_to_sign) {
        goto error;
    }

    string_to_sign = flb_sds_printf(&string_to_sign,
                                   "AWS4-HMAC-SHA256\n%s\n%s/%s/kafka-cluster/aws4_request\n%s",
                                   amzdate, datestamp, config->region, hexhash);
    if (!string_to_sign) {
        goto error;
    }

    /* Derive signing key */
    key = flb_sds_create_size(128);
    if (!key) {
        goto error;
    }

    key = flb_sds_printf(&key, "AWS4%s", creds->secret_access_key);
    if (!key) {
        goto error;
    }

    len = strlen(datestamp);
    if (hmac_sha256_sign(key_date, (unsigned char *) key, flb_sds_len(key),
                        (unsigned char *) datestamp, len) != 0) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: failed to sign date");
        goto error;
    }

    /* Clean up key immediately after use - prevent double-free */
    flb_sds_destroy(key);
    key = NULL;

    len = strlen(config->region);
    if (hmac_sha256_sign(key_region, key_date, 32, (unsigned char *) config->region, len) != 0) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: failed to sign region");
        goto error;
    }

    if (hmac_sha256_sign(key_service, key_region, 32, (unsigned char *) "kafka-cluster", 13) != 0) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: failed to sign service");
        goto error;
    }

    if (hmac_sha256_sign(key_signing, key_service, 32,
                        (unsigned char *) "aws4_request", 12) != 0) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: failed to create signing key");
        goto error;
    }

    if (hmac_sha256_sign(sig, key_signing, 32,
                        (unsigned char *) string_to_sign, flb_sds_len(string_to_sign)) != 0) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: failed to sign request");
        goto error;
    }

    hexsig = sha256_to_hex(sig);
    if (!hexsig) {
        goto error;
    }

    /* Append signature to query */
    tmp = flb_sds_printf(&query, "&X-Amz-Signature=%s", hexsig);
    if (!tmp) {
        goto error;
    }
    query = tmp;

    /* Build the complete presigned URL */
    presigned_url = flb_sds_create_size(16384);
    if (!presigned_url) {
        goto error;
    }

    presigned_url = flb_sds_printf(&presigned_url, "https://%s/?%s", host, query);
    if (!presigned_url) {
        goto error;
    }

    /* Base64 URL encode the presigned URL */
    url_len = flb_sds_len(presigned_url);
    encoded_len = ((url_len + 2) / 3) * 4 + 1; /* Base64 encoding size + null terminator */

    payload = flb_sds_create_size(encoded_len);
    if (!payload) {
        goto error;
    }

    encode_result = flb_base64_encode((unsigned char*) payload, encoded_len, &actual_encoded_len,
                                     (const unsigned char*) presigned_url, url_len);
    if (encode_result == -1) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: failed to base64 encode URL");
        goto error;
    }
    flb_sds_len_set(payload, actual_encoded_len);

    /* Convert to Base64 URL encoding (replace + with -, / with _, remove padding =) */
    p = payload;
    while (*p) {
        if (*p == '+') {
            *p = '-';
        }
        else if (*p == '/') {
            *p = '_';
        }
        p++;
    }

    /* Remove padding */
    len = flb_sds_len(payload);
    while (len > 0 && payload[len-1] == '=') {
        len--;
    }
    flb_sds_len_set(payload, len);
    payload[len] = '\0';

    /* Build the complete presigned URL */
    flb_sds_destroy(presigned_url);
    presigned_url = flb_sds_create_size(16384);
    if (!presigned_url) {
        goto error;
    }

    presigned_url = flb_sds_printf(&presigned_url, "https://%s/?%s", host, query);
    if (!presigned_url) {
        goto error;
    }

    /* Add User-Agent parameter to the signed URL (like Go implementation) */
    tmp = flb_sds_printf(&presigned_url, "&User-Agent=fluent-bit-msk-iam");
    if (!tmp) {
        goto error;
    }
    presigned_url = tmp;

    /* Base64 URL encode the presigned URL (RawURLEncoding - no padding like Go) */
    url_len = flb_sds_len(presigned_url);
    encoded_len = ((url_len + 2) / 3) * 4 + 1; /* Base64 encoding size + null terminator */

    flb_sds_destroy(payload);
    payload = flb_sds_create_size(encoded_len);
    if (!payload) {
        goto error;
    }

    encode_result = flb_base64_encode((unsigned char*) payload, encoded_len, &actual_encoded_len,
                                     (const unsigned char *) presigned_url, url_len);
    if (encode_result == -1) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: failed to base64 encode URL");
        goto error;
    }

    /* Update the SDS length to match actual encoded length */
    flb_sds_len_set(payload, actual_encoded_len);

    /* Convert to Base64 URL encoding AND remove padding (RawURLEncoding like Go) */
    p = payload;
    while (*p) {
        if (*p == '+') {
            *p = '-';
        }
        else if (*p == '/') {
            *p = '_';
        }
        p++;
    }

    /* Remove ALL padding (RawURLEncoding) */
    final_len = flb_sds_len(payload);
    while (final_len > 0 && payload[final_len-1] == '=') {
        final_len--;
    }
    flb_sds_len_set(payload, final_len);
    payload[final_len] = '\0';

    /* Clean up before successful return */
    flb_sds_destroy(credential);
    flb_sds_destroy(credential_enc);
    flb_sds_destroy(canonical);
    flb_sds_destroy(hexhash);
    flb_sds_destroy(string_to_sign);
    flb_sds_destroy(hexsig);
    flb_sds_destroy(query);
    flb_sds_destroy(action_enc);
    flb_sds_destroy(presigned_url);
    if (session_token_enc) {
        flb_sds_destroy(session_token_enc);
    }

    return payload;

error:
    /* Clean up everything - check for NULL to prevent double-free */
    if (credential) {
        flb_sds_destroy(credential);
    }
    if (credential_enc) {
        flb_sds_destroy(credential_enc);
    }
    if (canonical) {
        flb_sds_destroy(canonical);
    }
    if (hexhash) {
        flb_sds_destroy(hexhash);
    }
    if (string_to_sign) {
        flb_sds_destroy(string_to_sign);
    }
    if (hexsig) {
        flb_sds_destroy(hexsig);
    }
    if (query) {
        flb_sds_destroy(query);
    }
    if (action_enc) {
        flb_sds_destroy(action_enc);
    }
    if (presigned_url) {
        flb_sds_destroy(presigned_url);
    }
    if (key) {  /* Only destroy if not already destroyed */
        flb_sds_destroy(key);
    }
    if (payload) {
        flb_sds_destroy(payload);
    }
    if (session_token_enc) {
        flb_sds_destroy(session_token_enc);
    }

    return NULL;
}


/*
 * Full-jitter backoff delay for the given (0-based) retry attempt:
 * uniform random in [0, min(FLB_MSK_IAM_RETRY_MAX_MS, base << attempt)].
 */
static uint32_t msk_iam_retry_delay_ms(int attempt)
{
    uint32_t max_ms;
    uint32_t r;

    max_ms = (uint32_t) FLB_MSK_IAM_RETRY_BASE_MS << attempt;
    if (max_ms > FLB_MSK_IAM_RETRY_MAX_MS) {
        max_ms = FLB_MSK_IAM_RETRY_MAX_MS;
    }

    if (flb_random_bytes((unsigned char *) &r, sizeof(r)) != 0) {
        /* no entropy available; fall back to half the window */
        return max_ms / 2;
    }

    return r % (max_ms + 1);
}

/* Token refresh callback - runs on librdkafka's background thread */
static void oauthbearer_token_refresh_cb(rd_kafka_t *rk,
                                         const char *oauthbearer_config,
                                         void *opaque)
{
    char host[256];
    flb_sds_t payload = NULL;
    rd_kafka_resp_err_t err;
    char errstr[512];
    int64_t now;
    int64_t md_lifetime_ms;
    time_t adv_expiry;
    const char *s3_suffix = "-s3";
    size_t arn_len;
    size_t suffix_len;
    int attempt;
    uint32_t delay_ms;
    struct flb_aws_msk_iam *config;
    struct flb_aws_credentials *creds = NULL;
    struct flb_kafka_opaque *kafka_opaque;
    (void) oauthbearer_config;

    kafka_opaque = (struct flb_kafka_opaque *) opaque;
    if (!kafka_opaque || !kafka_opaque->msk_iam_ctx) {
        flb_error("[aws_msk_iam] oauthbearer_token_refresh_cb: invalid opaque context");
        rd_kafka_oauthbearer_set_token_failure(rk, "invalid context");
        return;
    }

    flb_debug("[aws_msk_iam] running OAuth bearer token refresh callback");

    /* get the msk_iam config (not persistent context!) */
    config = kafka_opaque->msk_iam_ctx;

    /* validate region (mandatory) */
    if (!config->region || flb_sds_len(config->region) == 0) {
        flb_error("[aws_msk_iam] region is not set or invalid");
        rd_kafka_oauthbearer_set_token_failure(rk, "region not set");
        return;
    }

    /* Determine host endpoint */
    if (config->cluster_arn) {
        arn_len = strlen(config->cluster_arn);
        suffix_len = strlen(s3_suffix);
        if (arn_len >= suffix_len && strcmp(config->cluster_arn + arn_len - suffix_len, s3_suffix) == 0) {
            snprintf(host, sizeof(host), "kafka-serverless.%s.amazonaws.com", config->region);
            flb_info("[aws_msk_iam] MSK Serverless cluster, using generic endpoint: %s", host);
        }
        else {
            snprintf(host, sizeof(host), "kafka.%s.amazonaws.com", config->region);
            flb_info("[aws_msk_iam] Regular MSK cluster, using generic endpoint: %s", host);
        }
    }
    else {
        snprintf(host, sizeof(host), "kafka.%s.amazonaws.com", config->region);
        flb_info("[aws_msk_iam] Regular MSK cluster, using generic endpoint: %s", host);
    }

    flb_info("[aws_msk_iam] requesting MSK IAM payload for region: %s, host: %s", config->region, host);

    /*
     * Generate the signed payload, retrying transient failures (credential
     * endpoint hiccup, stale credentials awaiting a fresh fetch) with
     * full-jitter backoff before giving the refresh up to librdkafka's much
     * slower retry cadence. This thread exists exactly for this work, so a
     * short bounded sleep here is fine.
     */
    for (attempt = 0; ; attempt++) {
        creds = msk_iam_get_credentials(config);
        if (creds) {
            payload = build_msk_iam_payload(config, host, creds);
            if (payload) {
                break;
            }
            flb_aws_credentials_destroy(creds);
            creds = NULL;
        }
        if (attempt >= FLB_MSK_IAM_FETCH_ATTEMPTS - 1) {
            break;
        }
        delay_ms = msk_iam_retry_delay_ms(attempt);
        flb_warn("[aws_msk_iam] payload generation failed, retrying in %u ms "
                 "(attempt %d of %d)",
                 delay_ms, attempt + 2, FLB_MSK_IAM_FETCH_ATTEMPTS);
        flb_time_msleep(delay_ms);
    }
    if (!payload) {
        flb_error("[aws_msk_iam] failed to generate MSK IAM payload");
        rd_kafka_oauthbearer_set_token_failure(rk, "payload generation failed");
        return;
    }

    now = time(NULL);
    /*
     * The presigned payload is cryptographically valid for 900s (see
     * X-Amz-Expires=900 in build_msk_iam_payload) and 900s is the MSK IAM
     * ceiling — it cannot be extended. librdkafka schedules the next refresh
     * at 0.8x the lifetime we advertise here, so advertising the full 900s
     * refreshes at 720s and leaves the held token only 180s of real life. MSK
     * re-auth (connections.max.reauth.ms) landing in that tail re-presents the
     * near-expired token and the broker rejects it "Session too short",
     * dropping the connection. Advertise a shorter lifetime so the 0.8x
     * refresh fires at ~432s, keeping ~468s of genuine validity in hand for
     * any re-auth. The real signature lifetime is unchanged.
     *
     * Additionally, never advertise a lifetime that outlives the credentials
     * the payload was signed with: MSK validates the SigV4 against the STS
     * credentials, so once they expire the held token is rejected even though
     * librdkafka still considers it valid. Cap the advertised expiry to the
     * signing credentials' remaining life (minus margin) so the 0.8x refresh
     * fires before they die. expiration == 0 means unknown -> no cap.
     */
    adv_expiry = now + 540;
    if (creds->expiration != 0 &&
        creds->expiration - FLB_MSK_IAM_CRED_MARGIN < adv_expiry) {
        adv_expiry = creds->expiration - FLB_MSK_IAM_CRED_MARGIN;
    }
    md_lifetime_ms = (int64_t) adv_expiry * 1000;

    err = rd_kafka_oauthbearer_set_token(rk,
                                        payload,
                                        md_lifetime_ms,
                                        creds->access_key_id,
                                        NULL,
                                        0,
                                        errstr,
                                        sizeof(errstr));

    if (err != RD_KAFKA_RESP_ERR_NO_ERROR) {
        flb_error("[aws_msk_iam] failed to set OAuth bearer token: %s", errstr);
        rd_kafka_oauthbearer_set_token_failure(rk, errstr);
    }
    else {
        flb_info("[aws_msk_iam] OAuth bearer token successfully set");
    }

    /* Clean up (the persistent provider lives on in config) */
    if (creds) {
        flb_aws_credentials_destroy(creds);
    }
    if (payload) {
        flb_sds_destroy(payload);
    }
}

/* Register callback with lightweight config - keeps your current interface */
struct flb_aws_msk_iam *flb_aws_msk_iam_register_oauth_cb(struct flb_config *config,
                                                          rd_kafka_conf_t *kconf,
                                                          const char *cluster_arn,
                                                          struct flb_kafka_opaque *opaque)
{
    struct flb_aws_msk_iam *ctx;
    char *region_str;

    flb_info("[aws_msk_iam] registering OAuth callback with cluster ARN: %s", cluster_arn);

    if (!cluster_arn) {
        flb_error("[aws_msk_iam] cluster ARN is required");
        return NULL;
    }

    /*
     * Allocate the config. The credential provider is NOT created here — it
     * is created lazily by the first token-refresh callback, on the librdkafka
     * background thread that remains its only user (see struct comment).
     */
    ctx = flb_calloc(1, sizeof(struct flb_aws_msk_iam));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    ctx->flb_config = config;

    ctx->cluster_arn = flb_sds_create(cluster_arn);
    if (!ctx->cluster_arn) {
        flb_error("[aws_msk_iam] failed to create cluster ARN string");
        flb_free(ctx);
        return NULL;
    }

    /* Extract region */
    region_str = extract_region(cluster_arn);
    if (!region_str || strlen(region_str) == 0) {
        flb_error("[aws_msk_iam] failed to extract region from cluster ARN: %s", cluster_arn);
        flb_sds_destroy(ctx->cluster_arn);
        flb_free(ctx);
        if (region_str) flb_free(region_str);
        return NULL;
    }

    ctx->region = flb_sds_create(region_str);
    flb_free(region_str);

    if (!ctx->region) {
        flb_error("[aws_msk_iam] failed to create region string");
        flb_sds_destroy(ctx->cluster_arn);
        flb_free(ctx);
        return NULL;
    }

    flb_info("[aws_msk_iam] extracted region: %s", ctx->region);

    if (pthread_mutex_init(&ctx->provider_lock, NULL) != 0) {
        flb_error("[aws_msk_iam] failed to initialize the provider mutex");
        flb_sds_destroy(ctx->region);
        flb_sds_destroy(ctx->cluster_arn);
        flb_free(ctx);
        return NULL;
    }

    /* Set the callback and opaque */
    rd_kafka_conf_set_oauthbearer_token_refresh_cb(kconf, oauthbearer_token_refresh_cb);

    /*
     * Create the dedicated SASL callback queue so the plugin can forward it
     * to librdkafka's background thread after rd_kafka_new()
     * (rd_kafka_sasl_background_callbacks_enable). Without this the refresh
     * callback is only serviced from rd_kafka_poll(), which idle producers
     * never call — the token then expires and every broker reconnect fails
     * with "SASL authentication error: Access denied" until traffic resumes.
     */
    rd_kafka_conf_enable_sasl_queue(kconf, 1);

    flb_kafka_opaque_set(opaque, NULL, ctx);
    rd_kafka_conf_set_opaque(kconf, opaque);

    flb_info("[aws_msk_iam] OAuth callback registered successfully");

    return ctx;
}

/*
 * Route the token-refresh callback to librdkafka's background thread.
 *
 * flb_aws_msk_iam_register_oauth_cb() enables the dedicated SASL queue, which
 * is a prerequisite for forwarding it to the background thread but also takes
 * the callback off the main queue: rd_kafka_poll() no longer serves it. So if
 * the forward fails and we leave the SASL queue unattended, the callback never
 * runs at all - not even once for the initial token - and every broker
 * connection fails authentication forever. Fall back to the main queue in that
 * case, which restores exactly the poll-driven behaviour of an unpatched
 * build.
 *
 * Returns FLB_MSK_IAM_REFRESH_BACKGROUND when the refresh runs on the
 * background thread, FLB_MSK_IAM_REFRESH_POLL when it fell back to the
 * poll path, or -1 when neither queue is available.
 */
int flb_aws_msk_iam_enable_background_refresh(rd_kafka_t *rk)
{
    rd_kafka_error_t *error;
    rd_kafka_queue_t *sasl_queue;
    rd_kafka_queue_t *main_queue;

    error = rd_kafka_sasl_background_callbacks_enable(rk);
    if (!error) {
        return FLB_MSK_IAM_REFRESH_BACKGROUND;
    }

    flb_warn("[aws_msk_iam] cannot serve the token refresh on librdkafka's "
             "background thread: %s", rd_kafka_error_string(error));
    rd_kafka_error_destroy(error);

    sasl_queue = rd_kafka_queue_get_sasl(rk);
    if (!sasl_queue) {
        flb_error("[aws_msk_iam] no SASL queue to fall back on: the token "
                  "refresh callback will never run and MSK IAM "
                  "authentication cannot succeed");
        return -1;
    }

    main_queue = rd_kafka_queue_get_main(rk);
    if (!main_queue) {
        rd_kafka_queue_destroy(sasl_queue);
        flb_error("[aws_msk_iam] no main queue to fall back on: the token "
                  "refresh callback will never run and MSK IAM "
                  "authentication cannot succeed");
        return -1;
    }

    rd_kafka_queue_forward(sasl_queue, main_queue);
    rd_kafka_queue_destroy(sasl_queue);
    rd_kafka_queue_destroy(main_queue);

    return FLB_MSK_IAM_REFRESH_POLL;
}

/*
 * Destroy config and the persistent provider. Callers destroy the rd_kafka
 * handle first (stopping the background thread that uses the provider), so
 * this cannot race the refresh callback.
 */
void flb_aws_msk_iam_destroy(struct flb_aws_msk_iam *ctx)
{
    if (!ctx) {
        return;
    }

    flb_info("[aws_msk_iam] destroying MSK IAM config");

    msk_iam_provider_destroy(ctx->provider, ctx->provider_tls);
    pthread_mutex_destroy(&ctx->provider_lock);
    if (ctx->region) {
        flb_sds_destroy(ctx->region);
    }
    if (ctx->cluster_arn) {
        flb_sds_destroy(ctx->cluster_arn);
    }
    flb_free(ctx);
}
