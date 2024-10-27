package dev.lavalink.youtube.http;

import com.grack.nanojson.JsonObject;
import com.grack.nanojson.JsonParser;
import com.grack.nanojson.JsonParserException;
import com.grack.nanojson.JsonWriter;
import com.sedmelluq.discord.lavaplayer.tools.DataFormatTools;
import com.sedmelluq.discord.lavaplayer.tools.ExceptionTools;
import com.sedmelluq.discord.lavaplayer.tools.io.HttpClientTools;
import com.sedmelluq.discord.lavaplayer.tools.io.HttpInterface;
import com.sedmelluq.discord.lavaplayer.tools.io.HttpInterfaceManager;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class YoutubeOauth2Handler {
    private static final Logger log = LoggerFactory.getLogger(YoutubeOauth2Handler.class);
    private static int fetchErrorLogCount = 0;

    // no, i haven't leaked anything of mine
    // this (i presume) can be found within youtube's page source
    // ¯\_(ツ)_/¯
    private static final String CLIENT_ID = "861556708454-d6dlm3lh05idd8npek18k6be8ba3oc68.apps.googleusercontent.com";
    private static final String CLIENT_SECRET = "SboVhoG9s0rNafixCSGGKXAT";
    private static final String SCOPES = "http://gdata.youtube.com https://www.googleapis.com/auth/youtube";
    private static final String OAUTH_FETCH_CONTEXT_ATTRIBUTE = "yt-oauth";

    private final HttpInterfaceManager httpInterfaceManager;

    private boolean enabled;
    private String refreshToken;

    private String tokenType;
    private String accessToken;
    private long tokenExpires;

    private List<YoutubeOauth2Account> oauth2Accounts = new CopyOnWriteArrayList<>();
    private AtomicInteger accountIndex = new AtomicInteger(0);

    public YoutubeOauth2Handler(HttpInterfaceManager httpInterfaceManager) {
        this.httpInterfaceManager = httpInterfaceManager;
    }

    private class YoutubeOauth2Account {
        private String refreshToken;
        private String tokenType;
        private String accessToken;
        private long tokenExpires;

        public YoutubeOauth2Account(String refreshToken, String tokenType, String accessToken, long tokenExpires) {
            this.refreshToken = refreshToken;
            this.tokenType = tokenType;
            this.accessToken = accessToken;
            this.tokenExpires = tokenExpires;
        }

        public String getRefreshToken() {
            return refreshToken;
        }

        public void setRefreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
        }

        public String getTokenType() {
            return tokenType;
        }

        public void setTokenType(String tokenType) {
            this.tokenType = tokenType;
        }

        public String getAccessToken() {
            return accessToken;
        }

        public void setAccessToken(String accessToken) {
            this.accessToken = accessToken;
        }

        public long getTokenExpires() {
            return tokenExpires;
        }

        public void setTokenExpires(long tokenExpires) {
            this.tokenExpires = tokenExpires;
        }
    }

    public void addRefreshToken(@NotNull String... refreshTokens) {
        for (String refreshToken : refreshTokens) {
            if (refreshToken == null) throw new IllegalArgumentException("cannot supply a null refreshToken");
            oauth2Accounts.add(new YoutubeOauth2Account(refreshToken, null, null, System.currentTimeMillis()));
            refreshAccessToken(refreshToken, true);
        }
    }

    public List<String> getAccountRefreshTokens() {
        return oauth2Accounts.stream().map(account -> account.refreshToken).collect(Collectors.toList());
    }

    public boolean isOauthFetchContext(HttpClientContext context) {
        return context.getAttribute(OAUTH_FETCH_CONTEXT_ATTRIBUTE) == Boolean.TRUE;
    }

    private void initializeAccessToken() {
        JsonObject response = fetchDeviceCode();

        log.debug("fetch device code response: {}", JsonWriter.string(response));

        String verificationUrl = response.getString("verification_url");
        String userCode = response.getString("user_code");
        String deviceCode = response.getString("device_code");
        long interval = response.getLong("interval") * 1000;

        log.info("==================================================");
        log.info("!!! DO NOT AUTHORISE WITH YOUR MAIN ACCOUNT, USE A BURNER !!!");
        log.info("OAUTH INTEGRATION: To give youtube-source access to your account, go to {} and enter code {}", verificationUrl, userCode);
        log.info("!!! DO NOT AUTHORISE WITH YOUR MAIN ACCOUNT, USE A BURNER !!!");
        log.info("==================================================");

        // Should this be a daemon?
        new Thread(() -> pollForToken(deviceCode, interval == 0 ? 5000 : interval), "youtube-source-token-poller").start();
    }

    /**
     * Returns JSON that can be used to poll for oauth connection
     *
     * <code>
     *     {
     *         "device_code": "REDACTED", - the value which should be passed to pollForToken
     *         "user_code": "REDACTED", - the code which needs to be entered by the account you want to authorise with
     *         "expires_in": 1800,
     *         "interval": 5, - interval in seconds
     *         "verification_url": "https://www.google.com/device"
     *     }
     * </code>
     * */
    public JsonObject fetchDeviceCode() {
        // @formatter:off
        String requestJson = JsonWriter.string()
            .object()
                .value("client_id", CLIENT_ID)
                .value("scope", SCOPES)
                .value("device_id", UUID.randomUUID().toString().replace("-", ""))
                .value("device_model", "ytlr::")
            .end()
            .done();
        // @formatter:on

        HttpPost request = new HttpPost("https://www.youtube.com/o/oauth2/device/code");
        StringEntity body = new StringEntity(requestJson, ContentType.APPLICATION_JSON);
        request.setEntity(body);

        try (HttpInterface httpInterface = getHttpInterface();
             CloseableHttpResponse response = httpInterface.execute(request)) {
            HttpClientTools.assertSuccessWithContent(response, "device code fetch");
            return JsonParser.object().from(response.getEntity().getContent());
        } catch (IOException | JsonParserException e) {
            throw ExceptionTools.toRuntimeException(e);
        }
    }

    /**
     * Poll for the deviceCode received from the {@link #fetchDeviceCode()} method
     *
     * This should be ran in a new {@link Thread} as the process is thread-blocking.
     * */
    public void pollForToken(String deviceCode, long interval) {
        // @formatter:off
        String requestJson = JsonWriter.string()
            .object()
                .value("client_id", CLIENT_ID)
                .value("client_secret", CLIENT_SECRET)
                .value("code", deviceCode)
                .value("grant_type", "http://oauth.net/grant_type/device/1.0")
            .end()
            .done();
        // @formatter:on

        HttpPost request = new HttpPost("https://www.youtube.com/o/oauth2/token");
        StringEntity body = new StringEntity(requestJson, ContentType.APPLICATION_JSON);
        request.setEntity(body);

        while (true) {
            try (HttpInterface httpInterface = getHttpInterface();
                 CloseableHttpResponse response = httpInterface.execute(request)) {
                HttpClientTools.assertSuccessWithContent(response, "oauth2 token fetch");
                JsonObject parsed = JsonParser.object().from(response.getEntity().getContent());

                log.debug("oauth2 token fetch response: {}", JsonWriter.string(parsed));

                if (parsed.has("error") && !parsed.isNull("error")) {
                    String error = parsed.getString("error");

                    switch (error) {
                        case "authorization_pending":
                        case "slow_down":
                            Thread.sleep(interval);
                            continue;
                        case "expired_token":
                            log.error("OAUTH INTEGRATION: The device token has expired. OAuth integration has been canceled.");
                        case "access_denied":
                            log.error("OAUTH INTEGRATION: Account linking was denied. OAuth integration has been canceled.");
                        default:
                            log.error("Unhandled OAuth2 error: {}", error);
                    }

                    return;
                }

                updateTokens(parsed);
                log.info("OAUTH INTEGRATION: Token retrieved successfully. Store your refresh token as this can be reused. ({})", refreshToken);
                enabled = true;
                return;
            } catch (IOException | JsonParserException | InterruptedException e) {
                log.error("Failed to fetch OAuth2 token response", e);
            }
        }
    }

    /**
     * Refreshes an access token using a supplied refresh token.
     * @param force Whether to forcefully renew the access token, even if it doesn't necessarily
     *              need to be refreshed yet.
     */
    public void refreshAccessToken(String refreshToken, boolean force) {
        log.debug("Refreshing access token (force: {})", force);

        if (DataFormatTools.isNullOrEmpty(refreshToken)) {
            throw new IllegalStateException("Cannot fetch access token without a refresh token!");
        }

        final YoutubeOauth2Account account = oauth2Accounts.stream().filter(acc -> acc.refreshToken.equals(refreshToken)).findFirst().orElse(null);
        if (account == null) return;

        if (account.tokenExpires < System.currentTimeMillis() && !force) {
            log.debug("Access token does not need to be refreshed yet.");
            return;
        }

        synchronized (this) {
            // @formatter:off
            String requestJson = JsonWriter.string()
                .object()
                    .value("client_id", CLIENT_ID)
                    .value("client_secret", CLIENT_SECRET)
                    .value("refresh_token", refreshToken)
                    .value("grant_type", "refresh_token")
                .end()
                .done();
            // @formatter:on

            HttpPost request = new HttpPost("https://www.youtube.com/o/oauth2/token");
            StringEntity entity = new StringEntity(requestJson, ContentType.APPLICATION_JSON);
            request.setEntity(entity);

            try (HttpInterface httpInterface = getHttpInterface();
                 CloseableHttpResponse response = httpInterface.execute(request)) {
                HttpClientTools.assertSuccessWithContent(response, "oauth2 token fetch");
                JsonObject parsed = JsonParser.object().from(response.getEntity().getContent());

                if (parsed.has("error") && !parsed.isNull("error")) {
                    throw new RuntimeException("Refreshing access token returned error " + parsed.getString("error"));
                }

                log.info("Parsed json {}", parsed);

                long tokenLifespan = parsed.getLong("expires_in");
                account.setTokenType(parsed.getString("token_type"));
                account.setAccessToken(parsed.getString("access_token"));
                account.setRefreshToken(parsed.getString("refresh_token", refreshToken));
                account.setTokenExpires(System.currentTimeMillis() + (tokenLifespan * 1000) - 60000);

                log.info("YouTube access token refreshed successfully, expires in {} seconds", tokenLifespan);
            } catch (IOException | JsonParserException e) {
                throw ExceptionTools.toRuntimeException(e);
            }
        }

        if (!enabled) enabled = true;
    }

    private void updateTokens(JsonObject json) {
        long tokenLifespan = json.getLong("expires_in");
        tokenType = json.getString("token_type");
        accessToken = json.getString("access_token");
        refreshToken = json.getString("refresh_token", refreshToken);
        tokenExpires = System.currentTimeMillis() + (tokenLifespan * 1000) - 60000;

        log.debug("OAuth access token is {} and refresh token is {}. Access token expires in {} seconds.", accessToken, refreshToken, tokenLifespan);
    }

    public void applyToken(HttpUriRequest request) {
        if (!enabled || oauth2Accounts.isEmpty()) {
            return;
        }

        int index = accountIndex.incrementAndGet();
        YoutubeOauth2Account account = oauth2Accounts.get(index);

        accountIndex.set((index % oauth2Accounts.size()));

        if (account.tokenExpires <= System.currentTimeMillis()) {
            log.debug("Access token has expired, refreshing...");

            try {
                refreshAccessToken(account.refreshToken, false);
            } catch (Throwable t) {
                if (++fetchErrorLogCount <= 3) {
                    // log fetch errors up to 3 consecutive times to avoid spamming logs. in theory requests can still be made
                    // without an access token, but they are less likely to succeed. regardless, we shouldn't bloat a
                    // user's logs just in case YT changed something and broke oauth integration.
                    log.error("Refreshing YouTube access token failed", t);
                } else {
                    log.debug("Refreshing YouTube access token failed", t);
                }

                // retry in 15 seconds to avoid spamming YouTube with requests.
                account.setTokenExpires(System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(15));
                return;
            }

            fetchErrorLogCount = 0;
        }

        // check again to ensure updating worked as expected.
        if (account.accessToken != null && account.tokenType != null && System.currentTimeMillis() < tokenExpires) {
            log.debug("Using oauth authorization header with value \"{} {}\"", tokenType, accessToken);
            request.setHeader("Authorization", String.format("%s %s", tokenType, accessToken));
        }
    }

    private HttpInterface getHttpInterface() {
        HttpInterface httpInterface = httpInterfaceManager.getInterface();
        httpInterface.getContext().setAttribute(OAUTH_FETCH_CONTEXT_ATTRIBUTE, true);
        return httpInterface;
    }
}
