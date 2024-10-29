package dev.lavalink.youtube.http;

public class YoutubeOauth2Account {
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
