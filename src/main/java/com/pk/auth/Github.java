package com.pk.auth;

import com.google.common.base.Preconditions;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;
import lombok.Data;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpSession;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Quick demo of github oauth flow
 * Created by pallav.kothari on 4/19/17.
 */
@Controller
@Slf4j
public class Github {
    public static final String GITHUB_USER_EMAILS = "https://api.github.com/user/emails";
    static Gson gson = new GsonBuilder().setPrettyPrinting().create();
    static OkHttpClient client = new OkHttpClient.Builder().connectTimeout(5, TimeUnit.SECONDS).readTimeout(5, TimeUnit.SECONDS).build();
    public static final String ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token";
    private final UriComponentsBuilder uriBuilder;
    private final String clientId;
    private final String clientSecret;

    @Autowired
    public Github(@Value("${github.auth_uri}")  String authUri,
                  @Value("${github.scope}")     String scope,
                  @Value("${github.client_id}") String clientId,
                  @Value("${github.client_secret}") String clientSecret,
                  @Value("${redirect_uri}")     String redirectUri) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        uriBuilder = UriComponentsBuilder
                .fromHttpUrl(authUri)
                .queryParam("client_id", clientId)
                .queryParam("scope", scope)
                .queryParam("redirect_uri", redirectUri);
    }

    @RequestMapping(value = "/", method = RequestMethod.GET)
    public String index(final HttpSession httpSession, Model model) {
        String state = UUID.randomUUID().toString();
        log.info("state = " + state);
        httpSession.setAttribute("state", state);
        uriBuilder.queryParam("state", state);
        model.addAttribute("authorizeUrl", uriBuilder.toUriString());
        return "index";
    }

    /**
     * callback endpoint for github
     */
    @RequestMapping("/authorized")
    public String callback(@RequestParam("code") String code,
                           @RequestParam("state") String state,
                           HttpSession session,
                           Model model) {
        String sessionState = (String) session.getAttribute("state");
        log.info("sessionState = " + sessionState);
        if (!state.equals(sessionState))
            throw new IllegalStateException();

        String accessToken = getAccessToken(code);
        log.info("accessToken = " + accessToken);

        String emailResponse = getEmail(accessToken);

        model.addAttribute("content", emailResponse);
        return "content";
    }

    private String getEmail(String accessToken) {
        Request request = new Request.Builder()
                .url(GITHUB_USER_EMAILS)
                .addHeader("Authorization", "token " + accessToken)
                .get()
                .build();
        return executeHttpReq(request);
    }

    private String getAccessToken(String code) {
        AccessTokenPayload req = new AccessTokenPayload(this.clientId, this.clientSecret, code);

        Request request = new Request.Builder()
                .url(ACCESS_TOKEN_URL)
                .post(RequestBody.create(MediaType.parse("application/json"), gson.toJson(req)))
                .addHeader("Accept", "application/json")
                .build();
        String resp = executeHttpReq(request);
        return gson.fromJson(resp, JsonObject.class).get("access_token").getAsString();
    }

    @SneakyThrows
    private String executeHttpReq(Request request) {
        Response response = client.newCall(request).execute();
        try (ResponseBody body = response.body()) {
            String content = body.string();
            Preconditions.checkState(response.isSuccessful(), content);
            log.info(content);
            return content;
        }
    }

    @Data
    private static final class AccessTokenPayload {
        @SerializedName("client_id") private final String clientId;
        @SerializedName("client_secret") private final String clientSecret;
        private final String code;
    }
}
