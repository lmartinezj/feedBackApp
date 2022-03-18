package controllers;

import com.fasterxml.jackson.databind.JsonNode;
import play.libs.Json;
import play.mvc.*;
import scala.util.parsing.json.JSON;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Inject;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * This controller contains an action to handle HTTP requests
 * to the application's home page.
 */
public class HomeController extends Controller {

    /**
     * An action that renders an HTML page with a welcome message.
     * The configuration in the <code>routes</code> file means that
     * this method will be called when the application receives a
     * <code>GET</code> request with a path of <code>/</code>.
     */
    public Result index() {
        return ok(views.html.index.render());
    }

    public Result feedback(Http.Request request) {
            JsonNode json = request.body().asJson();
            return ok("Got token: " + json.get("access_token").asText());
    }

    public static String calculateAuthorizationHeaderValue(String clientSecret, String bindIdAccessToken)
            throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException {

        // Create and initialize the Mac instance
        Mac mac = Mac.getInstance("HmacSHA256");
        byte[] keyBytes = clientSecret.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "HmacSHA256");
        mac.init(keySpec);

        // Calculate the MAC on the BindID AccessToken
        byte[] signedBytes = mac.doFinal(bindIdAccessToken.getBytes(StandardCharsets.UTF_8));

        // Encode the signed bytes to base64
        String encodedResult = Base64.getEncoder().encodeToString(signedBytes);

        // Create the Authorization Header value
        return "BindIdBackend AccessToken " + bindIdAccessToken + "; " + encodedResult;
    }
}



