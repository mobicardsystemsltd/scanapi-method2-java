import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.Random;
import java.util.HashMap;
import java.util.Map;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.IOException;
import java.net.URL;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

public class MobicardMethod2 {
    
    private final String mobicardVersion = "2.0";
    private final String mobicardMode = "LIVE";
    private final String mobicardMerchantId;
    private final String mobicardApiKey;
    private final String mobicardSecretKey;
    private final String mobicardServiceId = "20000";
    private final String mobicardServiceType = "2";
    private final String mobicardExtraData = "your_custom_data_here_will_be_returned_as_is";
    
    private final String mobicardTokenId;
    private final String mobicardTxnReference;
    
    private final Gson gson = new Gson();
    
    public MobicardMethod2(String merchantId, String apiKey, String secretKey) {
        this.mobicardMerchantId = merchantId;
        this.mobicardApiKey = apiKey;
        this.mobicardSecretKey = secretKey;
        
        Random random = new Random();
        this.mobicardTokenId = String.valueOf(random.nextInt(900000000) + 1000000);
        this.mobicardTxnReference = String.valueOf(random.nextInt(900000000) + 1000000);
    }
    
    public String imageToBase64FromUrl(String imageUrl) throws IOException {
        URL url = new URL(imageUrl);
        try (InputStream in = url.openStream();
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
            
            byte[] imageBytes = out.toByteArray();
            return Base64.getEncoder().encodeToString(imageBytes);
        }
    }
    
    public String generateJWT(String base64Image) throws Exception {
        Map jwtHeader = new HashMap<>();
        jwtHeader.put("typ", "JWT");
        jwtHeader.put("alg", "HS256");
        String encodedHeader = base64UrlEncode(gson.toJson(jwtHeader));
        
        Map jwtPayload = new HashMap<>();
        jwtPayload.put("mobicard_version", mobicardVersion);
        jwtPayload.put("mobicard_mode", mobicardMode);
        jwtPayload.put("mobicard_merchant_id", mobicardMerchantId);
        jwtPayload.put("mobicard_api_key", mobicardApiKey);
        jwtPayload.put("mobicard_service_id", mobicardServiceId);
        jwtPayload.put("mobicard_service_type", mobicardServiceType);
        jwtPayload.put("mobicard_token_id", mobicardTokenId);
        jwtPayload.put("mobicard_txn_reference", mobicardTxnReference);
        jwtPayload.put("mobicard_scan_card_photo_base64_string", base64Image);
        jwtPayload.put("mobicard_extra_data", mobicardExtraData);
        
        String encodedPayload = base64UrlEncode(gson.toJson(jwtPayload));
        
        String headerPayload = encodedHeader + "." + encodedPayload;
        String signature = generateHMAC(headerPayload, mobicardSecretKey);
        
        return encodedHeader + "." + encodedPayload + "." + signature;
    }
    
    public JsonObject scanCard(String base64Image) throws Exception {
        String jwtToken = generateJWT(base64Image);
        
        HttpClient client = HttpClient.newHttpClient();
        
        Map requestBody = new HashMap<>();
        requestBody.put("mobicard_auth_jwt", jwtToken);
        
        String jsonBody = gson.toJson(requestBody);
        
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://mobicardsystems.com/api/v1/card_scan"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .build();
        
        HttpResponse response = client.send(request, HttpResponse.BodyHandlers.ofString());
        
        return gson.fromJson(response.body(), JsonObject.class);
    }
    
    public JsonObject scanCardFromUrl(String imageUrl) throws Exception {
        String base64Image = imageToBase64FromUrl(imageUrl);
        return scanCard(base64Image);
    }
    
    private String base64UrlEncode(String data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data.getBytes());
    }
    
    private String generateHMAC(String data, String key) throws Exception {
        Mac sha256Hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        sha256Hmac.init(secretKey);
        byte[] hmacBytes = sha256Hmac.doFinal(data.getBytes());
        return base64UrlEncode(new String(hmacBytes));
    }
    
    public static void main(String[] args) {
        try {
            MobicardMethod2 scanner = new MobicardMethod2(
                "4",
                "YmJkOGY0OTZhMTU2ZjVjYTIyYzFhZGQyOWRiMmZjMmE2ZWU3NGIxZWM3ZTBiZSJ9",
                "NjIwYzEyMDRjNjNjMTdkZTZkMjZhOWNiYjIxNzI2NDQwYzVmNWNiMzRhMzBjYSJ9"
            );
            
            JsonObject result = scanner.scanCardFromUrl(
                "https://mobicardsystems.com/scan_card_photo_one.jpg"
            );
            
            if (result.has("status")) {
                String status = result.get("status").getAsString();
                
                if ("SUCCESS".equals(status)) {
                    System.out.println("Scan Successful!");
                    
                    if (result.has("card_information")) {
                        JsonObject cardInfo = result.getAsJsonObject("card_information");
                        
                        System.out.println("Card Number: " + 
                            cardInfo.get("card_number_masked").getAsString());
                        System.out.println("Expiry Date: " + 
                            cardInfo.get("card_expiry_date").getAsString());
                        System.out.println("Card Brand: " + 
                            cardInfo.get("card_brand").getAsString());
                        System.out.println("Bank: " + 
                            cardInfo.get("card_bank_name").getAsString());
                        System.out.println("Confidence Score: " + 
                            cardInfo.get("card_confidence_score").getAsString());
                        
                        if (cardInfo.has("card_validation_checks")) {
                            JsonObject validationChecks = 
                                cardInfo.getAsJsonObject("card_validation_checks");
                            
                            if (validationChecks.has("luhn_algorithm") && 
                                validationChecks.get("luhn_algorithm").getAsBoolean()) {
                                System.out.println("✓ Luhn Algorithm Check Passed");
                            }
                            
                            if (validationChecks.has("expiry_date")) {
                                if (validationChecks.get("expiry_date").getAsBoolean()) {
                                    System.out.println("✓ Expiry Date is Valid");
                                } else {
                                    System.out.println("⚠ Expired or Invalid Expiry Date");
                                }
                            }
                        }
                    }
                } else {
                    System.out.println("Scan Failed!");
                    if (result.has("status_message")) {
                        System.out.println("Error: " + result.get("status_message").getAsString());
                    }
                }
            }
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
