package com.loptamlyhoc.momopay.pay;

import java.nio.charset.StandardCharsets;
import java.util.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/api/v1/payment")
public class PayController {
    @Autowired
    private final MomoConfig momoConfig;

    public PayController(MomoConfig momoConfig) {
        this.momoConfig = momoConfig;
    }

    // === Tạo request gửi đến momo ===
    @PostMapping("/momo")
    public ResponseEntity<?> createOrder(@RequestBody Map<String, String> payload) throws Exception {
        String orderId = UUID.randomUUID().toString();
        String requestId = UUID.randomUUID().toString();
        String amount = payload.get("amount");
        String orderInfo = payload.get("orderInfo");

        // Chuỗi raw data để tạo chữ ký (signature)
        String rawSignature = "accessKey=" + momoConfig.getAccessKey() +
                "&amount=" + amount +
                "&extraData=" +
                "&ipnUrl=" + momoConfig.getIpnUrl() +
                "&orderId=" + orderId +
                "&orderInfo=" + orderInfo +
                "&partnerCode=" + momoConfig.getPartnerCode() +
                "&redirectUrl=" + momoConfig.getRedirectUrl() +
                "&requestId=" + requestId +
                "&requestType=captureWallet";

        String signature = signHmacSHA256(rawSignature, momoConfig.getSecretKey());

        // Tạo body để gửi sang MoMo
        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("partnerCode", momoConfig.getPartnerCode());
        requestBody.put("accessKey", momoConfig.getAccessKey());
        requestBody.put("requestId", requestId);
        requestBody.put("amount", amount);
        requestBody.put("orderId", orderId);
        requestBody.put("orderInfo", orderInfo);
        requestBody.put("redirectUrl", momoConfig.getRedirectUrl());
        requestBody.put("ipnUrl", momoConfig.getIpnUrl());
        requestBody.put("extraData", "");
        requestBody.put("requestType", "captureWallet");
        requestBody.put("signature", signature);
        requestBody.put("lang", "vi");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestBody, headers);

        // Gửi đến endpoint của MoMo
        String endpoint = momoConfig.getEndPoint();

        Logger logger = LoggerFactory.getLogger(PayController.class);
        logger.debug(">>>>>>>>>>>>  Info:" + endpoint);

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<?> response = restTemplate.postForEntity(endpoint, entity, Map.class);

        return ResponseEntity.ok(response.getBody());
    }

    // === Xử lý MoMo gọi IPN (xác thực kết quả giao dịch) ===
    @PostMapping("/momo/ipn")
    public ResponseEntity<String> handleIpn(@RequestBody Map<String, Object> payload) throws Exception {
        String resultCode = String.valueOf(payload.get("resultCode"));
        String orderId = (String) payload.get("orderId");
        String requestId = (String) payload.get("requestId");
        String amount = String.valueOf(payload.get("amount"));
        String orderInfo = (String) payload.get("orderInfo");
        String extraData = (String) payload.get("extraData");
        String receivedSignature = (String) payload.get("signature");

        // Tạo lại raw data như khi ký ban đầu
        String rawSignature = "accessKey=" + momoConfig.getAccessKey() +
                "&amount=" + amount +
                "&extraData=" + extraData +
                "&orderId=" + orderId +
                "&orderInfo=" + orderInfo +
                "&orderType=momo_wallet" + // mặc định
                "&partnerCode=" + momoConfig.getPartnerCode() +
                "&payType=qr" + // mặc định
                "&requestId=" + requestId +
                "&responseTime=" + payload.get("responseTime") +
                "&resultCode=" + resultCode +
                "&transId=" + payload.get("transId") +
                "&message=" + payload.get("message");

        // Kiểm tra chữ ký
        String expectedSignature = signHmacSHA256(rawSignature, momoConfig.getSecretKey());
        if (!expectedSignature.equals(receivedSignature)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid signature");
        }

        // Đã xác thực thành công → xử lý đơn hàng
        if ("0".equals(resultCode)) {
            System.out.println("✅ Thanh toán thành công cho orderId: " + orderId);
        } else {
            System.out.println("❌ Giao dịch thất bại: " + payload.get("message"));
        }

        return ResponseEntity.ok("IPN received");
    }

    // Hàm tạo chữ ký HMAC SHA256
    private String signHmacSHA256(String data, String key) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        hmac.init(secretKeySpec);
        byte[] hash = hmac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash);
    }

    // Chuyển byte[] sang Hex
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes)
            result.append(String.format("%02x", b));
        return result.toString();
    }
}
