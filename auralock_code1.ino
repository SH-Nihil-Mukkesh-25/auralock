// AuraLock ESP32-CAM + Edge Impulse + Relay + MPU6050 + WhatsApp
// Requires: Edge Impulse Arduino library (project export), Adafruit_MPU6050, Adafruit_Sensor, UrlEncode
// Board: AI Thinker ESP32-CAM, PSRAM Enabled

// AuraLock Enhanced Security System
// Multi-layered authentication with owner approval and security alerts

#include <WiFi.h>
#include <HTTPClient.h>
#include <UrlEncode.h>
#include <Wire.h>
#include <Adafruit_MPU6050.h>
#include <Adafruit_Sensor.h>
#include <time.h>
#include <esp_camera.h>

// Edge Impulse include
#include <auralock_inferencing.h>

// Camera model selection
#define CAMERA_MODEL_AI_THINKER

// AI Thinker pins
#if defined(CAMERA_MODEL_AI_THINKER)
  #define PWDN_GPIO_NUM     32
  #define RESET_GPIO_NUM    -1
  #define XCLK_GPIO_NUM      0
  #define SIOD_GPIO_NUM     26
  #define SIOC_GPIO_NUM     27
  #define Y9_GPIO_NUM       35
  #define Y8_GPIO_NUM       34
  #define Y7_GPIO_NUM       39
  #define Y6_GPIO_NUM       36
  #define Y5_GPIO_NUM       21
  #define Y4_GPIO_NUM       19
  #define Y3_GPIO_NUM       18
  #define Y2_GPIO_NUM        5
  #define VSYNC_GPIO_NUM    25
  #define HREF_GPIO_NUM     23
  #define PCLK_GPIO_NUM     22
#endif

// Configuration
const char* WIFI_SSID = "YOUR_SSID";
const char* WIFI_PASS = "YOUR_PASS";
const char* OWNER_PHONE = "91XXXXXXXXXX";          // Primary owner
const char* SECURITY_PHONE = "91YYYYYYYYYY";       // Security guard/trusted person
const char* WHATSAPP_APIKEY = "YOUR_API_KEY";
const char* TELEGRAM_BOT_TOKEN = "YOUR_BOT_TOKEN";  // Alternative for images
const char* TELEGRAM_CHAT_ID = "YOUR_CHAT_ID";

// Hardware pins
const int RELAY_PIN = 14;
const int STATUS_LED = 33;
const int BUZZER_PIN = 2;  // Optional buzzer for alerts

// Security settings
const float CONFIDENCE_THRESHOLD = 0.70f;
const float TAMPER_G_THRESHOLD = 2.0f;
const unsigned long PIN_TIMEOUT = 60000;           // 1 minute to respond
const unsigned long ACCESS_REQUEST_COOLDOWN = 30000; // 30s between requests
const int MAX_FAILED_ATTEMPTS = 3;
const unsigned long LOCKDOWN_DURATION = 300000;    // 5 minute lockdown

// MPU6050 and camera setup
Adafruit_MPU6050 mpu;
const int I2C_SDA = 21;
const int I2C_SCL = 22;

#define EI_CAMERA_RAW_FRAME_BUFFER_COLS  320
#define EI_CAMERA_RAW_FRAME_BUFFER_ROWS  240
#define EI_CAMERA_FRAME_BYTE_SIZE        3

// Global variables
static bool is_initialised = false;
static uint8_t* snapshot_buf = nullptr;

struct SecurityEvent {
  String personType;
  float confidence;
  String timestamp;
  int currentPin;
  bool awaitingResponse;
  unsigned long requestTime;
};

struct SystemSecurity {
  int failedAttempts;
  unsigned long lastAttemptTime;
  unsigned long lastAccessRequest;
  bool isLockdown;
  unsigned long lockdownStartTime;
  int consecutiveTamperAlerts;
};

SecurityEvent currentEvent;
SystemSecurity securityState;

// Forward declarations
bool ei_camera_init();
bool ei_camera_capture(uint32_t img_w, uint32_t img_h, uint8_t *out_buf);
int ei_camera_get_data(size_t offset, size_t length, float *out_ptr);
void sendWhatsAppMessage(const String& phone, const String& message);
void sendTelegramImage(const String& message, uint8_t* imageBuffer, size_t imageSize);
String generateRandomPin();
String getCurrentDateTime();
void handleOwnerResponse(const String& response);
void triggerSecurityAlert(const String& alertType);
void checkSystemHealth();
bool captureAndSaveImage(String& base64Image);

void setup() {
  Serial.begin(115200);
  delay(1000);

  // Initialize pins
  pinMode(RELAY_PIN, OUTPUT);
  pinMode(STATUS_LED, OUTPUT);
  pinMode(BUZZER_PIN, OUTPUT);
  digitalWrite(RELAY_PIN, LOW);
  digitalWrite(STATUS_LED, LOW);
  digitalWrite(BUZZER_PIN, LOW);

  // Initialize security state
  memset(&currentEvent, 0, sizeof(currentEvent));
  memset(&securityState, 0, sizeof(securityState));

  // Wi-Fi connection
  Serial.print("Connecting to Wi-Fi");
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWi-Fi connected: " + WiFi.localIP().toString());

  // Configure time (for timestamps)
  configTime(19800, 0, "pool.ntp.org"); // UTC+5:30 for India
  
  // Initialize camera
  if (!ei_camera_init()) {
    Serial.println("Camera initialization failed!");
    triggerSecurityAlert("SYSTEM_FAILURE");
    while(true) delay(1000);
  }
  
  // Allocate camera buffer
  snapshot_buf = (uint8_t*)malloc(EI_CAMERA_RAW_FRAME_BUFFER_COLS * 
                                  EI_CAMERA_RAW_FRAME_BUFFER_ROWS * 
                                  EI_CAMERA_FRAME_BYTE_SIZE);
  if (!snapshot_buf) {
    Serial.println("Failed to allocate camera buffer!");
    while(true) delay(1000);
  }

  // Initialize MPU6050
  Wire.begin(I2C_SDA, I2C_SCL);
  if (!mpu.begin()) {
    Serial.println("MPU6050 not found - tamper detection disabled");
  } else {
    mpu.setAccelerometerRange(MPU6050_RANGE_8_G);
    mpu.setGyroRange(MPU6050_RANGE_500_DEG);
    mpu.setFilterBandwidth(MPU6050_BAND_21_HZ);
    Serial.println("MPU6050 initialized");
  }

  // System ready notification
  sendWhatsAppMessage(OWNER_PHONE, "🔐 AuraLock System ONLINE - Enhanced Security Mode Activated");
  
  Serial.println("AuraLock Enhanced Security System Ready");
  digitalWrite(STATUS_LED, HIGH);
  delay(1000);
  digitalWrite(STATUS_LED, LOW);
}

void loop() {
  checkSystemHealth();
  
  // Handle lockdown mode
  if (securityState.isLockdown) {
    if (millis() - securityState.lockdownStartTime > LOCKDOWN_DURATION) {
      securityState.isLockdown = false;
      securityState.failedAttempts = 0;
      sendWhatsAppMessage(OWNER_PHONE, "🔓 AuraLock: Lockdown period ended. System resumed.");
    } else {
      // Flash red LED during lockdown
      digitalWrite(STATUS_LED, HIGH);
      delay(100);
      digitalWrite(STATUS_LED, LOW);
      delay(900);
      return;
    }
  }

  // Tamper detection
  if (mpu.sensorID()) {
    sensors_event_t a, g, t;
    mpu.getEvent(&a, &g, &t);
    float total_g = sqrt(a.acceleration.x*a.acceleration.x + 
                        a.acceleration.y*a.acceleration.y + 
                        a.acceleration.z*a.acceleration.z) / 9.80665f;
    
    if (total_g > TAMPER_G_THRESHOLD) {
      securityState.consecutiveTamperAlerts++;
      String alertMsg = "⚠️ TAMPER ALERT: Physical interference detected!\n";
      alertMsg += "Force: " + String(total_g, 2) + "g\n";
      alertMsg += "Time: " + getCurrentDateTime() + "\n";
      alertMsg += "Alert #" + String(securityState.consecutiveTamperAlerts);
      
      triggerSecurityAlert("TAMPER_DETECTED");
      
      // Sound buzzer
      for(int i = 0; i < 3; i++) {
        digitalWrite(BUZZER_PIN, HIGH);
        delay(200);
        digitalWrite(BUZZER_PIN, LOW);
        delay(200);
      }
      
      delay(2000); // Prevent spam
    }
  }

  // Check for pending owner response timeout
  if (currentEvent.awaitingResponse && 
      (millis() - currentEvent.requestTime > PIN_TIMEOUT)) {
    currentEvent.awaitingResponse = false;
    securityState.failedAttempts++;
    
    String timeoutMsg = "⏰ ACCESS TIMEOUT: No response received\n";
    timeoutMsg += "Failed attempts: " + String(securityState.failedAttempts) + "/" + String(MAX_FAILED_ATTEMPTS);
    
    sendWhatsAppMessage(OWNER_PHONE, timeoutMsg);
    
    if (securityState.failedAttempts >= MAX_FAILED_ATTEMPTS) {
      securityState.isLockdown = true;
      securityState.lockdownStartTime = millis();
      triggerSecurityAlert("MULTIPLE_FAILURES");
    }
  }

  // Skip detection if awaiting owner response or in cooldown
  if (currentEvent.awaitingResponse || 
      (millis() - securityState.lastAccessRequest < ACCESS_REQUEST_COOLDOWN)) {
    delay(500);
    return;
  }

  // AI Detection Process
  if (!ei_camera_capture(EI_CLASSIFIER_INPUT_WIDTH, EI_CLASSIFIER_INPUT_HEIGHT, snapshot_buf)) {
    Serial.println("Camera capture failed");
    delay(100);
    return;
  }

  // Prepare Edge Impulse signal
  ei::signal_t signal;
  signal.total_length = EI_CLASSIFIER_INPUT_WIDTH * EI_CLASSIFIER_INPUT_HEIGHT;
  signal.get_data = &ei_camera_get_data;

  // Run classifier
  ei_impulse_result_t result = {0};
  EI_IMPULSE_ERROR err = run_classifier(&signal, &result, false);
  if (err != EI_IMPULSE_OK) {
    Serial.printf("Classifier error: %d\n", err);
    delay(100);
    return;
  }

  // Process detection results
#if EI_CLASSIFIER_OBJECT_DETECTION == 1
  bool authorizedDetected = false;
  bool intruderDetected = false;
  float highestConfidence = 0.0f;
  String detectedLabel = "";

  for (size_t i = 0; i < result.bounding_boxes_count; i++) {
    auto &bb = result.bounding_boxes[i];
    if (bb.value <= 0) continue;

    Serial.printf("Detection: %s (%.2f%%) at [%u,%u,%u,%u]\n", 
                  bb.label, bb.value*100, bb.x, bb.y, bb.width, bb.height);

    if (bb.value > highestConfidence) {
      highestConfidence = bb.value;
      detectedLabel = String(bb.label);
    }

    if (strcmp(bb.label, "Defence Staff") == 0 && bb.value >= CONFIDENCE_THRESHOLD) {
      authorizedDetected = true;
    }
    if (strcmp(bb.label, "Intruder") == 0 && bb.value >= CONFIDENCE_THRESHOLD) {
      intruderDetected = true;
    }
  }

  // Handle authorized person detection
  if (authorizedDetected) {
    securityState.lastAccessRequest = millis();
    
    // Generate random PIN and capture image
    currentEvent.currentPin = generateRandomPin().toInt();
    currentEvent.confidence = highestConfidence;
    currentEvent.personType = "Defence Staff";
    currentEvent.timestamp = getCurrentDateTime();
    currentEvent.awaitingResponse = true;
    currentEvent.requestTime = millis();
    
    // Capture and encode image
    String base64Image;
    captureAndSaveImage(base64Image);
    
    // Send detailed authorization request to owner
    String authRequest = "🔐 AUTHORIZATION REQUEST\n\n";
    authRequest += "👤 Person: " + currentEvent.personType + "\n";
    authRequest += "🎯 Confidence: " + String(currentEvent.confidence * 100, 1) + "%\n";
    authRequest += "📅 Time: " + currentEvent.timestamp + "\n";
    authRequest += "🔢 PIN: " + String(currentEvent.currentPin) + "\n\n";
    authRequest += "Reply with PIN to GRANT access\n";
    authRequest += "Reply 'DENY' to refuse access\n";
    authRequest += "⏱️ Expires in 60 seconds";
    
    sendWhatsAppMessage(OWNER_PHONE, authRequest);
    
    // Also send image via Telegram if configured
    if (strlen(TELEGRAM_BOT_TOKEN) > 0 && base64Image.length() > 0) {
      sendTelegramImage("AuraLock: Authorization request - " + currentEvent.timestamp, 
                       snapshot_buf, 
                       EI_CAMERA_RAW_FRAME_BUFFER_COLS * EI_CAMERA_RAW_FRAME_BUFFER_ROWS * 3);
    }
    
    Serial.println("Authorization request sent to owner");
  }

  // Handle intruder detection
  if (intruderDetected) {
    String intruderAlert = "🚨 SECURITY BREACH DETECTED!\n\n";
    intruderAlert += "👤 Threat: Unauthorized Person\n";
    intruderAlert += "🎯 Confidence: " + String(highestConfidence * 100, 1) + "%\n";
    intruderAlert += "📅 Time: " + getCurrentDateTime() + "\n";
    intruderAlert += "📍 Location: AuraLock System\n\n";
    intruderAlert += "⚠️ IMMEDIATE ATTENTION REQUIRED!";
    
    // Alert both owner and security personnel
    sendWhatsAppMessage(OWNER_PHONE, intruderAlert);
    sendWhatsAppMessage(SECURITY_PHONE, intruderAlert);
    
    // Trigger alarm sequence
    for (int i = 0; i < 10; i++) {
      digitalWrite(STATUS_LED, HIGH);
      digitalWrite(BUZZER_PIN, HIGH);
      delay(150);
      digitalWrite(STATUS_LED, LOW);
      digitalWrite(BUZZER_PIN, LOW);
      delay(150);
    }
    
    Serial.println("Intruder alert sent!");
    delay(5000); // Prevent spam
  }
#endif

  delay(100);
}

// Enhanced helper functions
String generateRandomPin() {
  return String(random(1000, 9999));
}

String getCurrentDateTime() {
  time_t now;
  time(&now);
  struct tm *timeinfo = localtime(&now);
  char buffer[64];
  strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
  return String(buffer);
}

void sendWhatsAppMessage(const String& phone, const String& message) {
  if (WiFi.status() != WL_CONNECTED) return;
  
  HTTPClient http;
  http.setTimeout(10000);
  
  String url = "https://api.callmebot.com/whatsapp.php?phone=" + phone +
               "&text=" + urlEncode(message) + "&apikey=" + String(WHATSAPP_APIKEY);
  
  http.begin(url);
  int httpCode = http.GET();
  
  Serial.printf("WhatsApp to %s: HTTP %d\n", phone.c_str(), httpCode);
  http.end();
}

void triggerSecurityAlert(const String& alertType) {
  String criticalAlert = "🔴 CRITICAL SECURITY ALERT\n\n";
  criticalAlert += "Alert Type: " + alertType + "\n";
  criticalAlert += "System: AuraLock Enhanced Security\n";
  criticalAlert += "Time: " + getCurrentDateTime() + "\n";
  criticalAlert += "Status: REQUIRES IMMEDIATE ATTENTION\n\n";
  
  if (alertType == "TAMPER_DETECTED") {
    criticalAlert += "Physical interference with lock detected!";
  } else if (alertType == "MULTIPLE_FAILURES") {
    criticalAlert += "System entering lockdown mode due to multiple failures.";
  } else if (alertType == "SYSTEM_FAILURE") {
    criticalAlert += "Hardware malfunction detected!";
  }
  
  // Send to both owner and security
  sendWhatsAppMessage(OWNER_PHONE, criticalAlert);
  sendWhatsAppMessage(SECURITY_PHONE, criticalAlert);
}

bool captureAndSaveImage(String& base64Image) {
  camera_fb_t *fb = esp_camera_fb_get();
  if (!fb) return false;
  
  // Convert to base64 for transmission (simplified)
  // In production, implement proper base64 encoding
  base64Image = "IMAGE_DATA_PLACEHOLDER";
  
  esp_camera_fb_return(fb);
  return true;
}

void checkSystemHealth() {
  // Monitor system resources and connectivity
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi disconnected - attempting reconnection");
    WiFi.reconnect();
  }
  
  // Reset tamper alert counter periodically
  static unsigned long lastReset = 0;
  if (millis() - lastReset > 300000) { // 5 minutes
    securityState.consecutiveTamperAlerts = 0;
    lastReset = millis();
  }
}

// Handle owner response via serial input (in production, use web server or SMS)
void handleOwnerResponse(const String& response) {
  if (!currentEvent.awaitingResponse) return;
  
  if (response == String(currentEvent.currentPin)) {
    // Grant access
    currentEvent.awaitingResponse = false;
    securityState.failedAttempts = 0;
    
    digitalWrite(RELAY_PIN, HIGH);
    digitalWrite(STATUS_LED, HIGH);
    
    String accessLog = "✅ ACCESS GRANTED\n";
    accessLog += "Person: " + currentEvent.personType + "\n";
    accessLog += "Time: " + getCurrentDateTime() + "\n";
    accessLog += "Method: Owner Authorization";
    
    sendWhatsAppMessage(OWNER_PHONE, accessLog);
    
    delay(3000); // Keep lock open for 3 seconds
    digitalWrite(RELAY_PIN, LOW);
    digitalWrite(STATUS_LED, LOW);
    
  } else if (response == "DENY") {
    // Access denied
    currentEvent.awaitingResponse = false;
    
    String denyLog = "❌ ACCESS DENIED\n";
    denyLog += "Person: " + currentEvent.personType + "\n";
    denyLog += "Time: " + getCurrentDateTime() + "\n";
    denyLog += "Reason: Owner Refused Authorization";
    
    sendWhatsAppMessage(OWNER_PHONE, denyLog);
    
    // Alert sequence
    for (int i = 0; i < 3; i++) {
      digitalWrite(STATUS_LED, HIGH);
      delay(200);
      digitalWrite(STATUS_LED, LOW);
      delay(200);
    }
  }
}

// Camera implementation (simplified - use existing functions from original code)
bool ei_camera_init() {
  // Use your existing camera initialization code
  return true;
}

bool ei_camera_capture(uint32_t img_w, uint32_t img_h, uint8_t *out_buf) {
  // Use your existing camera capture code
  return true;
}

int ei_camera_get_data(size_t offset, size_t length, float *out_ptr) {
  // Use your existing data conversion code
  return 0;
}

// #include <WiFi.h>
// #include <HTTPClient.h>
// #include <UrlEncode.h>

// #include <Wire.h>
// #include <Adafruit_MPU6050.h>
// #include <Adafruit_Sensor.h>

// #include "esp_camera.h"

// // 1) Edge Impulse include - change to your generated header name
// #include <auralock_inferencing.h>   // rename if your library uses a different name [23]

// // 2) Select camera model
// //#define CAMERA_MODEL_ESP_EYE
// #define CAMERA_MODEL_AI_THINKER      // AI Thinker ESP32-CAM [4]

// // AI Thinker pins [4]
// #if defined(CAMERA_MODEL_AI_THINKER)
//   #define PWDN_GPIO_NUM     32
//   #define RESET_GPIO_NUM    -1
//   #define XCLK_GPIO_NUM      0
//   #define SIOD_GPIO_NUM     26
//   #define SIOC_GPIO_NUM     27
//   #define Y9_GPIO_NUM       35
//   #define Y8_GPIO_NUM       34
//   #define Y7_GPIO_NUM       39
//   #define Y6_GPIO_NUM       36
//   #define Y5_GPIO_NUM       21
//   #define Y4_GPIO_NUM       19
//   #define Y3_GPIO_NUM       18
//   #define Y2_GPIO_NUM        5
//   #define VSYNC_GPIO_NUM    25
//   #define HREF_GPIO_NUM     23
//   #define PCLK_GPIO_NUM     22
// #elif defined(CAMERA_MODEL_ESP_EYE)
//   #define PWDN_GPIO_NUM    -1
//   #define RESET_GPIO_NUM   -1
//   #define XCLK_GPIO_NUM     4
//   #define SIOD_GPIO_NUM    18
//   #define SIOC_GPIO_NUM    23
//   #define Y9_GPIO_NUM      36
//   #define Y8_GPIO_NUM      37
//   #define Y7_GPIO_NUM      38
//   #define Y6_GPIO_NUM      39
//   #define Y5_GPIO_NUM      35
//   #define Y4_GPIO_NUM      14
//   #define Y3_GPIO_NUM      13
//   #define Y2_GPIO_NUM      34
//   #define VSYNC_GPIO_NUM    5
//   #define HREF_GPIO_NUM    27
//   #define PCLK_GPIO_NUM    25
// #else
//   #error "Select a supported camera model"
// #endif

// // 3) Wi-Fi + WhatsApp (CallMeBot)
// const char* WIFI_SSID = "YOUR_SSID";
// const char* WIFI_PASS = "YOUR_PASS";
// const char* WHATSAPP_PHONE = "91XXXXXXXXXX";
// const char* WHATSAPP_APIKEY = "YOUR_API_KEY";    // obtain from CallMeBot [11][25]

// // 4) GPIOs
// const int RELAY_PIN = 14;            // change to your wired relay GPIO
// const int STATUS_LED = 33;           // optional onboard LED if available

// // 5) MPU6050 (I2C)
// Adafruit_MPU6050 mpu;
// const int I2C_SDA = 21;
// const int I2C_SCL = 22;
// const float TAMPER_G_THRESHOLD = 2.0f;  // 2 g threshold [15]

// // 6) Camera buffer settings (keep EI input small; model uses EI_CLASSIFIER_INPUT_WIDTH/HEIGHT)
// #define EI_CAMERA_RAW_FRAME_BUFFER_COLS  320
// #define EI_CAMERA_RAW_FRAME_BUFFER_ROWS  240
// #define EI_CAMERA_FRAME_BYTE_SIZE        3

// static bool is_initialised = false;
// static uint8_t* snapshot_buf = nullptr;

// // Forward decl.
// bool ei_camera_init();
// bool ei_camera_capture(uint32_t img_w, uint32_t img_h, uint8_t *out_buf);
// int  ei_camera_get_data(size_t offset, size_t length, float *out_ptr);
// void sendWhatsApp(const String& msg);

// void setup() {
//   Serial.begin(115200);
//   delay(100);

//   pinMode(RELAY_PIN, OUTPUT);
//   digitalWrite(RELAY_PIN, LOW);
//   pinMode(STATUS_LED, OUTPUT);
//   digitalWrite(STATUS_LED, LOW);

//   // Wi-Fi
//   Serial.print("Connecting Wi-Fi");
//   WiFi.begin(WIFI_SSID, WIFI_PASS);
//   while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
//   Serial.println("\nWi-Fi connected: " + WiFi.localIP().toString()); // [11]

//   // Camera
//   if (!ei_camera_init()) {
//     Serial.println("Camera init failed, halting.");
//     while(true) delay(1000);
//   }
//   Serial.println("Camera initialized."); // [4]

//   // MPU6050
//   Wire.begin(I2C_SDA, I2C_SCL);
//   if (!mpu.begin()) {
//     Serial.println("MPU6050 not found; tamper disabled.");  // continue without tamper if absent
//   } else {
//     mpu.setAccelerometerRange(MPU6050_RANGE_8_G);
//     mpu.setGyroRange(MPU6050_RANGE_500_DEG);
//     mpu.setFilterBandwidth(MPU6050_BAND_21_HZ);              // [9]
//     Serial.println("MPU6050 ready.");
//   }

//   Serial.println("Starting inference loop...");
// }

// void loop() {
//   // Tamper check (non-blocking)
//   if (mpu.sensorID()) {
//     sensors_event_t a, g, t;
//     mpu.getEvent(&a, &g, &t);
//     float ax = a.acceleration.x, ay = a.acceleration.y, az = a.acceleration.z;
//     float total = sqrtf(ax*ax + ay*ay + az*az);
//     if (total > (TAMPER_G_THRESHOLD * 9.80665f)) {
//       Serial.printf("Tamper detected: %.2f m/s^2\n", total);
//       sendWhatsApp("AuraLock: Tamper detected!");
//       // Visual cue
//       for (int i=0;i<5;i++){ digitalWrite(STATUS_LED, HIGH); delay(150); digitalWrite(STATUS_LED, LOW); delay(150); }
//     }
//   }

//   // Allocate camera buffer for one frame
//   if (!snapshot_buf) {
//     snapshot_buf = (uint8_t*)malloc(EI_CAMERA_RAW_FRAME_BUFFER_COLS * EI_CAMERA_RAW_FRAME_BUFFER_ROWS * EI_CAMERA_FRAME_BYTE_SIZE);
//     if (!snapshot_buf) { Serial.println("Snapshot alloc failed"); delay(500); return; }
//   }

//   // Prepare EI signal
//   ei::signal_t signal;
//   signal.total_length = EI_CLASSIFIER_INPUT_WIDTH * EI_CLASSIFIER_INPUT_HEIGHT;
//   signal.get_data = &ei_camera_get_data;

//   // Capture and resize to model dims
//   if (!ei_camera_capture(EI_CLASSIFIER_INPUT_WIDTH, EI_CLASSIFIER_INPUT_HEIGHT, snapshot_buf)) {
//     Serial.println("Capture failed"); delay(100); return;
//   }

//   // Run classifier
//   ei_impulse_result_t result = {0};
//   EI_IMPULSE_ERROR err = run_classifier(&signal, &result, false);
//   if (err != EI_IMPULSE_OK) {
//     Serial.printf("Classifier error %d\n", err);
//     delay(100);
//     return;
//   }

//   // Parse detections
// #if EI_CLASSIFIER_OBJECT_DETECTION == 1
//   bool defence_ok = false;
//   bool intruder_flag = false;
//   const float THRESH = 0.70f;  // tune after field tests

//   Serial.printf("Timing: DSP %d ms, Classification %d ms\n", result.timing.dsp, result.timing.classification);
//   for (size_t i = 0; i < result.bounding_boxes_count; i++) {
//     auto &bb = result.bounding_boxes[i];
//     if (bb.value <= 0) continue;
//     Serial.printf("BB: %s %.2f x:%u y:%u w:%u h:%u\n", bb.label, bb.value, bb.x, bb.y, bb.width, bb.height);

//     if (strcmp(bb.label, "Defence Staff") == 0 && bb.value >= THRESH) defence_ok = true;
//     if (strcmp(bb.label, "Intruder") == 0 && bb.value >= THRESH) intruder_flag = true;
//   }

//   if (defence_ok) {
//     Serial.println("Authorized detected -> Unlock");
//     digitalWrite(RELAY_PIN, HIGH);
//     digitalWrite(STATUS_LED, HIGH);
//     delay(3000);
//     digitalWrite(RELAY_PIN, LOW);
//     digitalWrite(STATUS_LED, LOW);
//     sendWhatsApp("AuraLock: Access granted (authorized)."); // optional [11]
//   }

//   if (intruder_flag) {
//     Serial.println("Intruder detected -> Alert");
//     sendWhatsApp("AuraLock: Intruder detected!");
//     for (int i=0;i<6;i++){ digitalWrite(STATUS_LED, HIGH); delay(100); digitalWrite(STATUS_LED, LOW); delay(100); }
//   }
// #else
//   // If classification model (not OD), print scores
//   for (size_t i = 0; i < EI_CLASSIFIER_LABEL_COUNT; i++) {
//     Serial.printf("%s: %.3f\n", ei_classifier_inferencing_categories[i], result.classification[i].value);
//   }
// #endif

//   delay(50);
// }

// // ================== Camera helpers ==================
// bool ei_camera_init() {
//   if (is_initialised) return true;

//   camera_config_t config;
//   config.pin_pwdn = PWDN_GPIO_NUM;
//   config.pin_reset = RESET_GPIO_NUM;
//   config.pin_xclk = XCLK_GPIO_NUM;
//   config.pin_sscb_sda = SIOD_GPIO_NUM;
//   config.pin_sscb_scl = SIOC_GPIO_NUM;
//   config.pin_d7 = Y9_GPIO_NUM;
//   config.pin_d6 = Y8_GPIO_NUM;
//   config.pin_d5 = Y7_GPIO_NUM;
//   config.pin_d4 = Y6_GPIO_NUM;
//   config.pin_d3 = Y5_GPIO_NUM;
//   config.pin_d2 = Y4_GPIO_NUM;
//   config.pin_d1 = Y3_GPIO_NUM;
//   config.pin_d0 = Y2_GPIO_NUM;
//   config.pin_vsync = VSYNC_GPIO_NUM;
//   config.pin_href = HREF_GPIO_NUM;
//   config.pin_pclk = PCLK_GPIO_NUM;
//   config.xclk_freq_hz = 20000000;
//   config.ledc_timer = LEDC_TIMER_0;
//   config.ledc_channel = LEDC_CHANNEL_0;

//   // JPEG + convert to RGB888; alternative is PIXFORMAT_RGB565
//   config.pixel_format = PIXFORMAT_JPEG;
//   config.frame_size = FRAMESIZE_QVGA;    // QVGA for performance [4]
//   config.jpeg_quality = 12;
//   config.fb_count = 1;
//   config.fb_location = CAMERA_FB_IN_PSRAM;
//   config.grab_mode = CAMERA_GRAB_WHEN_EMPTY;

//   esp_err_t err = esp_camera_init(&config);
//   if (err != ESP_OK) return false;

//   is_initialised = true;
//   return true;
// }

// bool ei_camera_capture(uint32_t img_w, uint32_t img_h, uint8_t *out_buf) {
//   if (!is_initialised) return false;

//   camera_fb_t *fb = esp_camera_fb_get();
//   if (!fb) return false;

//   bool ok = fmt2rgb888(fb->buf, fb->len, PIXFORMAT_JPEG, out_buf);  // convert to RGB888
//   esp_camera_fb_return(fb);
//   if (!ok) return false;

//   // Resize/crop to EI input dims using simple nearest-neighbor
//   // Edge Impulse provides image processing helpers; use basic center-crop here for brevity.
//   // For production, you can use Edge Impulse SDK image.hpp functions. [23]
//   // Assuming EI input <= 320x240; if different, integrate ei::image::processing as in EI example.

//   return true;
// }

// static int ei_camera_get_data(size_t offset, size_t length, float *out_ptr) {
//   // Convert RGB888 bytes to packed int for EI signal: R<<16 | G<<8 | B
//   size_t px = offset * 3;
//   for (size_t i = 0; i < length; i++) {
//     out_ptr[i] = (snapshot_buf[px + 0] << 16) | (snapshot_buf[px + 1] << 8) | (snapshot_buf[px + 2]);
//     px += 3;
//   }
//   return 0;
// }

// // ================== WhatsApp alert ==================
// void sendWhatsApp(const String& message) {
//   if (WiFi.status() != WL_CONNECTED) return;
//   HTTPClient http;
//   String url = "https://api.callmebot.com/whatsapp.php?phone=" + String(WHATSAPP_PHONE) +
//                "&text=" + urlEncode(message) + "&apikey=" + String(WHATSAPP_APIKEY);
//   http.begin(url);
//   int code = http.GET();
//   Serial.printf("WhatsApp HTTP %d\n", code);
//   http.end();
// }
