#include <WiFi.h>
#include "PubSubClient.h"

const char* ssid = "Wokwi-GUEST";
const char* password = "";
const char* mqttServer = "broker.emqx.io";
int port = 1883;
String stMac;
char mac[50];
char clientId[50];

WiFiClient espClient;
PubSubClient client(espClient);

unsigned long lastMsg = 0;
#define MSG_BUFFER_SIZE  (50)
char msg[MSG_BUFFER_SIZE];
int value = 0;

const int pinRed = 26;
const int pinYellow = 27;
const int pinBlue = 14;
const int pinPurple = 12;
const int pinGreen = 13;

void setup() {
  Serial.begin(115200);
  randomSeed(analogRead(0));

  delay(10);
  Serial.println();
  Serial.print("Connecting to ");
  Serial.println(ssid);

  wifiConnect();

  Serial.println("");
  Serial.println("WiFi connected");
  Serial.println("IP address: ");
  Serial.println(WiFi.localIP());
  Serial.println(WiFi.macAddress());
  stMac = WiFi.macAddress();
  stMac.replace(":", "_");
  Serial.println(stMac);
  
  client.setServer(mqttServer, port);
  client.setCallback(callback);
  pinMode(pinRed, OUTPUT);
  pinMode(pinYellow, OUTPUT);
  pinMode(pinBlue, OUTPUT);
  pinMode(pinPurple, OUTPUT);
  pinMode(pinGreen, OUTPUT);
}

void wifiConnect() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
}

void mqttReconnect() {
  while (!client.connected()) {
    Serial.print("Attempting MQTT connection...");
    long r = random(1000);
    sprintf(clientId, "clientId-%ld", r);
    if (client.connect(clientId)) {
      Serial.print(clientId);
      Serial.println(" connected");
      client.subscribe("AiriPy/openCVmqtt");
    } else {
      Serial.print("failed, rc=");
      Serial.print(client.state());
      Serial.println(" try again in 5 seconds");
      delay(5000);
    }
  }
}

void callback(char* topic, byte* message, unsigned int length) {
  
    if((char)message[0] == '1'){
      digitalWrite(pinRed, HIGH);
    }
    else{
      digitalWrite(pinRed, LOW);
    }
    if((char)message[1] == '1'){
      digitalWrite(pinYellow, HIGH);
    }
    else{
      digitalWrite(pinYellow, LOW);
    }
    if((char)message[2] == '1'){
      digitalWrite(pinBlue, HIGH);
    }
    else{
      digitalWrite(pinBlue, LOW);
    }
    if((char)message[3] == '1'){
      digitalWrite(pinPurple, HIGH);
    }
    else{
      digitalWrite(pinPurple, LOW);
    }
    if((char)message[4] == '1'){
      digitalWrite(pinGreen, HIGH);
    }
    else{
      digitalWrite(pinGreen, LOW);
    }
}

void loop() {
  delay(10);
  if (!client.connected()) {
    mqttReconnect();
  }
  client.loop();
}
