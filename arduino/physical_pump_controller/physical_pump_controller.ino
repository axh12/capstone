#include <Wire.h>
#include <LiquidCrystal_I2C.h>

LiquidCrystal_I2C lcd(0x27, 16, 2);

const uint8_t TRIG = 5;
const uint8_t ECHO = 6;
const uint8_t RELAY = 7;       // Active LOW relay module
const uint8_t FLOW_SENSOR = 2;
const int EMPTY_DISTANCE = 8;
const int FULL_DISTANCE = 2;

volatile unsigned long pulseCount = 0;
unsigned long lastUpdate = 0;
unsigned long lastValidDistanceAt = 0;
int lastValidDistance = -1;
int distance = -1;
float flowRate = 0.0;
bool remoteControl = false;

void flowCounter() { pulseCount++; }

int getDistance() {
  digitalWrite(TRIG, LOW);
  delayMicroseconds(2);
  digitalWrite(TRIG, HIGH);
  delayMicroseconds(10);
  digitalWrite(TRIG, LOW);
  unsigned long duration = pulseIn(ECHO, HIGH, 30000);
  if (duration == 0) return -1;
  return (int)(duration * 0.034 / 2);
}

void setPump(bool on) { digitalWrite(RELAY, on ? LOW : HIGH); }

void printStatus() {
  Serial.print("Distance: "); Serial.print(distance); Serial.println(" cm");
  Serial.print("Flow: "); Serial.print(flowRate, 1); Serial.println(" L/min");
  Serial.print("Pump: ");
  Serial.println(digitalRead(RELAY) == LOW ? "ON" : "OFF");
}

void handleSerial() {
  if (!Serial.available()) return;
  String command = Serial.readStringUntil('\n');
  command.trim();
  command.toUpperCase();

  if (command == "STATUS") {
    printStatus();
  } else if (command == "REMOTE ENABLE") {
    remoteControl = true;
    Serial.println("ACK: REMOTE ENABLED");
  } else if (command == "REMOTE DISABLE") {
    remoteControl = false;
    setPump(false);
    Serial.println("ACK: REMOTE DISABLED; PUMP OFF");
  } else if (command == "PUMP ON") {
    if (!remoteControl) {
      Serial.println("ERROR: REMOTE CONTROL DISABLED");
    } else if (distance < 0 || distance <= FULL_DISTANCE) {
      setPump(false);
      Serial.println(distance < 0 ? "ERROR: NO LEVEL SENSOR; PUMP OFF"
                                  : "ERROR: TANK FULL; PUMP OFF");
    } else {
      setPump(true);
      Serial.println("ACK: PUMP ON");
    }
  } else if (command == "PUMP OFF") {
    setPump(false);
    Serial.println("ACK: PUMP OFF");
  } else {
    Serial.println("ERROR: UNKNOWN COMMAND");
  }
}

void setup() {
  Serial.begin(9600);
  pinMode(TRIG, OUTPUT);
  pinMode(ECHO, INPUT);
  pinMode(RELAY, OUTPUT);
  setPump(false);
  pinMode(FLOW_SENSOR, INPUT_PULLUP);
  attachInterrupt(digitalPinToInterrupt(FLOW_SENSOR), flowCounter, FALLING);
  lcd.init();
  lcd.backlight();
  lcd.setCursor(0, 0); lcd.print("Water System");
  lcd.setCursor(0, 1); lcd.print("Starting...");
  delay(2000);
}

void loop() {
  handleSerial();
  distance = getDistance();

  if (distance >= 0) {
    lastValidDistance = distance;
    lastValidDistanceAt = millis();
  }

  if (!remoteControl) {
    if (distance < 0) setPump(false);             // fail safe
    else if (distance >= EMPTY_DISTANCE) setPump(true);
    else if (distance <= FULL_DISTANCE) setPump(false);
  } else if (distance < 0 || distance <= FULL_DISTANCE) {
    setPump(false);                              // fail safe/full-tank stop
  }

  if (millis() - lastUpdate >= 1000) {
    noInterrupts();
    unsigned long pulses = pulseCount;
    pulseCount = 0;
    interrupts();
    flowRate = pulses / 7.5;
    printStatus();
    lcd.clear();
    lcd.setCursor(0, 0); lcd.print("Distance:");
    if (distance >= 0) { lcd.print(distance); lcd.print(" cm"); }
    else if (lastValidDistance >= 0 && millis() - lastValidDistanceAt <= 3000UL) {
      lcd.print(lastValidDistance); lcd.print(" cm*");
    } else lcd.print("NO ECHO");
    lcd.setCursor(0, 1); lcd.print("Flow:"); lcd.print(flowRate, 1); lcd.print("L/m");
    lastUpdate = millis();
  }
}
