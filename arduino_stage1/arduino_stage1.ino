#include <Wire.h>
#include <LiquidCrystal_I2C.h>


LiquidCrystal_I2C lcd(0x27, 16, 2);


// Pins
#define TRIG 5
#define ECHO 6
#define RELAY 7
#define FLOW_SENSOR 2


// Tank limits
#define EMPTY_DISTANCE 8
#define FULL_DISTANCE 2



long duration;
int distance;



volatile unsigned long pulseCount = 0;

float flowRate;

unsigned long lastUpdate = 0;
int lastValidDistance = -1;
unsigned long lastValidDistanceAt = 0;
bool pump1Override = false;
int pump1Requested = 0;
unsigned long pump1OverrideAt = 0;
char serialCommand[32];
byte serialCommandLength = 0;


void handleSerialCommand()
{
  unsigned int sequence;
  unsigned int value;
  char extra;
  if(sscanf(serialCommand, "P1 %u %u %c", &sequence, &value, &extra) != 2 || value > 1)
  {
    Serial.println("ERR P1 0 FORMAT");
    return;
  }
  if(value == 1 && (distance < 0 || distance <= FULL_DISTANCE))
  {
    Serial.print("ERR P1 ");
    Serial.print(sequence);
    Serial.println(" SENSOR_OR_FULL");
    return;
  }
  pump1Requested = value;
  pump1Override = true;
  pump1OverrideAt = millis();
  digitalWrite(RELAY, value == 1 ? LOW : HIGH);
  Serial.print("ACK P1 ");
  Serial.print(sequence);
  Serial.print(" ");
  Serial.println(value);
}


void readSerialCommands()
{
  while(Serial.available() > 0)
  {
    char incoming = Serial.read();
    if(incoming == '\r') continue;
    if(incoming == '\n')
    {
      serialCommand[serialCommandLength] = '\0';
      if(serialCommandLength > 0) handleSerialCommand();
      serialCommandLength = 0;
    }
    else if(serialCommandLength < sizeof(serialCommand) - 1)
    {
      serialCommand[serialCommandLength++] = incoming;
    }
    else
    {
      serialCommandLength = 0;
    }
  }
}



void flowCounter()
{
  pulseCount++;
}




int getDistance()
{
  digitalWrite(TRIG, LOW);
  delayMicroseconds(2);


  digitalWrite(TRIG, HIGH);
  delayMicroseconds(10);


  digitalWrite(TRIG, LOW);



  duration = pulseIn(ECHO, HIGH, 30000);



  if(duration == 0)
  {
    return -1;   // No echo
  }


  return duration * 0.034 / 2;
}




void setup()
{
  Serial.begin(9600);



  pinMode(TRIG, OUTPUT);
  pinMode(ECHO, INPUT);



  pinMode(RELAY, OUTPUT);


  // Relay OFF initially (Active LOW relay)
  digitalWrite(RELAY, HIGH);



  pinMode(FLOW_SENSOR, INPUT_PULLUP);


  attachInterrupt(
    digitalPinToInterrupt(FLOW_SENSOR),
    flowCounter,
    FALLING
  );



  lcd.init();
  lcd.backlight();



  lcd.setCursor(0,0);
  lcd.print("Water System");


  lcd.setCursor(0,1);
  lcd.print("Starting...");


  delay(2000);

}





void loop()
{

  distance = getDistance();
  if(distance >= 0)
  {
    lastValidDistance = distance;
    lastValidDistanceAt = millis();
  }
  readSerialCommands();



  // Pump control

  if(pump1Override && millis() - pump1OverrideAt >= 30000UL)
  {
    pump1Override = false;  // A lost gateway cannot hold a relay indefinitely.
  }

  if(distance < 0 || distance <= FULL_DISTANCE)
  {
    digitalWrite(RELAY, HIGH);  // No echo or full box: pump OFF.
  }
  else if(pump1Override)
  {
    digitalWrite(RELAY, pump1Requested == 1 ? LOW : HIGH);
  }
  else if(distance >= EMPTY_DISTANCE)
  {
    digitalWrite(RELAY, LOW);   // Pump ON
  }




  if(millis() - lastUpdate >= 1000)
  {


    noInterrupts();

    unsigned long pulses = pulseCount;

    pulseCount = 0;

    interrupts();



    // Flow sensor calculation
    flowRate = pulses / 7.5;



    Serial.print("Distance: ");
    Serial.print(distance);
    Serial.println(" cm");


    Serial.print("Flow: ");
    Serial.print(flowRate);
    Serial.println(" L/min");




    lcd.clear();

    lcd.setCursor(0,0);
    lcd.print("Distance:");
    if(distance >= 0)
    {
      lcd.print(distance);
      lcd.print(" cm");
    }
    else if(lastValidDistance >= 0 && millis() - lastValidDistanceAt <= 3000UL)
    {
      lcd.print(lastValidDistance);
      lcd.print(" cm*");  // * marks a held reading, not a new measurement
    }
    else
    {
      lcd.print("NO ECHO");
    }

    lcd.setCursor(0,1);
    lcd.print("Flow:");
    lcd.print(flowRate,1);
    lcd.print(" L/m");



    lastUpdate = millis();

  }

  delay(70);  // Leave the ultrasonic echo time before the next trigger.

}
