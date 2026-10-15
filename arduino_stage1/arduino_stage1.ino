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



  // Pump control

  if(distance < 0)
  {
    digitalWrite(RELAY, HIGH);  // Pump OFF on no echo
  }


  else if(distance >= EMPTY_DISTANCE)
  {
    digitalWrite(RELAY, LOW);   // Pump ON
  }


  else if(distance <= FULL_DISTANCE)
  {
    digitalWrite(RELAY, HIGH);  // Pump OFF
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
    lcd.print("Level:");
    lcd.print(distance);
    lcd.print("cm");



    lcd.setCursor(0,1);
    lcd.print("Flow:");
    lcd.print(flowRate,1);
    lcd.print("L/m");



    lastUpdate = millis();

  }

}
