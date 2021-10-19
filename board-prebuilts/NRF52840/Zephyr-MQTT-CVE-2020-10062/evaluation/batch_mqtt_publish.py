import os
import time

test_message = "hello"

# for i in range(32755):
#     test_message = test_message + "a"

for i in range(1000):
    os.system("mosquitto_pub -t test_topic -m {} -p 1883".format(test_message))
    time.sleep(0.7)