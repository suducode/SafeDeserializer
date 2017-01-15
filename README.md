# SafeDeserializer

Safely deserialize java objects when using the native java serialization to avoid the known vulnerability. 

# What is the vulnarability in Java deserialization ?

a. The problem lies in the fact that many apps that accept serialized objects do not validate or check untrusted input before deserializing it. This gives attackers an opening to insert a malicious object into a data stream and have it execute on the app server. 

b. Also if the desrialization process doesn't excercise strict limits on the size of the object being deserialized , attacker may be able to inject a really large object into the stream causing buffer overflow leading to [vulnerability](https://www.owasp.org/index.php/Buffer_Overflow).


