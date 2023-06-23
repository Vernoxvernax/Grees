## **GreeS**

### **s** for shit

___

For some reason it has become necessary to write all controls for your smart home devices by yourself. The Gree+ AC lineup is part of that trash and apparently just doesn't stop cooling, even if the current room temperature is 2° below the target temp.

*At least you can control it via Wi-Fi.*

Just connect it to your home Wi-Fi and find its local IP-Address.

Then control it like this:

```
grees --ipaddress <IP-Address> maintain --temperature 23 --cooling
```
Yes `temperature` is in celsius.

Since this is just first commit code and untested, things are bound to change.

Currently, the AC will only turn on if the room temperature derives for at least 2° from the target temperature. The `--cooling` and `--heating` flag will also make it possible to avoid wasting power on heating in the summer.

___

## **Acknowledgements**

[tomikaa87/gree-remote](https://github.com/tomikaa87/gree-remote)
