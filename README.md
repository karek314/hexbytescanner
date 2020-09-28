# hexbytescanner

Static byte pattern scanner with binary patcher for MacOS.
Unlike most byte pattern scanners, it's static one. It allows to search binaries by byte patterns with optional wildcard like
```F9 1F ?? 82 12``` where ```??``` is wildcard byte. It can also patch specified address with new bytes.

Additionally, pattern searching and patching can be combined and done automatically by adding json object, called tasks or hooks, each one can be either patching or regular search task. There is also possibility to define distance between pattern and patch location. It allows fairly automatic binary patching.  

Repository [hexbytescanner-hooks](https://github.com/karek314/hexbytescanner-hooks) with some useful/example hooks published by contributors.

## Build

```
git clone https://github.com/karek314/hexbytescanner
cd hexbytescanner && bash build.sh
```

## Usage
<b>Command line scanning</b><br>
scan BinaryName Pattern
```
./hexbytescanner scan MyApp E103??AA????E0
```
![scan](/screenshots/scan.png?raw=true)

<b>Command line patching</b><br>
patch BinaryName Address NewBytes DistanceFromAddress
```
./hexbytescanner patch MyApp 0x184dfc 1F2003D5 0x1
```
![patch](/screenshots/patch.png?raw=true)

<b>Json file based automated task/hooks queues</b><br>
JsonFile BinaryName
```
./hexbytescanner test.json TestApp
```
![json](/screenshots/json.png?raw=true)

Where json file contains array of objects like
```
{
   "pattern": "F91F8212????00321C3A8252??00009018932491744A40B90700????7A4A00B921008252E2030032E00313AAA0023FD6744A00B9",
   "patchBytes": "1F2003D5",
   "patchDistance": "0x1"
 }
 ```
This example looks for address with pattern and will patch (found address + patchDistance) with patchBytes. In this case, it's replacing instruction <b>bl</b> with <b>nop</b> on Aarch64.

However, if patchBytes is empty. It work only in scan mode and results will be shown in console output.
```
{
   "pattern": "8252????8A1A2AC103B97F6200B9",
   "patchBytes": "",
   "patchDistance": "0x1"
}
```

## Notes
Patterns and patch bytes can be either submitted without spacing as "F91F8212????00" or "F9 1F 82 12 ?? ?? 00"

## License
MIT
