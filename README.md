# Honey Pot
Currently a pretty basic honeypot that will set up a listening port on 8080. It tries to install a Swift on Security sysmon config file and sets up a fake ssh server that will log any input and shut down the service.

## Installing
You can create an exe  by running in dotnet CLI: 
```
dotnet publish -o publish -c Release -r win-x86 -p:PublishSingleFile=True
```
Here's an explanation of what the parameters do
* -o specifices where to output, in this case a publish folder
* -c specifices the target runtime enviroment. Can be win-x64, but doesn't work with linux since linux doesn't support the Windows Event Log API
* -p specifices what properties we want to change. In this case, we want dotnet to make all of this code into one exe file

To actually install the exe as a service, we can use sc.exe in the cmd
```
sc.exe create [Whatever name you want for the service] binpath="[path to exe]"
```
Then, we can use the Services application to run the service.

