To get started on installing this:

1. Open Command Prompt or PowerShell on Windows, and run these two commands:
//
winget install Microsoft.DotNet.SDK.8 //
winget install Git.Git
//
3. Follow the on-screen prompts until finished with the installation.
4. Close your current Command Prompt window and any open VS Code windows completely, then open a fresh Command Prompt window.
5. To ensure installation, open a new Command Prompt window, run:
//
dotnet --list-sdks //
git --version
//
6. You should see .NET SDK 8.x.xxx listed along with the installed Git version.
7. To generate license key on first-time use, run:
//
dotnet build 
//
8. To start the program, run:
//
dotnet run 
//
9. To create exe file for user, use git command in project directory (or copy and paste from existing):
//
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
//
File will be found in bin\Release\net8.0\win-x64\publish\
//
10. Use "./ShazrinSonar.exe --provision ShafiqNazrinSonar2026" in command prompt for license key
