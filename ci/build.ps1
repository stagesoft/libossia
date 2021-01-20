Set-PSDebug -Trace 1

function CheckLastExitCode {
    param ([int[]]$SuccessCodes = @(0), [scriptblock]$CleanupScript=$null)

    Push-AppveyorArtifact "$LogFile"
    Push-AppveyorArtifact "C:/projects/libossia/build/CMakeFiles/CMakeOutput.log"
    Push-AppveyorArtifact "C:/projects/libossia/build/CMakeFiles/CMakeError.log"

    if ($SuccessCodes -notcontains $LastExitCode) {
        if ($CleanupScript) {
            "Executing cleanup script: $CleanupScript"
            &$CleanupScript
        }
        $msg = @"
EXE RETURNED EXIT CODE $LastExitCode
CALLSTACK:$(Get-PSCallStack | Out-String)
"@
        throw $msg
    }
}

cd C:\projects\libossia\build\
$LogFile = "C:\projects\libossia\build-${env:APPVEYOR_BUILD_TYPE}-${env:platform}.log"
cmake --build . --config "${env:configuration}" > "$LogFile"
CheckLastExitCode

if ( $env:APPVEYOR_BUILD_TYPE -eq "max" -Or $env:APPVEYOR_BUILD_TYPE -eq "Release" -Or $env:APPVEYOR_BUILD_TYPE -eq "ossia-cpp"){
  cd C:\projects\libossia\build-32bit
  $LogFile = "C:\projects\libossia\build-${env:APPVEYOR_BUILD_TYPE}-32bit.log"
  cmake --build . --config "${env:configuration}" > "$LogFile"
  CheckLastExitCode
}

if ( $env:APPVEYOR_BUILD_TYPE -eq "Release" -Or $env:APPVEYOR_BUILD_TYPE -eq "ossia-cpp"){
  cd C:\projects\libossia\build\
  $LogFile = "C:\projects\libossia\build-Debug-${env:platform}.log"
  cmake --build . --config Debug > "$LogFile"
  CheckLastExitCode

  cd C:\projects\libossia\build-32bit
  $LogFile = "C:\projects\libossia\build-Debug-32bit.log"
  cmake --build . --config Debug > "$LogFile"
  CheckLastExitCode
}

if ( $env:APPVEYOR_BUILD_TYPE -eq "qml" )
{
  cd C:\projects\libossia\build\
  $LogFile = "C:\projects\libossia\build-Debug-${env:platform}.log"
  cmake --build . --config Debug > "$LogFile"
  CheckLastExitCode
}