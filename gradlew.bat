@echo off
pushd "%~dp0android"
call gradlew.bat %*
set ERR=%ERRORLEVEL%
popd
exit /b %ERR%
