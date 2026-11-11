@echo off
setlocal
cd /d "%~dp0"

set "PYTHON=%CD%\.venv\Scripts\python.exe"
set "WEBSITE_URL=http://127.0.0.1:5000/"

if not exist "requirements.txt" (
    echo ERROR: requirements.txt was not found in the project folder.
    pause
    exit /b 1
)

if not exist "%PYTHON%" (
    where py >nul 2>nul
    if errorlevel 1 (
        echo ERROR: Python 3 is not installed or the Python launcher is unavailable.
        echo Install Python 3 and try again.
        pause
        exit /b 1
    )
    echo Creating the project Python environment...
    py -3 -m venv .venv
    if errorlevel 1 (
        echo ERROR: Could not create the Python environment.
        pause
        exit /b 1
    )
)

echo Checking and installing project dependencies...
"%PYTHON%" -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 (
    echo ERROR: Dependency installation failed. Check your internet connection and try again.
    pause
    exit /b 1
)

curl.exe --silent --fail --output NUL "%WEBSITE_URL%"
if errorlevel 1 (
    echo Starting NetShield AI...
    start "NetShield AI server" "%PYTHON%" app.py
)

echo Waiting for the website to respond...
for /L %%I in (1,1,30) do (
    curl.exe --silent --fail --output NUL "%WEBSITE_URL%"
    if not errorlevel 1 goto :server_ready
    powershell -NoProfile -Command "Start-Sleep -Seconds 1"
)

echo ERROR: NetShield AI did not respond at %WEBSITE_URL%
echo Check the NetShield AI server window for an error message.
pause
exit /b 1

:server_ready
echo NetShield AI is ready at %WEBSITE_URL%
if exist "%ProgramFiles%\Google\Chrome\Application\chrome.exe" (
    start "" "%ProgramFiles%\Google\Chrome\Application\chrome.exe" "%WEBSITE_URL%"
    goto :done
)
if exist "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" (
    start "" "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" "%WEBSITE_URL%"
    goto :done
)
if exist "%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe" (
    start "" "%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe" "%WEBSITE_URL%"
    goto :done
)

echo Chrome was not found in its usual install locations. Opening your default browser.
start "" "%WEBSITE_URL%"

:done
echo Leave the NetShield AI server window open while you use the website.
echo Double-click this file again to reopen the website later.
exit /b 0
