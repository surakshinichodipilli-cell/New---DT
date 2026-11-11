@echo off
setlocal
cd /d "%~dp0"
if errorlevel 1 goto :project_folder_error

if not exist "app.py" goto :project_files_error
if not exist "requirements.txt" goto :project_files_error

if not exist ".venv\Scripts\activate.bat" goto :create_environment
goto :activate_environment

:create_environment
echo Project virtual environment not found. Creating .venv...
where py >nul 2>nul
if not errorlevel 1 (
    py -3 -m venv .venv
    if errorlevel 1 goto :environment_error
    goto :activate_environment
)

where python >nul 2>nul
if errorlevel 1 goto :python_error
python -m venv .venv
if errorlevel 1 goto :environment_error

:activate_environment
call ".venv\Scripts\activate.bat"
if errorlevel 1 goto :environment_error

set "HOST=127.0.0.1"
set "PORT=5000"

echo Checking and installing required packages...
python -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 goto :dependency_error

echo.
echo Starting NetShield AI at http://127.0.0.1:5000
echo Keep this window open while you use the website.
echo To stop the server, press Ctrl+C in this window.
echo.
python app.py
set "APP_EXIT_CODE=%ERRORLEVEL%"
if not "%APP_EXIT_CODE%"=="0" (
    echo.
    echo ERROR: NetShield AI stopped with exit code %APP_EXIT_CODE%.
    echo If port 5000 is already in use, close the other server window and try again.
)
goto :finish

:project_folder_error
echo ERROR: Could not change to the project folder.
goto :finish

:project_files_error
echo ERROR: app.py or requirements.txt was not found.
echo Double-click this file from inside the NetShield-AI project folder.
goto :finish

:python_error
echo ERROR: Python 3 was not found. Install Python 3 and try again.
goto :finish

:environment_error
echo ERROR: Could not create or activate the project virtual environment.
goto :finish

:dependency_error
echo ERROR: Required packages could not be installed.
echo Check your internet connection and the requirements.txt file.
goto :finish

:finish
echo.
echo This window will stay open so you can review any messages.
pause
endlocal
