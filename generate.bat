@echo off
setlocal enableextensions  EnableDelayedExpansion	

del wget.vbs sqlite3.exe

echo Generating Report...
Rem Computer Info
(
echo ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
echo +-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
echo *                 												 Malicious Reporting - %computername% - by Fyp.USBFF.2017												                    *
echo +-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
echo ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
echo.
echo Computer Machine %computername% live Memory has been checked through
echo.
echo   i. Pslist  - Scan list of process 
echo  ii. Psxview - Recovering Hidden Process not showing in Pslist 
echo iii. Netscan - Checking the Ip address connection that has connection with program in Psxview
echo.
echo +---------------------+
echo *  1. COMPUTER INFO   * 
echo +---------------------+
systeminfo
echo.
echo ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
echo.
echo +---------------------+
echo *  2. RESULT          *
echo +---------------------+
echo.

goto condition
)>Malicious-Reporting.txt
Rem use if condition

:congetname
( 
goto continue
)>>Malicious-Reporting.txt

:continue
(
echo.
echo ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
echo.
echo +---------------------+	
echo *  3. Tools Used      *
echo +---------------------+
echo.
echo   i. Dumpit
echo  ii. Volatility v2.6
echo iii. sqlite3
echo.
echo.
echo.
echo ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
echo **************************************************************Final Year Project : USB Firmware Forensic with MicroSD - USBFF****************************************************************
echo ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
)>>Malicious-Reporting.txt

echo Reporting completed...
goto last

rem check if malicious program detected
:condition
set file=malicious-linking-process.txt
set minbyte=0
if exist %file% goto checksize
echo not found

:checksize
FOR /F "usebackq" %%A IN ('%file%') DO set size=%%~zA
if %size% GTR %minbyte% goto detected
echo %computername% is Safe from Malicious program >>Malicious-Reporting.txt
echo no malicious program is detected on this machice >>Malicious-Reporting.txt
goto continue

:detected
(
echo %computername% has been detected contain of Malicious program 
echo. 
if exist malicious-name.txt (
	goto read-name
) else (
	echo file not found!
	goto continue	
)

:read-name
set /p namee=<malicious-name.txt
(for %%b in (%namee%) do (
	set name=%%b
	echo Program name : !name!
	echo !name! is suspicious since it shows up in every column except pslist-PsActiveProcessHead.
))>>Malicious-Reporting.txt
goto co

:co
(
echo.
echo Details from list from pslist, psxview and netscan :-
echo ------------------------------------------------------
echo.
type malicious-linking-process.txt
echo.
)>>Malicious-Reporting.txt
goto congetname


:last
rem last process
rem checking file if exist
if exist malicious-pid.txt (
	echo Dump Malicious Program from Memory
	goto read-PID
) else (
	echo file not exist
	goto end	
)

:read-PID
set /p val=<malicious-pid.txt
	(for %%a in (%val%) do (
		set pid=%%a
		volatility-2.6.exe -f *.raw --profile=!os2! procdump -p !pid! -D malicious-prog/
	))

goto end

	
:end
del malicious_pid.txt malicious-name.txt malicious-linking-process.txt sqlite3
timeout /t 5
exit

endlocal
