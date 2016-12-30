# Ghostlister

Ghostlister is a PID brute-forcer for Windows. It's compiled as a 64-bit application with the open-source Lazarus IDE and FreePascal 3.x compiler.

I wrote this back in 2011 in Delphi, but at the time there was only a 32-bit compiler for Delphi. So I easily ported the code to use the FreePascal compiler which had a 32 and 64 bit compiler.

# Purpose

This program enumerates all processes on the system using a PID brute force. This means I increment through possible PID values from 0 to MAX_PID, calling `OpenProcess` with each possible PID value as a parameter, and checking for success/failure.

Then I compare this to the PID values returned from the standard Windows API `CreateToolhelp32Snapshot` call.

# Notes

This isn't a great technique anymore for discovering malware, and even in 2011 this method was on its way out. Malware authors employe more sophisticated methods of evading detection these days.

However, back in 2011 I did find malware hiding on machines using this method. I'm releasing it as open-source for others to use or learn from.