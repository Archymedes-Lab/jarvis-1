; ARGUS-INSTINCT-Setup-windows-x64.exe: the Windows edition as one download.
;
; Per-user, no administrator. It copies the engine (the compiled program from
; argus-instinct-windows-x64.zip, gated and digest-checked) and the desktop app
; into %LOCALAPPDATA%\Programs\ARGUS-INSTINCT, then lets the engine do the rest:
; `argus-instinct.exe native install` registers the per-user service, waits for
; it to answer and pairs the desktop app. Nothing here changes a Windows setting.
;
;   ARGUS-INSTINCT-Setup-windows-x64.exe       the installer window
;   ARGUS-INSTINCT-Setup-windows-x64.exe /S    silent; exit code 0 only when the
;                                              service answers. 2: the service did
;                                              not start; 3: another install exists
;
; Built by release/build_setup.py:
;   makensis -DVERSION=... -DFILE_VERSION=a.b.c.d -DSRC=<staged folder> -DOUTFILE=<exe> [-DICON=<ico>]

Unicode true
Target amd64-unicode
SetCompressor /SOLID lzma
; No build-machine timestamps inside the archive, so a rebuild matches.
SetDateSave off

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"

!define PRODUCT "ARGUS-INSTINCT"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARGUS-INSTINCT"
!define ENGINE "$INSTDIR\engine\argus-instinct.exe"
!define APP "$INSTDIR\argus-desktop.exe"

Name "${PRODUCT}"
Caption "${PRODUCT} ${VERSION} Setup"
OutFile "${OUTFILE}"
RequestExecutionLevel user
InstallDir "$LOCALAPPDATA\Programs\ARGUS-INSTINCT"
ShowInstDetails show
ShowUninstDetails show
BrandingText "${PRODUCT} ${VERSION}"

!ifdef ICON
  !define MUI_ICON "${ICON}"
  !define MUI_UNICON "${ICON}"
!endif
!define MUI_ABORTWARNING

!define MUI_WELCOMEPAGE_TITLE "Install ${PRODUCT} ${VERSION}"
!define MUI_WELCOMEPAGE_TEXT "${PRODUCT} watches what runs on this PC and checks the ways something could take or keep control of it. It runs on this PC; nothing is sent anywhere unless you set up notifications.$\r$\n$\r$\nIt installs for your account only, needs no administrator, and starts when you sign in. No firewall, Defender or system setting is changed.$\r$\n$\r$\nNot in this edition: the elevated event sensor and broker. The app shows what it can and cannot see on this PC."
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_TITLE "${PRODUCT} is installed"
!define MUI_FINISHPAGE_TEXT "It runs whenever you are signed in. Open it from the Start menu: ${PRODUCT}.$\r$\n$\r$\nIf the log above lists problems, they are what still needs doing; nothing was hidden."
!define MUI_FINISHPAGE_RUN "${APP}"
!define MUI_FINISHPAGE_RUN_TEXT "Open ${PRODUCT}"
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

VIProductVersion "${FILE_VERSION}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductName" "${PRODUCT}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileDescription" "${PRODUCT} Setup"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileVersion" "${FILE_VERSION}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "CompanyName" "Archymedes"
VIAddVersionKey /LANG=${LANG_ENGLISH} "LegalCopyright" "Archymedes"

Var Result
Var Output

Section "Install"
  ; One install per computer. The 2026.10 Argus builds installed themselves in
  ; Programs\Argus with their own uninstaller; never install beside one.
  ${If} ${FileExists} "$LOCALAPPDATA\Programs\Argus\Uninstall-Argus.ps1"
    MessageBox MB_ICONSTOP|MB_OK "An older Argus is installed on this PC. Remove it first (Settings > Apps, or Programs\Argus\Uninstall-Argus.ps1), then run this Setup again." /SD IDOK
    SetErrorLevel 3
    Quit
  ${EndIf}

  ; An upgrade: stop the running app and engine so their files can be replaced. The
  ; pairing and the history stay. The APP FIRST: an open app of an older build starts
  ; the engine again whenever it finds it down, which would re-lock the engine folder
  ; right after `native stop` removes the service.
  nsExec::Exec '"$SYSDIR\taskkill.exe" /F /IM argus-desktop.exe'
  Pop $Result
  ${If} ${FileExists} "${ENGINE}"
    DetailPrint "Stopping the running ${PRODUCT} service ..."
    nsExec::ExecToLog '"${ENGINE}" native stop'
    Pop $Result
  ${EndIf}
  ; A clean engine folder every time: no file of an older build survives.
  RMDir /r "$INSTDIR\engine"

  SetOutPath "$INSTDIR"
  File /r "${SRC}\*.*"
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  WriteRegStr HKCU "${UNINST_KEY}" "DisplayName" "${PRODUCT}"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINST_KEY}" "Publisher" "Archymedes"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayIcon" "${APP}"
  WriteRegStr HKCU "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINST_KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKCU "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1

  nsExec::ExecToLog '"${APP}" --install-shortcut'
  Pop $Result

  DetailPrint "Starting the ${PRODUCT} service (this can take a minute) ..."
  ; Output kept in install.log too: a silent install shows no details window.
  nsExec::ExecToStack '"${ENGINE}" native install'
  Pop $Result
  Pop $Output
  DetailPrint $Output
  FileOpen $0 "$INSTDIR\install.log" w
  FileWrite $0 "native install exit code: $Result$\r$\n$Output"
  FileClose $0
  ${If} $Result == "3"
    MessageBox MB_ICONSTOP|MB_OK "${PRODUCT} already runs on this PC (for example inside WSL). One install per PC: remove that one first." /SD IDOK
    SetErrorLevel 3
  ${ElseIf} $Result != "0"
    DetailPrint "The service did not start ($Result). See %LOCALAPPDATA%\Argus\NativeService\daemon.err.log"
    MessageBox MB_ICONEXCLAMATION|MB_OK "${PRODUCT} was installed, but its service did not start. The log above says why." /SD IDOK
    SetErrorLevel 2
  ${EndIf}
SectionEnd

Section "Uninstall"
  ; The app first, for the same reason as in the install: an open app must not start
  ; the engine again between the service being removed and the files being deleted.
  nsExec::Exec '"$SYSDIR\taskkill.exe" /F /IM argus-desktop.exe'
  Pop $Result
  ${If} ${FileExists} "${ENGINE}"
    nsExec::ExecToLog '"${ENGINE}" native uninstall'
    Pop $Result
  ${EndIf}
  ${If} ${FileExists} "${APP}"
    nsExec::ExecToLog '"${APP}" --remove-shortcut'
    Pop $Result
  ${EndIf}
  ; Everything this Setup created goes: the program, its task (native uninstall above),
  ; the Start menu entry, and the app's own settings, pairing and browser profile.
  RMDir /r "$APPDATA\local.argus.desktop"
  RMDir /r "$LOCALAPPDATA\local.argus.desktop"
  ; History (what ARGUS-INSTINCT saw on this PC) and the service's logs are evidence: they go
  ; only when the person says so. Asked when uninstalling by hand, "No" by default; a silent
  ; uninstall keeps them unless /PURGE is given. Nothing outside this product is touched
  ; (no WSL, no other program's folders or tasks).
  ${GetParameters} $0
  ClearErrors
  ${GetOptions} $0 "/PURGE" $1
  ${If} ${Errors}
    MessageBox MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2 "Also delete ${PRODUCT}'s history on this PC?$\r$\n$\r$\nThat is everything it recorded about this computer, and its logs. Choose No to keep them (in $PROFILE\.argus) in case you reinstall or need them later." /SD IDNO IDYES purge
    DetailPrint "kept the history in $PROFILE\.argus"
    Goto history_done
  ${EndIf}
  purge:
  RMDir /r "$PROFILE\.argus"
  RMDir /r "$LOCALAPPDATA\Argus"
  DetailPrint "deleted the history"
  history_done:
  RMDir /r "$INSTDIR"
  DeleteRegKey HKCU "${UNINST_KEY}"
SectionEnd
