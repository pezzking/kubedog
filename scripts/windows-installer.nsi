; The Windows installer for Kubedog, made on a Mac by scripts/release.sh with NSIS (brew install makensis):
;   makensis -DVERSION=0.3.2 -DEXE_AMD64=<kubedog.exe> -DEXE_ARM64=<kubedog.exe> -DKUBECTL_AMD64=<kubectl.exe>
;            -DKUBECTL_ARM64=<kubectl.exe> -DKUBECTL_VERSION=v1.37.2 -DNOTICES=<THIRD-PARTY-LIBRARIES.txt>
;            -DROOT=<this repository> -DOUT=<setup.exe>
; One installer for every Windows computer: it holds the program for Intel/AMD and for ARM and installs the one
; that fits, so nobody can pick the wrong file.
; Everything is inside: it downloads nothing, so it works on a computer without internet.
; It installs for the person who runs it, so it needs no administrator: the program goes in
; %LOCALAPPDATA%\Programs\Kubedog, with a Start menu entry and an entry under "Installed apps" to remove it.
; Settings (%APPDATA%\Kubedog) are left alone when Kubedog is removed.

Unicode true
SetCompressor /SOLID lzma
RequestExecutionLevel user
ManifestDPIAware true

!include "MUI2.nsh"
!include "x64.nsh"

Name "Kubedog"
OutFile "${OUT}"
InstallDir "$LOCALAPPDATA\Programs\Kubedog"
InstallDirRegKey HKCU "Software\Kubedog" "InstallDir"

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "Kubedog"
VIAddVersionKey "FileDescription" "Kubedog installer"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "Apache License 2.0"

!define MUI_ICON "${ROOT}/assets/icons/kubedog-windows.ico"
!define MUI_UNICON "${ROOT}/assets/icons/kubedog-windows.ico"
!define MUI_FINISHPAGE_RUN "$INSTDIR\kubedog.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Start Kubedog"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${ROOT}/LICENSE"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Function .onInit
    ${IfNot} ${IsNativeAMD64}
    ${AndIfNot} ${IsNativeARM64}
        MessageBox MB_ICONSTOP "Kubedog needs 64-bit Windows (Intel/AMD or ARM). This computer runs 32-bit Windows."
        Abort
    ${EndIf}
FunctionEnd

!define UNINST "Software\Microsoft\Windows\CurrentVersion\Uninstall\Kubedog"

Section "Kubedog" SecMain
    SectionIn RO
    SetOutPath "$INSTDIR"
    ${If} ${IsNativeARM64}
        File "/oname=kubedog.exe" "${EXE_ARM64}"
    ${Else}
        File "/oname=kubedog.exe" "${EXE_AMD64}"
    ${EndIf}
    File "${ROOT}/LICENSE"
    File "${ROOT}/THIRD-PARTY.md"
    File "${NOTICES}"
    SetOutPath "$INSTDIR\licenses"
    File "${ROOT}/assets/fonts/*-OFL.txt"
    File "${ROOT}/assets/fonts/*-LICENSE.txt"
    SetOutPath "$INSTDIR"
    WriteUninstaller "$INSTDIR\uninstall.exe"

    CreateShortcut "$SMPROGRAMS\Kubedog.lnk" "$INSTDIR\kubedog.exe"

    WriteRegStr HKCU "Software\Kubedog" "InstallDir" "$INSTDIR"
    WriteRegStr HKCU "${UNINST}" "DisplayName" "Kubedog"
    WriteRegStr HKCU "${UNINST}" "DisplayVersion" "${VERSION}"
    WriteRegStr HKCU "${UNINST}" "Publisher" "Kubedog"
    WriteRegStr HKCU "${UNINST}" "DisplayIcon" "$INSTDIR\kubedog.exe"
    WriteRegStr HKCU "${UNINST}" "InstallLocation" "$INSTDIR"
    WriteRegStr HKCU "${UNINST}" "UninstallString" '"$INSTDIR\uninstall.exe"'
    WriteRegStr HKCU "${UNINST}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
    WriteRegDWORD HKCU "${UNINST}" "NoModify" 1
    WriteRegDWORD HKCU "${UNINST}" "NoRepair" 1
SectionEnd

Section "kubectl ${KUBECTL_VERSION}" SecKubectl
    SetOutPath "$INSTDIR"
    ${If} ${IsNativeARM64}
        File "/oname=kubectl.exe" "${KUBECTL_ARM64}"
    ${Else}
        File "/oname=kubectl.exe" "${KUBECTL_AMD64}"
    ${EndIf}
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} "The program itself."
    !insertmacro MUI_DESCRIPTION_TEXT ${SecKubectl} "Kubedog reaches clusters through kubectl. This copy is only used when the computer has no kubectl or oc of its own; yours always goes first."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"
    Delete "$INSTDIR\kubectl.exe"
    Delete "$SMPROGRAMS\Kubedog.lnk"
    Delete "$INSTDIR\kubedog.exe"
    Delete "$INSTDIR\LICENSE"
    Delete "$INSTDIR\THIRD-PARTY.md"
    Delete "$INSTDIR\THIRD-PARTY-LIBRARIES.txt"
    Delete "$INSTDIR\licenses\*-OFL.txt"
    Delete "$INSTDIR\licenses\*-LICENSE.txt"
    RMDir "$INSTDIR\licenses"
    Delete "$INSTDIR\uninstall.exe"
    RMDir "$INSTDIR"
    DeleteRegKey HKCU "${UNINST}"
    DeleteRegKey HKCU "Software\Kubedog"
SectionEnd
