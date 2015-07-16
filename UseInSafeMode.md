# Introduction #

By default, Windows does not load custom credential providers in safe mode. The reason is covered in FAQ (Appendix A of the RTM Cred Provider Sample Overview):

> Q: My implementation of ICredentialProviderFilter is not loaded in SAFE mode. Is this a bug? Is there a way to run my Filter in SAFE mode?

> A: This is not a bug. SAFE mode is intended to serve as a workaround in order to correct repair Operating Systems malfunctioning due to incorrectly configured components such as device drivers. By default, only the in-box Password Provider is loaded in SAFE mode. The in-box Smart Card Provider is also available if the machine is booted into SAFE mode with networking. This provides a fallback in case of a bad error. To over-ride the fallback logic and force logonUI to load Credential Provider filters in SAFE Mode, create and set the following registry key:

> [HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers]
> “ProhibitFallbacks”=dword:1

# Details #

If you want to use OpenOTP CP or any other CP in safe mode, you may download our use-cp-in-safe-mode.zip file from the downloads section.

**Be sure what you are doing. If OpenOTP CP or any other custom CP misbehaves and you are not able to login, you will experience that even safe mode can not help you!**

# Download and installation #

  1. Go to the [download section](http://code.google.com/p/open-one-time-password--credential-provider/downloads/list) and download use-cp-in-safe-mode.zip
  1. As administrator run RegisterForSafeMode.reg

# Uninstall #

  1. Run UnregisterForSafeMode.reg from the archive downloaded. See "Download and installation"