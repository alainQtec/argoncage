# dev wiki

Small things to remember

## 1. Running test

```PowerShell
build.ps1 -Task test
```

## 2. Trying new changes in pwsh before commit

```PowerShell
copy ./argoncage.psm1 ./module_tmp.ps1; . ./module_tmp.ps1; Remove-Item ./module_tmp.ps1
```
