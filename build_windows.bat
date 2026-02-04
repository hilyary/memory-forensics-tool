@echo off
REM 析镜 LensAnalysis - Windows PyInstaller 打包脚本

echo ============================================================
echo   析镜 LensAnalysis - Windows 打包工具
echo ============================================================
echo.

REM 清理旧文件
if exist dist rmdir /s /q dist
if exist build rmdir /s /q build
echo [√] 已清理旧文件
echo.

REM 运行 PyInstaller
echo [i] 开始打包...
python -m PyInstaller build.spec -y
echo.

REM 显示结果
if exist dist\LensAnalysis.exe (
    echo ============================================================
    echo   打包完成!
    echo ============================================================
    echo [√] 可执行文件: dist\LensAnalysis.exe
    echo.
    echo 使用方法:
    echo   1. 安装 Volatility 3: pip install volatility3
    echo   2. 运行: dist\LensAnalysis.exe
    echo.
) else (
    echo [×] 打包失败
)

pause
